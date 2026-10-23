"""api.py - FastAPI gateway for the real Agentic DevSecOps Jenkins workflow.

Key properties:
- Streams the exact unique Jenkins job/build created for the request.
- Reads progressive Jenkins console output.
- Emits exact stage lifecycle events from [UI_STAGE] markers:
  running | success | failed | skipped | blocked.
- Downloads genuine archived scanner artifacts into a per-run directory.
- Never converts a missing report into "0 findings".
- Exposes both per-run report summaries and a convenience latest-run endpoint.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, AsyncIterator

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator

from graph import agentic_pipeline, policy_pipeline


load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("DevSecOps_API")

BASE_DIR = Path(__file__).resolve().parent
REPORTS_ROOT = BASE_DIR / "reports"

STAGE_NAMES = {
    "build": "Build",
    "scan": "Scan",
    "package": "Package",
    "containerize": "Containerize",
    "release": "Release",
    "deploy": "Deploy",
    "test": "Test",
    "publish": "Publish",
}

STAGE_STATUSES = {"running", "success", "failed", "skipped", "blocked"}

REPORT_NAMES = (
    "project-metadata.json",
    "build-report.json",
    "deployment-plan.json",
    "test-discovery.json",
    "unit-test-result.json",
    "scan-execution.json",
    "semgrep-report.json",
    "gitleaks-report.json",
    "trivy-report.json",
    "trivy-iac-report.json",
    "grype-report.json",
    "containerize-report.json",
    "release-report.json",
    "deploy-report.json",
    "test-report.json",
    "zap-report.json",
    "pipeline-summary.json",
)

app = FastAPI(
    title="Agentic DevSecOps CI/CD Gateway",
    version="4.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in os.getenv(
            "CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000",
        ).split(",")
        if origin.strip()
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


class PipelineRequest(BaseModel):
    repo_url: str = Field(min_length=1, max_length=500)
    branch: str = Field(default="main", min_length=1, max_length=250)

    @field_validator("repo_url")
    @classmethod
    def validate_github_url(cls, value: str) -> str:
        value = value.strip()
        parsed = urllib.parse.urlparse(value)
        parts = [part for part in parsed.path.strip("/").split("/") if part]

        if (
            parsed.scheme != "https"
            or parsed.hostname not in {"github.com", "www.github.com"}
            or len(parts) != 2
        ):
            raise ValueError(
                "repo_url must be an HTTPS GitHub repository URL in owner/repository format."
            )

        if parsed.query or parsed.fragment:
            raise ValueError("repo_url must not contain query parameters or a fragment.")

        return value

    @field_validator("branch")
    @classmethod
    def validate_branch(cls, value: str) -> str:
        value = value.strip()
        if (
            not re.fullmatch(r"[A-Za-z0-9_./-]+", value)
            or value.startswith(("-", "/"))
            or value.endswith("/")
            or ".." in value
            or "@{" in value
        ):
            raise ValueError("branch contains unsupported characters.")
        return value


def _clean_env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name, default)
    return value.strip().strip('"').strip("'") if value is not None else None


def _jenkins_config() -> tuple[str, dict[str, str]]:
    base_url = (
        _clean_env("JENKINS_URL", "http://localhost:8080")
        or "http://localhost:8080"
    ).rstrip("/")

    user = _clean_env("JENKINS_USER")
    token = _clean_env("JENKINS_API_TOKEN")

    if not user or not token:
        raise RuntimeError(
            "JENKINS_USER and JENKINS_API_TOKEN must be configured in .env."
        )

    auth = base64.b64encode(f"{user}:{token}".encode("utf-8")).decode("ascii")
    return base_url, {
        "Authorization": f"Basic {auth}",
        "User-Agent": "Agentic-DevSecOps/3.0",
    }


def _jenkins_get(url: str, timeout: int = 10) -> tuple[bytes, Any]:
    base_url, headers = _jenkins_config()

    if not url.startswith(base_url + "/"):
        raise RuntimeError(
            "Refusing to request a URL outside the configured Jenkins server."
        )

    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read(), response.headers


def _event(event_type: str, **payload: Any) -> str:
    return (
        "data: "
        + json.dumps(
            {"type": event_type, **payload},
            ensure_ascii=False,
        )
        + "\n\n"
    )


def _extract_tool_result(graph_result: dict[str, Any]) -> dict[str, Any]:
    """Decode the orchestration tool's JSON response from LangGraph messages."""
    messages = graph_result.get("messages", [])

    for message in reversed(messages):
        content = getattr(message, "content", None)
        if not content:
            continue

        if isinstance(content, list):
            content = "\n".join(
                str(item.get("text", ""))
                if isinstance(item, dict)
                else str(item)
                for item in content
            )

        if not isinstance(content, str):
            continue

        try:
            decoded = json.loads(content)
        except (json.JSONDecodeError, TypeError):
            continue

        if isinstance(decoded, dict) and (
            "job_name" in decoded or decoded.get("status") == "ERROR"
        ):
            return decoded

    raise RuntimeError(
        "LangGraph finished without a readable Jenkins orchestration result."
    )


def _safe_run_dir(job_name: str, build_number: int) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", job_name):
        raise ValueError("Invalid Jenkins job name.")

    run_dir = REPORTS_ROOT / job_name / str(build_number)
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def _download_artifacts(
    base_url: str,
    job_name: str,
    build_number: int,
) -> dict[str, bool]:
    """Download genuine archived JSON artifacts for one exact Jenkins build."""
    run_dir = _safe_run_dir(job_name, build_number)
    safe_job = urllib.parse.quote(job_name, safe="")
    availability: dict[str, bool] = {}

    for report_name in REPORT_NAMES:
        url = (
            f"{base_url}/job/{safe_job}/{build_number}/artifact/"
            f"reports/{urllib.parse.quote(report_name)}"
        )

        try:
            data, _ = _jenkins_get(url, timeout=10)

            parsed = None
            decode_error = None
            for encoding in ("utf-8-sig", "utf-8", "cp1252"):
                try:
                    parsed = json.loads(data.decode(encoding))
                    break
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    decode_error = exc

            if parsed is None:
                raise ValueError(
                    f"Could not decode {report_name} as JSON using utf-8/cp1252: {decode_error}"
                )

            (run_dir / report_name).write_text(
                json.dumps(parsed, indent=2),
                encoding="utf-8",
            )
            availability[report_name] = True

        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                logger.warning(
                    "Could not download %s from Jenkins: HTTP %s",
                    report_name,
                    exc.code,
                )
            availability[report_name] = False

        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
        ) as exc:
            logger.warning(
                "Could not persist report artifact %s: %s",
                report_name,
                exc,
            )
            availability[report_name] = False

    metadata = {
        "job_name": job_name,
        "build_number": build_number,
        "jenkins_url": base_url,
        "artifacts": availability,
    }
    (run_dir / "_run.json").write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )

    REPORTS_ROOT.mkdir(parents=True, exist_ok=True)
    (REPORTS_ROOT / "_latest.json").write_text(
        json.dumps(
            {
                "job_name": job_name,
                "build_number": build_number,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    return availability


def _read_json(path: Path) -> Any | None:
    if not path.is_file():
        return None

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _scanner_summary(run_dir: Path) -> dict[str, Any]:
    """
    Parse only reports that actually exist.

    Missing report => executed=False, findings=None.
    This intentionally does not collapse absence into zero.
    """
    result: dict[str, Any] = {
        "semgrep": {"executed": False, "findings": None},
        "gitleaks": {"executed": False, "findings": None},
        "trivy": {
            "executed": False,
            "findings": None,
            "critical": None,
            "high": None,
        },
        "trivy_iac": {
            "executed": False,
            "findings": None,
            "critical": None,
            "high": None,
        },
        "grype": {
            "executed": False,
            "findings": None,
            "critical": None,
            "high": None,
        },
        "zap": {
            "executed": False,
            "findings": None,
            "high": None,
            "medium": None,
        },
    }

    semgrep = _read_json(run_dir / "semgrep-report.json")
    if isinstance(semgrep, dict):
        findings = semgrep.get("results") or []
        result["semgrep"] = {
            "executed": True,
            "findings": len(findings),
        }

    gitleaks = _read_json(run_dir / "gitleaks-report.json")
    if isinstance(gitleaks, list):
        findings = gitleaks
        result["gitleaks"] = {
            "executed": True,
            "findings": len(findings),
        }
    elif isinstance(gitleaks, dict):
        findings = gitleaks.get("findings") or gitleaks.get("results") or []
        result["gitleaks"] = {
            "executed": True,
            "findings": len(findings),
        }

    def parse_trivy(filename: str, key: str) -> None:
        obj = _read_json(run_dir / filename)
        if not isinstance(obj, dict):
            return

        total = 0
        critical = 0
        high = 0

        for item in obj.get("Results") or []:
            if not isinstance(item, dict):
                continue

            findings = (
                (item.get("Vulnerabilities") or [])
                + (item.get("Misconfigurations") or [])
            )
            total += len(findings)

            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                severity = str(finding.get("Severity", "")).upper()
                critical += int(severity == "CRITICAL")
                high += int(severity == "HIGH")

        result[key] = {
            "executed": True,
            "findings": total,
            "critical": critical,
            "high": high,
        }

    parse_trivy("trivy-report.json", "trivy")
    parse_trivy("trivy-iac-report.json", "trivy_iac")

    grype = _read_json(run_dir / "grype-report.json")
    if isinstance(grype, dict):
        matches = grype.get("matches") or []
        critical = 0
        high = 0

        for match in matches:
            if not isinstance(match, dict):
                continue
            severity = str(
                (match.get("vulnerability") or {}).get("severity", "")
            ).upper()
            critical += int(severity == "CRITICAL")
            high += int(severity == "HIGH")

        result["grype"] = {
            "executed": True,
            "findings": len(matches),
            "critical": critical,
            "high": high,
        }

    zap = _read_json(run_dir / "zap-report.json")
    if isinstance(zap, dict):
        total = 0
        high = 0
        medium = 0

        for site in zap.get("site") or []:
            if not isinstance(site, dict):
                continue

            alerts = site.get("alerts") or []
            total += len(alerts)

            for alert in alerts:
                if not isinstance(alert, dict):
                    continue
                risk = str(
                    alert.get("riskdesc")
                    or alert.get("riskcode")
                    or ""
                ).upper()
                high += int("HIGH" in risk or risk == "3")
                medium += int("MEDIUM" in risk or risk == "2")

        result["zap"] = {
            "executed": True,
            "findings": total,
            "high": high,
            "medium": medium,
        }

    pipeline_summary = _read_json(run_dir / "pipeline-summary.json")
    agent_policy = _read_json(run_dir / "agent-policy-decision.json")

    return {
        "scanners": result,
        "policy": pipeline_summary,
        "agent_policy": agent_policy,
    }


async def _stream_jenkins(
    job_name: str,
    build_number: int,
    build_url: str,
    planning_state: dict[str, Any],
) -> AsyncIterator[str]:
    base_url, _ = _jenkins_config()
    safe_job = urllib.parse.quote(job_name, safe="")
    log_offset = 0
    last_stage_status: dict[str, str] = {}

    yield _event(
        "status",
        message=(
            f"Connected to Jenkins build #{build_number}. "
            "Streaming live console output..."
        ),
        job_name=job_name,
        build_number=build_number,
        build_url=build_url,
    )

    while True:
        await asyncio.sleep(1.0)

        log_url = (
            f"{base_url}/job/{safe_job}/{build_number}/"
            f"logText/progressiveText?start={log_offset}"
        )

        try:
            data, headers = await asyncio.to_thread(
                _jenkins_get,
                log_url,
                10,
            )

            new_logs = data.decode("utf-8", errors="replace")

            try:
                log_offset = int(
                    headers.get(
                        "X-Text-Size",
                        log_offset + len(data),
                    )
                )
            except (TypeError, ValueError):
                log_offset += len(data)

            for line in new_logs.splitlines():
                if not line.strip():
                    continue

                yield _event("status", message=line)

                # New industrial contract:
                # [UI_STAGE] scan running
                # [UI_STAGE] scan success
                # [UI_STAGE] containerize skipped
                # [UI_STAGE] publish failed
                stage_match = re.search(
                    r"\[UI_STAGE\]\s*([A-Za-z_-]+)\s+([A-Za-z_-]+)",
                    line,
                )

                if stage_match:
                    stage = stage_match.group(1).lower()
                    status = stage_match.group(2).lower()

                    if (
                        stage in STAGE_NAMES
                        and status in STAGE_STATUSES
                        and last_stage_status.get(stage) != status
                    ):
                        last_stage_status[stage] = status

                        yield _event(
                            "stage",
                            name=stage,
                            display_name=STAGE_NAMES[stage],
                            status=status,
                            job_name=job_name,
                            build_number=build_number,
                            build_url=build_url,
                        )

                        # Backward-compatible event for older frontend builds.
                        if status == "running":
                            yield _event(
                                "tool",
                                name=stage,
                                status="running",
                                job_name=job_name,
                                build_number=build_number,
                                build_url=build_url,
                            )

        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            TimeoutError,
            OSError,
        ) as exc:
            logger.warning(
                "Could not read Jenkins progressive console log: %s",
                exc,
            )

        try:
            build_api = (
                f"{base_url}/job/{safe_job}/{build_number}/"
                "api/json?tree=building,result,url,number"
            )
            raw, _ = await asyncio.to_thread(
                _jenkins_get,
                build_api,
                10,
            )
            info = json.loads(raw.decode("utf-8"))

        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            TimeoutError,
            OSError,
            json.JSONDecodeError,
        ) as exc:
            logger.warning(
                "Could not read Jenkins build status: %s",
                exc,
            )
            continue

        if not info.get("building", False):
            result = str(info.get("result") or "UNKNOWN").upper()

            artifact_availability = await asyncio.to_thread(
                _download_artifacts,
                base_url,
                job_name,
                build_number,
            )

            run_dir = _safe_run_dir(job_name, build_number)
            report_summary = _scanner_summary(run_dir)

            policy_state = dict(planning_state)
            policy_state["execution_evidence"] = {
                "jenkins_result": result,
                "job_name": job_name,
                "build_number": build_number,
                "build_url": build_url,
                "artifact_availability": artifact_availability,
                "report_summary": report_summary,
            }

            try:
                policy_result = await asyncio.to_thread(
                    policy_pipeline.invoke,
                    policy_state,
                )
                agent_policy = policy_result.get("policy_decision", {})
                (run_dir / "agent-policy-decision.json").write_text(
                    json.dumps(agent_policy, indent=2),
                    encoding="utf-8",
                )

                yield _event(
                    "agent",
                    name="policy_release",
                    status="completed",
                    output=agent_policy,
                    message=(
                        "Policy / Release Agent decision: "
                        f"{agent_policy.get('decision', 'UNKNOWN')}"
                    ),
                )
            except Exception as exc:
                logger.exception("Policy / Release Agent failed")
                agent_policy = {
                    "decision": "INSUFFICIENT_EVIDENCE",
                    "release_allowed": False,
                    "rationale": f"Policy agent execution failed: {exc}",
                }
                yield _event(
                    "status",
                    message=f"Policy / Release Agent warning: {exc}",
                )

            policy_summary = report_summary.get("policy") if isinstance(report_summary, dict) else None
            policy_failures = (
                policy_summary.get("policy_failures") or []
                if isinstance(policy_summary, dict)
                else []
            )
            release_allowed = not bool(policy_failures)

            if result == "SUCCESS" and release_allowed:
                yield _event(
                    "pipeline_complete",
                    status="success",
                    result=result,
                    release_allowed=True,
                    policy_failures=[],
                    job_name=job_name,
                    build_number=build_number,
                    build_url=build_url,
                    artifacts=artifact_availability,
                )
            elif result in {"UNSTABLE", "SUCCESS"} and not release_allowed:
                # Jenkins execution completed, but the evidence policy denied release.
                # This is a policy BLOCK, not an execution failure.
                yield _event(
                    "pipeline_complete",
                    status="blocked",
                    result=result,
                    release_allowed=False,
                    policy_failures=policy_failures,
                    message=(
                        "Pipeline execution completed, but release was blocked "
                        "by the DevSecOps evidence policy."
                    ),
                    job_name=job_name,
                    build_number=build_number,
                    build_url=build_url,
                    artifacts=artifact_availability,
                )
            else:
                yield _event(
                    "error",
                    message=(
                        f"Jenkins build #{build_number} finished "
                        f"with result: {result}."
                    ),
                    result=result,
                    release_allowed=False,
                    job_name=job_name,
                    build_number=build_number,
                    build_url=build_url,
                    artifacts=artifact_availability,
                )
            break


async def pipeline_event_generator(
    repo_url: str,
    branch: str,
) -> AsyncIterator[str]:
    yield _event(
        "status",
        message="Validating repository and initializing LangGraph supervisor...",
    )

    try:
        initial_state = {
            "repo_url": repo_url,
            "branch": branch,
            "messages": [],
            "active_phase": "init",
            "jenkins_triggered": False,
            "vulnerabilities_found": False,
            "scan_results": {},
        }

        graph_result = await asyncio.to_thread(
            agentic_pipeline.invoke,
            initial_state,
        )

        for agent_key, label in (
            ("repo_analysis", "Repository Analysis Agent"),
            ("build_strategy", "Build Strategy Agent"),
            ("security_strategy", "Security Strategy Agent"),
            ("deployment_strategy", "Container / Deployment Agent"),
            ("test_strategy", "Test Strategy Agent"),
        ):
            output = graph_result.get(agent_key, {})
            yield _event(
                "agent",
                name=agent_key,
                status="completed",
                output=output,
                message=f"{label} completed.",
            )

        tool_result = _extract_tool_result(graph_result)

        if str(tool_result.get("status", "")).upper() == "ERROR":
            yield _event(
                "error",
                message=str(
                    tool_result.get(
                        "message",
                        "Jenkins orchestration failed.",
                    )
                ),
            )
            return

        job_name = str(tool_result.get("job_name", ""))
        build_number = tool_result.get("build_number")
        build_url = str(
            tool_result.get("build_url")
            or tool_result.get("job_url")
            or ""
        )

        jenkins_url = str(
            tool_result.get("jenkins_url")
            or (
                _clean_env(
                    "JENKINS_URL",
                    "http://localhost:8080",
                )
                or "http://localhost:8080"
            ).rstrip("/")
        )

        if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", job_name):
            raise RuntimeError(
                "The orchestration tool returned an invalid Jenkins job name."
            )

        if not build_number:
            queue_url = tool_result.get("queue_url")

            if queue_url:
                yield _event(
                    "status",
                    message=(
                        "Jenkins accepted the job; "
                        "waiting for an exact build number..."
                    ),
                    job_name=job_name,
                )

                queue_api = str(
                    tool_result.get("queue_api_url") or ""
                )

                for _ in range(30):
                    await asyncio.sleep(1)

                    if not queue_api:
                        break

                    try:
                        raw, _ = await asyncio.to_thread(
                            _jenkins_get,
                            queue_api,
                            8,
                        )
                        queue_info = json.loads(
                            raw.decode("utf-8")
                        )
                        executable = (
                            queue_info.get("executable") or {}
                        )

                        if executable.get("number"):
                            build_number = int(
                                executable["number"]
                            )
                            build_url = (
                                executable.get("url")
                                or (
                                    f"{jenkins_url}/job/"
                                    f"{urllib.parse.quote(job_name, safe='')}/"
                                    f"{build_number}/"
                                )
                            )
                            break

                    except Exception as exc:
                        logger.warning(
                            "Queue polling failed: %s",
                            exc,
                        )

            if not build_number:
                raise RuntimeError(
                    "Jenkins job was created, but its build number "
                    "could not be resolved."
                )

        build_number = int(build_number)

        if not build_url:
            build_url = (
                f"{jenkins_url}/job/"
                f"{urllib.parse.quote(job_name, safe='')}/"
                f"{build_number}/"
            )

        yield _event(
            "status",
            message=(
                f"Jenkins job {job_name} started: "
                f"build #{build_number}."
            ),
            job_name=job_name,
            build_number=build_number,
            build_url=build_url,
        )

        async for event in _stream_jenkins(
            job_name,
            build_number,
            build_url,
            graph_result,
        ):
            yield event

    except Exception as exc:
        logger.exception("Pipeline request failed")

        message = str(exc)

        for secret_name in (
            "OPENAI_API_KEY",
            "JENKINS_API_TOKEN",
            "LANGSMITH_API_KEY",
        ):
            secret = _clean_env(secret_name)
            if secret:
                message = message.replace(
                    secret,
                    "[REDACTED]",
                )

        yield _event(
            "error",
            message=message,
        )


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "agentic-devsecops-api",
        "version": "4.0.0",
    }


@app.post("/api/run-pipeline")
async def run_pipeline(
    request: PipelineRequest,
) -> StreamingResponse:
    return StreamingResponse(
        pipeline_event_generator(
            request.repo_url,
            request.branch,
        ),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.get("/api/reports/{job_name}/{build_number}")
def get_run_reports(
    job_name: str,
    build_number: int,
) -> dict[str, Any]:
    """
    Return real scanner/report information for one exact Jenkins build.
    Missing reports remain executed=False/findings=None.
    """
    try:
        run_dir = _safe_run_dir(
            job_name,
            build_number,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    if not (run_dir / "_run.json").is_file():
        raise HTTPException(
            status_code=404,
            detail="No downloaded report set exists for this Jenkins build.",
        )

    summary = _scanner_summary(run_dir)
    run_meta = _read_json(run_dir / "_run.json")

    return {
        "job_name": job_name,
        "build_number": build_number,
        "run": run_meta,
        **summary,
    }


@app.get("/api/reports")
def get_latest_reports() -> dict[str, Any]:
    """
    Convenience endpoint for the most recently completed Jenkins build.

    This endpoint does not report missing scanner files as zero findings.
    """
    latest = _read_json(REPORTS_ROOT / "_latest.json")

    if not isinstance(latest, dict):
        raise HTTPException(
            status_code=404,
            detail="No completed Jenkins report set is available yet.",
        )

    job_name = str(latest.get("job_name", ""))
    build_number = latest.get("build_number")

    if not job_name or not build_number:
        raise HTTPException(
            status_code=500,
            detail="Latest report metadata is incomplete.",
        )

    return get_run_reports(
        job_name,
        int(build_number),
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(
            _clean_env(
                "API_PORT",
                "8000",
            )
            or "8000"
        ),
    )
