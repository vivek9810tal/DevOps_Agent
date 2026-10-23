"""specialized_agents.py - Real specialized sub-agents used by graph.py."""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Literal, Optional

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from state import CICDState

load_dotenv()


def _llm() -> ChatOpenAI:
    key = os.getenv("OPENAI_API_KEY", "").strip().strip('"').strip("'")
    if not key:
        raise RuntimeError("OPENAI_API_KEY is missing.")
    return ChatOpenAI(
        model=(os.getenv("OPENAI_MODEL", "gpt-4o").strip() or "gpt-4o"),
        temperature=0,
        request_timeout=45,
        max_retries=2,
    )


MODEL = _llm()


def _state_json(state: CICDState) -> str:
    safe = {}
    for key, value in state.items():
        if key == "messages":
            continue
        try:
            json.dumps(value)
            safe[key] = value
        except TypeError:
            safe[key] = str(value)
    return json.dumps(safe, indent=2, default=str)


def _structured(schema: type[BaseModel], instruction: str, state: CICDState):
    return MODEL.with_structured_output(schema).invoke(
        instruction
        + "\n\nSTATE / EVIDENCE:\n"
        + _state_json(state)
        + "\n\nUse only supplied evidence. Never fabricate execution results."
    )


def _github_inventory(repo_url: str, branch: str) -> Dict[str, Any]:
    """Get a public GitHub tree for pre-execution repository reasoning."""
    parsed = urllib.parse.urlparse(repo_url)
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) != 2:
        return {"available": False, "error": "Invalid owner/repository URL."}

    owner, repo = parts
    repo = repo.removesuffix(".git")
    url = (
        f"https://api.github.com/repos/{urllib.parse.quote(owner)}/"
        f"{urllib.parse.quote(repo)}/git/trees/{urllib.parse.quote(branch, safe='')}?recursive=1"
    )

    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "Agentic-DevSecOps/4.0",
    }
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403) and "Authorization" in headers:
            retry_headers = {"Accept": "application/vnd.github+json", "User-Agent": "Agentic-DevSecOps/4.0"}
            try:
                req = urllib.request.Request(url, headers=retry_headers)
                with urllib.request.urlopen(req, timeout=15) as response:
                    data = json.loads(response.read().decode("utf-8"))
            except Exception as retry_exc:
                return {"available": False, "error": str(retry_exc), "auth_retry": "anonymous_failed"}
        else:
            return {"available": False, "error": str(exc)}
    except Exception as exc:
        return {"available": False, "error": str(exc)}

    files = [
        item.get("path", "")
        for item in (data.get("tree") or [])
        if item.get("type") == "blob"
    ]

    manifests = []
    interesting = {
        "requirements.txt", "pyproject.toml", "setup.py", "package.json",
        "pom.xml", "build.gradle", "build.gradle.kts", "gradlew",
        "gradlew.bat", "go.mod", "Cargo.toml", "composer.json",
        "Gemfile", "Package.swift", "pubspec.yaml", "mix.exs",
        "CMakeLists.txt", "Makefile", "Dockerfile", "build.sbt", "project.clj", "deps.edn", "stack.yaml", "cabal.project", "Project.toml", "DESCRIPTION", "cpanfile", "WORKSPACE", "WORKSPACE.bazel", "MODULE.bazel", "meson.build",
    }

    for path in files:
        if path.split("/")[-1] in interesting or path.endswith((".sln", ".csproj", ".fsproj", ".vbproj", ".cabal", ".rockspec")):
            manifests.append(path)

    extension_counts: Dict[str, int] = {}
    for path in files:
        name = path.rsplit("/", 1)[-1]
        if "." in name:
            ext = "." + name.rsplit(".", 1)[-1].lower()
            extension_counts[ext] = extension_counts.get(ext, 0) + 1

    return {
        "available": True,
        "file_count": len(files),
        "manifests": manifests[:200],
        "top_extensions": dict(
            sorted(extension_counts.items(), key=lambda x: x[1], reverse=True)[:20]
        ),
        "sample_files": files[:300],
        "truncated": bool(data.get("truncated")),
    }


class RepositoryAnalysis(BaseModel):
    primary_ecosystem: str
    secondary_ecosystems: List[str] = Field(default_factory=list)
    is_monorepo: bool = False
    has_dockerfile: bool = False
    has_iac: bool = False
    likely_web_application: bool = False
    detected_manifests: List[str] = Field(default_factory=list)
    recommended_components: List[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)
    rationale: str


class BuildStrategy(BaseModel):
    ecosystem: str
    build_system: str
    build_required: bool
    package_required: bool
    recommended_build_commands: List[str] = Field(default_factory=list)
    recommended_package_commands: List[str] = Field(default_factory=list)
    required_runtime_tools: List[str] = Field(default_factory=list)
    unsupported_reason: Optional[str] = None
    rationale: str


class SecurityStrategy(BaseModel):
    run_semgrep: bool
    run_gitleaks: bool
    run_trivy_fs: bool
    run_trivy_iac: bool
    run_grype: bool
    run_zap: bool
    blocking_rules: List[str] = Field(default_factory=list)
    evidence_required: List[str] = Field(default_factory=list)
    rationale: str


class DeploymentStrategy(BaseModel):
    should_containerize: bool
    should_stage_deploy: bool
    dockerfile_required: bool
    deployment_kind: Literal[
        "container", "non-web-artifact", "unsupported", "not-applicable"
    ]
    expected_service_port: Optional[int] = None
    deployment_checks: List[str] = Field(default_factory=list)
    cleanup_required: bool = True
    rationale: str


class TestStrategy(BaseModel):
    unit_test_required: bool
    integration_test_required: bool
    http_probe_required: bool
    dast_required: bool
    recommended_test_commands: List[str] = Field(default_factory=list)
    expected_test_artifacts: List[str] = Field(default_factory=list)
    rationale: str


class PolicyDecision(BaseModel):
    decision: Literal["PASS", "FAIL", "REVIEW", "INSUFFICIENT_EVIDENCE"]
    blocking_findings: List[str] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list)
    non_blocking_findings: List[str] = Field(default_factory=list)
    release_allowed: bool
    rationale: str


def repository_analysis_agent(state: CICDState) -> Dict[str, Any]:
    inventory = _github_inventory(
        str(state.get("repo_url", "")),
        str(state.get("branch", "main")),
    )
    enriched = dict(state)
    enriched["repository_inventory"] = inventory

    result = _structured(
        RepositoryAnalysis,
        """You are the Repository Analysis Agent.
Analyze the actual public GitHub file inventory. Identify ecosystem(s), manifests,
monorepo structure, Docker capability, IaC and likely web-app characteristics.
Docker is a capability, not automatically the primary ecosystem.
If inventory retrieval failed, explicitly lower confidence.""",
        enriched,
    )
    return {
        "repository_inventory": inventory,
        "repo_analysis": result.model_dump(),
        "active_phase": "Repository Analysis Agent completed",
    }


def build_strategy_agent(state: CICDState) -> Dict[str, Any]:
    result = _structured(
        BuildStrategy,
        """You are the Build Strategy Agent.
Using repository analysis and inventory, select the correct build/package approach.
Do not execute commands and do not claim success. Do not invent unsupported build systems.""",
        state,
    )
    return {
        "build_strategy": result.model_dump(),
        "active_phase": "Build Strategy Agent completed",
    }


def security_strategy_agent(state: CICDState) -> Dict[str, Any]:
    result = _structured(
        SecurityStrategy,
        """You are the Security Strategy Agent.
Plan Semgrep, Gitleaks, Trivy FS, Trivy IaC, Grype and ZAP applicability.
Grype requires a real image. ZAP requires a real reachable web deployment.
Missing evidence is never zero findings.""",
        state,
    )
    return {
        "security_strategy": result.model_dump(),
        "active_phase": "Security Strategy Agent completed",
    }


def container_deployment_agent(state: CICDState) -> Dict[str, Any]:
    result = _structured(
        DeploymentStrategy,
        """You are the Container / Deployment Agent.
Determine whether containerization and isolated staging deployment are appropriate.
Never infer a port without evidence. Never equate Dockerfile with a web service. Generated staging adapters such as JupyterLab are explicit runtime adapters and must not be described as the repository's native application.
Never recommend production push unless explicitly configured.""",
        state,
    )
    return {
        "deployment_strategy": result.model_dump(),
        "active_phase": "Container / Deployment Agent completed",
    }


def test_strategy_agent(state: CICDState) -> Dict[str, Any]:
    result = _structured(
        TestStrategy,
        """You are the Test Strategy Agent.
Choose evidence-based unit/integration test strategy and whether HTTP probe/DAST applies.
No configured test framework means NOT_CONFIGURED, not PASS.""",
        state,
    )
    return {
        "test_strategy": result.model_dump(),
        "active_phase": "Test Strategy Agent completed",
    }


def policy_release_agent(state: CICDState) -> Dict[str, Any]:
    result = _structured(
        PolicyDecision,
        """You are the Policy / Release Agent.
Evaluate ONLY real Jenkins execution evidence and archived report summaries.
PASS requires sufficient evidence. Missing reports are not zero findings.
FAIL only for observed blocking evidence. Use INSUFFICIENT_EVIDENCE when required
execution/report evidence is absent.""",
        state,
    )
    return {
        "policy_decision": result.model_dump(),
        "active_phase": "Policy / Release Agent completed",
    }
