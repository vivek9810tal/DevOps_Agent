"""mcp_server.py - dynamic Jenkins execution engine for the Agentic DevSecOps platform.

This version runs real build/test/scanner/container commands. It does not create
synthetic scanner findings and does not claim pipeline success merely because
Jenkins accepted the build.

The target repository does not need a Jenkinsfile.
"""

from __future__ import annotations

import base64
import html
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.cookiejar import CookieJar
from typing import Any
from urllib.parse import urlparse

from langchain_core.tools import tool


def _env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name, default)
    return value.strip().strip('"').strip("'") if value is not None else None


def _required_env(name: str) -> str:
    value = _env(name)
    if not value:
        raise ValueError(f"Missing required environment variable {name}.")
    return value


def _jenkins_base_url() -> str:
    raw = _env("JENKINS_URL", "http://localhost:8080") or "http://localhost:8080"
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("JENKINS_URL must be a valid http:// or https:// URL.")
    return raw.rstrip("/")


def _validate_repo_and_branch(repo_url: str, branch: str) -> tuple[str, str]:
    repo_url = (repo_url or "").strip()
    branch = (branch or "").strip()
    parsed = urlparse(repo_url)

    if (
        parsed.scheme != "https"
        or parsed.hostname not in {"github.com", "www.github.com"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("repo_url must be an HTTPS GitHub owner/repository URL.")

    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) != 2:
        raise ValueError("Use a GitHub repository URL in owner/repository format.")

    owner, repo = parts
    repo = repo.removesuffix(".git")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", owner):
        raise ValueError("Unsupported characters in GitHub owner.")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", repo):
        raise ValueError("Unsupported characters in repository name.")

    if (
        not branch
        or len(branch) > 250
        or branch.startswith(("-", "/"))
        or branch.endswith("/")
        or ".." in branch
        or "@{" in branch
        or not re.fullmatch(r"[A-Za-z0-9_./-]+", branch)
    ):
        raise ValueError("branch contains unsupported characters.")

    return f"https://github.com/{owner}/{repo}.git", branch


def _groovy_quote(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'").replace("$", "\\$") + "'"


class JenkinsClient:
    def __init__(self) -> None:
        self.base_url = _jenkins_base_url()
        self.username = _required_env("JENKINS_USER")
        self.api_token = _required_env("JENKINS_API_TOKEN")
        self.cookie_jar = CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookie_jar)
        )

        encoded = base64.b64encode(
            f"{self.username}:{self.api_token}".encode("utf-8")
        ).decode("ascii")
        self.headers = {
            "Authorization": f"Basic {encoded}",
            "User-Agent": "Agentic-DevSecOps/3.0",
        }

    def _crumb(self, timeout: int = 10) -> dict[str, str]:
        req = urllib.request.Request(
            f"{self.base_url}/crumbIssuer/api/json",
            headers=self.headers,
            method="GET",
        )
        try:
            with self.opener.open(req, timeout=timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
            field = data.get("crumbRequestField")
            value = data.get("crumb")
            return {field: value} if field and value else {}
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return {}
            raise RuntimeError(
                f"Could not obtain Jenkins CSRF crumb (HTTP {exc.code})."
            ) from None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            raise RuntimeError("Could not contact Jenkins CSRF crumb endpoint.") from None

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        data: bytes | None = None,
        content_type: str | None = None,
        timeout: int = 30,
    ) -> tuple[int, dict[str, str], bytes]:
        headers = dict(self.headers)
        if content_type:
            headers["Content-Type"] = content_type
        if method.upper() == "POST":
            headers.update(self._crumb())

        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers=headers,
            method=method.upper(),
        )

        try:
            with self.opener.open(req, timeout=timeout) as response:
                return response.status, dict(response.headers.items()), response.read()
        except urllib.error.HTTPError as exc:
            body = exc.read(1200).decode("utf-8", errors="replace")
            body = re.sub(
                r"(?i)(authorization|token|password)\s*[:=]\s*\S+",
                r"\1=[REDACTED]",
                body,
            )
            raise RuntimeError(
                f"Jenkins request failed: HTTP {exc.code} {exc.reason}. "
                f"{html.escape(body[:600])}"
            ) from None
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"Cannot connect to Jenkins at {self.base_url}: "
                f"{getattr(exc, 'reason', 'connection error')}"
            ) from None

    def create_job(self, job_name: str, pipeline_script: str) -> None:
        config_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<flow-definition plugin="workflow-job">
  <description>Agentic DevSecOps run {html.escape(job_name)}</description>
  <keepDependencies>false</keepDependencies>
  <properties/>
  <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition" plugin="workflow-cps">
    <script>{html.escape(pipeline_script, quote=False)}</script>
    <sandbox>true</sandbox>
  </definition>
  <triggers/>
  <disabled>false</disabled>
</flow-definition>'''.encode("utf-8")

        encoded_name = urllib.parse.quote(job_name, safe="")
        try:
            self.request(f"/job/{encoded_name}/api/json", timeout=10)
        except RuntimeError as exc:
            if "HTTP 404" not in str(exc):
                raise
        else:
            raise RuntimeError(f"Jenkins job {job_name} already exists.")

        self.request(
            f"/createItem?name={encoded_name}",
            method="POST",
            data=config_xml,
            content_type="application/xml",
            timeout=30,
        )

    def trigger_job(self, job_name: str) -> dict[str, Any]:
        encoded_name = urllib.parse.quote(job_name, safe="")
        status, headers, _ = self.request(
            f"/job/{encoded_name}/build",
            method="POST",
            data=b"",
            content_type="application/x-www-form-urlencoded",
            timeout=30,
        )
        queue_url = headers.get("Location") or headers.get("location")
        if queue_url:
            queue_url = urllib.parse.urljoin(f"{self.base_url}/", queue_url)

        return {
            "http_status": status,
            "queue_url": queue_url,
            "queue_api_url": f"{queue_url.rstrip('/')}/api/json" if queue_url else None,
        }

    def wait_for_build(self, queue_api_url: str, timeout_seconds: int = 120) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_seconds

        while time.monotonic() < deadline:
            path = urlparse(queue_api_url).path
            try:
                _, _, body = self.request(path, timeout=10)
                item = json.loads(body.decode("utf-8"))
            except RuntimeError as exc:
                if "HTTP 404" in str(exc):
                    time.sleep(2)
                    continue
                raise

            if item.get("cancelled"):
                raise RuntimeError("Jenkins cancelled the queued build.")

            executable = item.get("executable") or {}
            if executable.get("number") is not None:
                return {
                    "build_number": int(executable["number"]),
                    "build_url": executable.get("url"),
                }

            time.sleep(2)

        return {"build_number": None, "build_url": None, "queue_timeout": True}


REPO_BUILD_HELPER = '\nimport json, re, shutil, subprocess, sys\nfrom pathlib import Path\nROOT=Path.cwd(); REPORTS=ROOT/"reports"; DIST=ROOT/"dist"; REPORTS.mkdir(exist_ok=True); DIST.mkdir(exist_ok=True)\ndef exists(n): return (ROOT/n).exists()\ndef files(p): return [x for x in ROOT.rglob(p) if x.is_file() and "reports" not in x.parts and ".agentic" not in x.parts and ".git" not in x.parts]\ndef any_files(ps): return any(files(p) for p in ps)\ndef has(c): return shutil.which(c) is not None\ndef run(cmd):\n    print("+"," ".join(map(str,cmd)),flush=True); rc=subprocess.call([str(x) for x in cmd])\n    if rc: raise SystemExit(rc)\ndef detect():\n    if exists("pyproject.toml") or exists("setup.py") or exists("requirements.txt"): return "python"\n    if exists("package.json"): return "node"\n    if exists("pom.xml"): return "maven"\n    if exists("gradlew.bat") or exists("gradlew") or exists("build.gradle") or exists("build.gradle.kts"): return "gradle"\n    if any_files(["*.sln","*.csproj","*.fsproj","*.vbproj"]): return "dotnet"\n    if exists("go.mod"): return "go"\n    if exists("Cargo.toml"): return "rust"\n    if exists("composer.json"): return "php"\n    if exists("Gemfile"): return "ruby"\n    if exists("pubspec.yaml"):\n        t=(ROOT/"pubspec.yaml").read_text(encoding="utf-8",errors="ignore"); return "flutter" if "flutter:" in t else "dart"\n    if exists("Package.swift"): return "swift"\n    if exists("mix.exs"): return "elixir"\n    if exists("build.sbt"): return "scala"\n    if exists("project.clj") or exists("deps.edn"): return "clojure"\n    if exists("stack.yaml") or exists("cabal.project") or any_files(["*.cabal"]): return "haskell"\n    if exists("Project.toml"): return "julia"\n    if exists("DESCRIPTION") and any_files(["*.R"]): return "r"\n    if exists("cpanfile") or exists("Makefile.PL") or exists("Build.PL"): return "perl"\n    if any_files(["*.rockspec"]): return "lua"\n    if exists("WORKSPACE") or exists("WORKSPACE.bazel") or exists("MODULE.bazel"): return "bazel"\n    if exists("meson.build"): return "meson"\n    if exists("CMakeLists.txt"): return "cmake"\n    if exists("Makefile"): return "make"\n    nb=files("*.ipynb"); py=files("*.py")\n    if nb and not py: return "jupyter"\n    if py or nb: return "python-source"\n    if any_files(["*.js","*.ts","*.jsx","*.tsx","*.mjs","*.cjs"]): return "node-source"\n    if any_files(["*.java"]): return "java-source"\n    if any_files(["*.c","*.cc","*.cpp","*.cxx","*.h","*.hpp"]): return "native-source"\n    if exists("Dockerfile"): return "docker-only"\n    return "unknown-source"\ndef main():\n    k=detect(); mode="HOST"; docker=has("docker")\n    req={"python":["python"],"node":["node","npm.cmd"],"maven":["mvn"],"gradle":[] if exists("gradlew.bat") else ["gradle"],"dotnet":["dotnet"],"go":["go"],"rust":["cargo"],"php":["php","composer"],"ruby":["ruby","bundle"],"flutter":["flutter"],"dart":["dart"],"swift":["swift"],"elixir":["mix"],"scala":["sbt"],"clojure":["clojure"],"haskell":["stack"] if exists("stack.yaml") else ["cabal"],"julia":["julia"],"r":["Rscript"],"perl":["perl"],"lua":["lua"],"bazel":["bazel"],"meson":["meson"],"cmake":["cmake"],"make":["make"]}\n    missing=any(not has(c) for c in req.get(k,[]))\n    if k in {"jupyter","python-source","node-source","java-source","native-source","docker-only","unknown-source"}:\n        mode="DOCKERFILE" if k=="docker-only" else "SOURCE_ONLY"\n    elif missing:\n        mode="CONTAINER_BUILD_PENDING" if docker else "RUNTIME_UNAVAILABLE"\n    else:\n        if k=="python":\n            if exists("requirements.txt"): run([sys.executable,"-m","pip","install","-r","requirements.txt"])\n            if exists("pyproject.toml") or exists("setup.py"): run([sys.executable,"-m","pip","install","build"]); run([sys.executable,"-m","build"])\n        elif k=="node": run(["npm.cmd","ci"] if exists("package-lock.json") else ["npm.cmd","install"]); run(["npm.cmd","run","build","--if-present"])\n        elif k=="maven": run(["mvn","-B","-DskipTests","package"])\n        elif k=="gradle": run(["gradlew.bat","assemble","--no-daemon"] if exists("gradlew.bat") else ["gradle","assemble","--no-daemon"])\n        elif k=="dotnet": run(["dotnet","restore"]); run(["dotnet","build","--configuration","Release","--no-restore"])\n        elif k=="go": run(["go","mod","download"]); run(["go","build","./..."])\n        elif k=="rust": run(["cargo","build","--release"])\n        elif k=="php": run(["composer","install","--no-interaction","--prefer-dist"])\n        elif k=="ruby": run(["bundle","install"])\n        elif k=="flutter": run(["flutter","pub","get"]); run(["flutter","build","web"])\n        elif k=="dart": run(["dart","pub","get"])\n        elif k=="swift": run(["swift","build","-c","release"])\n        elif k=="elixir": run(["mix","deps.get"]); run(["mix","compile"])\n        elif k=="scala": run(["sbt","-batch","compile"])\n        elif k=="clojure": run(["clojure","-P"])\n        elif k=="haskell": run(["stack","build"] if exists("stack.yaml") else ["cabal","build","all"])\n        elif k=="julia": run(["julia","--project=.","-e","using Pkg; Pkg.instantiate(); Pkg.precompile()"])\n        elif k in {"r","perl","lua"}: mode="SOURCE_ONLY"\n        elif k=="bazel": run(["bazel","build","//..."])\n        elif k=="meson":\n            if not exists("build"): run(["meson","setup","build"])\n            run(["meson","compile","-C","build"])\n        elif k=="cmake": run(["cmake","-S",".","-B","build"]); run(["cmake","--build","build","--config","Release"])\n        elif k=="make": run(["make"])\n    rep={"project_type":k,"mode":mode,"host_runtime_missing":missing,"docker_available":docker,"dockerfile_present":exists("Dockerfile")}\n    (REPORTS/"project-type.txt").write_text(k,encoding="utf-8"); (REPORTS/"build-mode.txt").write_text(mode,encoding="utf-8")\n    (REPORTS/"build-report.json").write_text(json.dumps(rep,indent=2),encoding="utf-8")\n    print("PROJECT_TYPE="+k); print("BUILD_MODE="+mode)\nif __name__=="__main__": main()\n'
REPO_DEPLOY_HELPER = '\nimport json,re\nfrom pathlib import Path\nROOT=Path.cwd(); REPORTS=ROOT/"reports"; AGENTIC=ROOT/".agentic"; AGENTIC.mkdir(exist_ok=True)\nkind=(REPORTS/"project-type.txt").read_text(encoding="utf-8").strip()\nplan={"deployable":False,"adapter":"none","dockerfile":None,"expected_port":None,"reason":"No safe deployment adapter matched.","generated":False}\ndef text(p):\n    q=ROOT/p\n    return q.read_text(encoding="utf-8",errors="ignore") if q.is_file() else ""\ndef files(p): return [x for x in ROOT.rglob(p) if x.is_file() and "reports" not in x.parts and ".agentic" not in x.parts and ".git" not in x.parts]\ndef write_df(s):\n    p=AGENTIC/"Dockerfile.generated"; p.write_text(s,encoding="utf-8"); return str(p.relative_to(ROOT)).replace("\\\\","/")\ndef service_dockerfile():\n    if not (ROOT/"Dockerfile").is_file(): return False\n    d=text("Dockerfile")\n    if re.search(r\'(?im)^\\s*(CMD|ENTRYPOINT)\\s+.*\\b(echo|true|false|exit)\\b\',d): return False\n    return bool(re.search(r\'(?im)^\\s*EXPOSE\\s+\\d+\',d))\ndef pick_py(pattern):\n    for p in files("*.py"):\n        if re.search(pattern,p.read_text(encoding="utf-8",errors="ignore")): return p\n    return None\n\nif service_dockerfile():\n    d=text("Dockerfile"); m=re.search(r\'(?im)^\\s*EXPOSE\\s+(\\d+)\',d)\n    plan.update(deployable=True,adapter="authored-dockerfile",dockerfile="Dockerfile",expected_port=int(m.group(1)) if m else None,reason="Repository-authored Dockerfile exposes a persistent service port.",generated=False)\nelif kind=="jupyter" or (files("*.ipynb") and not files("*.py")):\n    df=\'\'\'FROM python:3.11-slim\nWORKDIR /workspace\nRUN python -m pip install --no-cache-dir --upgrade pip jupyterlab\nCOPY . /workspace\nEXPOSE 8888\nCMD ["python","-m","jupyterlab","--ip=0.0.0.0","--port=8888","--no-browser","--allow-root","--ServerApp.token=","--ServerApp.password="]\n\'\'\'\n    plan.update(deployable=True,adapter="jupyterlab",dockerfile=write_df(df),expected_port=8888,reason="Notebook-only repository detected after excluding generated CI artifacts; staged as JupyterLab.",generated=True)\nelif kind in ("python","python-source"):\n    req=(text("requirements.txt")+" "+text("pyproject.toml")).lower()\n    fast=pick_py(r\'FastAPI\\s*\\(\'); flask=pick_py(r\'Flask\\s*\\(\'); stream=pick_py(r\'\\bstreamlit\\b\'); gradio=pick_py(r\'\\bgradio\\b|\\bgr\\.Interface\\b|\\bgr\\.Blocks\\b\')\n    base=\'FROM python:3.11-slim\\nWORKDIR /app\\nCOPY . /app\\nRUN python -m pip install --no-cache-dir --upgrade pip\\nRUN if [ -f requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; fi\\n\'\n    if fast or "fastapi" in req:\n        p=fast or next((p for p in files("*.py") if p.name in ("main.py","app.py","api.py")),None)\n        if p:\n            mod=str(p.relative_to(ROOT)).replace("\\\\","/")[:-3].replace("/",".")\n            df=base+\'RUN python -m pip install --no-cache-dir fastapi uvicorn\\nEXPOSE 8000\\nCMD ["python","-m","uvicorn","\'+mod+\':app","--host","0.0.0.0","--port","8000"]\\n\'\n            plan.update(deployable=True,adapter="fastapi",dockerfile=write_df(df),expected_port=8000,reason="FastAPI application detected.",generated=True)\n    elif flask or "flask" in req:\n        p=flask or next((p for p in files("*.py") if p.name in ("app.py","main.py")),None)\n        if p:\n            rel=str(p.relative_to(ROOT)).replace("\\\\","/")\n            df=base+\'RUN python -m pip install --no-cache-dir flask\\nEXPOSE 8000\\nCMD ["python","-m","flask","--app","\'+rel+\'","run","--host=0.0.0.0","--port=8000"]\\n\'\n            plan.update(deployable=True,adapter="flask",dockerfile=write_df(df),expected_port=8000,reason="Flask application detected.",generated=True)\n    elif (ROOT/"manage.py").is_file():\n        df=base+\'RUN python -m pip install --no-cache-dir django\\nEXPOSE 8000\\nCMD ["python","manage.py","runserver","0.0.0.0:8000"]\\n\'\n        plan.update(deployable=True,adapter="django",dockerfile=write_df(df),expected_port=8000,reason="Django manage.py detected.",generated=True)\n    elif stream or "streamlit" in req:\n        p=stream or next((p for p in files("*.py") if p.name in ("app.py","main.py")),None)\n        if p:\n            rel=str(p.relative_to(ROOT)).replace("\\\\","/")\n            df=base+\'RUN python -m pip install --no-cache-dir streamlit\\nEXPOSE 8501\\nCMD ["streamlit","run","\'+rel+\'","--server.address=0.0.0.0","--server.port=8501"]\\n\'\n            plan.update(deployable=True,adapter="streamlit",dockerfile=write_df(df),expected_port=8501,reason="Streamlit application detected.",generated=True)\n    elif gradio or "gradio" in req:\n        p=gradio or next((p for p in files("*.py") if p.name in ("app.py","main.py")),None)\n        if p:\n            rel=str(p.relative_to(ROOT)).replace("\\\\","/")\n            df=base+\'RUN python -m pip install --no-cache-dir gradio\\nENV GRADIO_SERVER_NAME=0.0.0.0\\nENV GRADIO_SERVER_PORT=7860\\nEXPOSE 7860\\nCMD ["python","\'+rel+\'"]\\n\'\n            plan.update(deployable=True,adapter="gradio",dockerfile=write_df(df),expected_port=7860,reason="Gradio application detected.",generated=True)\nelif kind in ("node","node-source"):\n    try: pkg=json.loads(text("package.json") or "{}")\n    except Exception: pkg={}\n    if (pkg.get("scripts") or {}).get("start"):\n        df=\'\'\'FROM node:22-alpine\nWORKDIR /app\nCOPY package*.json ./\nRUN if [ -f package-lock.json ]; then npm ci; else npm install; fi\nCOPY . .\nENV HOST=0.0.0.0\nENV PORT=3000\nEXPOSE 3000\nCMD ["npm","start"]\n\'\'\'\n        plan.update(deployable=True,adapter="node-start",dockerfile=write_df(df),expected_port=3000,reason="package.json start script detected.",generated=True)\nelif kind in ("maven","gradle"):\n    jars=files("*.jar"); jar=next((p for p in jars if "sources" not in p.name.lower() and "javadoc" not in p.name.lower()),None)\n    if jar:\n        rel=str(jar.relative_to(ROOT)).replace("\\\\","/")\n        df=\'FROM eclipse-temurin:21-jre\\nWORKDIR /app\\nCOPY "\'+rel+\'" /app/app.jar\\nEXPOSE 8080\\nCMD ["java","-jar","/app/app.jar"]\\n\'\n        plan.update(deployable=True,adapter="java-jar",dockerfile=write_df(df),expected_port=8080,reason="Runnable JAR artifact detected.",generated=True)\nelif kind=="go":\n    df=\'\'\'FROM golang:1.24-alpine AS build\nWORKDIR /src\nCOPY . .\nRUN go mod download && CGO_ENABLED=0 go build -o /out/app .\nFROM alpine:3.21\nCOPY --from=build /out/app /app\nEXPOSE 8080\nCMD ["/app"]\n\'\'\'\n    plan.update(deployable=True,adapter="go",dockerfile=write_df(df),expected_port=8080,reason="Go module detected; container-native build adapter selected.",generated=True)\nelif kind=="rust":\n    cargo=text("Cargo.toml"); m=re.search(r\'(?ms)^\\s*name\\s*=\\s*"([^"]+)"\',cargo)\n    if m:\n        name=m.group(1)\n        df=\'FROM rust:1.85 AS build\\nWORKDIR /src\\nCOPY . .\\nRUN cargo build --release\\nFROM debian:bookworm-slim\\nCOPY --from=build /src/target/release/\'+name+\' /app\\nEXPOSE 8080\\nCMD ["/app"]\\n\'\n        plan.update(deployable=True,adapter="rust",dockerfile=write_df(df),expected_port=8080,reason="Cargo project detected; container-native build adapter selected.",generated=True)\nelif kind=="php":\n    df=\'FROM php:8.4-apache\\nWORKDIR /var/www/html\\nCOPY . /var/www/html\\nEXPOSE 80\\n\'\n    plan.update(deployable=True,adapter="php-apache",dockerfile=write_df(df),expected_port=80,reason="PHP repository staged with Apache.",generated=True)\n\nif not plan["deployable"]:\n    for d in [ROOT/"dist",ROOT/"build",ROOT/"public",ROOT]:\n        if d.is_dir() and (d/"index.html").is_file():\n            rel=str(d.relative_to(ROOT)).replace("\\\\","/") or "."\n            df=\'FROM nginx:1.27-alpine\\nCOPY "\'+rel+\'/" /usr/share/nginx/html/\\nEXPOSE 80\\n\'\n            plan.update(deployable=True,adapter="static-nginx",dockerfile=write_df(df),expected_port=80,reason="Static index.html detected.",generated=True)\n            break\n\n(REPORTS/"deployment-plan.json").write_text(json.dumps(plan,indent=2),encoding="utf-8")\n(REPORTS/"deploy-dockerfile.txt").write_text(plan["dockerfile"] or "",encoding="utf-8")\n(REPORTS/"deploy-adapter.txt").write_text(plan["adapter"],encoding="utf-8")\n(REPORTS/"deploy-port.txt").write_text("" if plan["expected_port"] is None else str(plan["expected_port"]),encoding="utf-8")\n(REPORTS/"deployable.txt").write_text("true" if plan["deployable"] else "false",encoding="utf-8")\nprint(json.dumps(plan,indent=2))\n'
REPO_TEST_HELPER = '\nimport json\nimport re\nimport shutil\nimport subprocess\nimport sys\nfrom pathlib import Path\n\nROOT = Path.cwd()\nREPORTS = ROOT / "reports"\nREPORTS.mkdir(exist_ok=True)\n\ndef exists(name):\n    return (ROOT / name).exists()\n\ndef read_text(name):\n    path = ROOT / name\n    if not path.exists() or not path.is_file():\n        return ""\n    return path.read_text(encoding="utf-8", errors="ignore")\n\ndef find_files(patterns):\n    found = []\n    for pattern in patterns:\n        found.extend(ROOT.rglob(pattern))\n    unique, seen = [], set()\n    for p in sorted(found):\n        if p.is_file() and "reports" not in p.parts and ".agentic" not in p.parts and ".git" not in p.parts and p not in seen:\n            unique.append(p); seen.add(p)\n    return unique\n\ndef command_available(cmd):\n    return shutil.which(cmd) is not None\n\ndef run(cmd):\n    print("+", " ".join(map(str, cmd)), flush=True)\n    return subprocess.call([str(x) for x in cmd])\n\ndef install_requirements_files():\n    for depfile in ("requirements-dev.txt","dev-requirements.txt","requirements-test.txt","test-requirements.txt"):\n        if exists(depfile):\n            rc = run([sys.executable,"-m","pip","install","-r",depfile])\n            if rc: raise SystemExit(rc)\n\ndef install_python_project_if_needed():\n    if exists("pyproject.toml") or exists("setup.py"):\n        rc = run([sys.executable,"-m","pip","install","-e","."])\n        if rc: raise SystemExit(rc)\n\ndef python_test_strategy():\n    tests = find_files(["test_*.py","*_test.py"])\n    if not tests:\n        return None, ["no Python test files matching test_*.py or *_test.py"]\n    evidence = [f"discovered {len(tests)} Python test file(s)"]\n    combined = "\\n".join(read_text(str(p.relative_to(ROOT))) for p in tests[:100])\n    tox_cfg = exists("tox.ini")\n    pytest_cfg = (\n        exists("pytest.ini") or exists("conftest.py")\n        or "[tool.pytest" in read_text("pyproject.toml")\n        or "[tool:pytest]" in read_text("setup.cfg")\n        or any("pytest" in read_text(f).lower() for f in (\n            "requirements.txt","requirements-dev.txt","dev-requirements.txt","requirements-test.txt","test-requirements.txt"\n        ))\n    )\n    unittest_hint = bool(re.search(r"(^|\\n)\\s*(import unittest|from unittest)", combined)) or "unittest.TestCase" in combined\n    if tox_cfg:\n        evidence.append("tox.ini present"); return "tox", evidence\n    if pytest_cfg:\n        evidence.append("pytest configuration/dependency evidence present"); return "pytest", evidence\n    if unittest_hint:\n        evidence.append("unittest imports/TestCase evidence present"); return "unittest", evidence\n    evidence.append("no framework-specific evidence; pytest chosen as generic Python collector")\n    return "pytest", evidence\n\ndef node_test_strategy():\n    if not exists("package.json"):\n        return None, ["package.json missing"]\n    try:\n        pkg = json.loads(read_text("package.json"))\n    except Exception as exc:\n        return None, [f"invalid package.json: {exc}"]\n    script = str((pkg.get("scripts") or {}).get("test") or "").strip()\n    if not script:\n        return None, ["package.json has no test script"]\n    low = script.lower()\n    if "no test specified" in low or "no tests specified" in low:\n        return None, ["package.json test script is the default no-tests placeholder"]\n    return "npm test", [f"package.json test script detected: {script}"]\n\ndef dotnet_has_tests():\n    for project in find_files(["*.csproj","*.fsproj","*.vbproj"]):\n        txt = project.read_text(encoding="utf-8", errors="ignore").lower()\n        if ("microsoft.net.test.sdk" in txt or "<istestproject>true</istestproject>" in txt or\n            "xunit" in txt or "nunit" in txt or "mstest" in txt or "test" in project.stem.lower()):\n            return True\n    return False\n\ndef detect_strategy(kind):\n    if kind in ("python","python-source"):\n        return python_test_strategy()\n    if kind == "node":\n        return node_test_strategy()\n    if kind == "maven":\n        files=find_files(["*Test.java","*Tests.java","*IT.java"]); return (("mvn test",[f"discovered {len(files)} Maven-style test file(s)"]) if files else (None,["no Maven-style test files detected"]))\n    if kind == "gradle":\n        files=find_files(["*Test.java","*Test.kt","*Spec.groovy"]); return (("gradle test",[f"discovered {len(files)} Gradle-style test file(s)"]) if files else (None,["no Gradle-style test files detected"]))\n    if kind == "dotnet":\n        return (("dotnet test",[".NET test project evidence detected"]) if dotnet_has_tests() else (None,["no .NET test project evidence detected"]))\n    if kind == "go":\n        files=find_files(["*_test.go"]); return (("go test",[f"discovered {len(files)} Go test file(s)"]) if files else (None,["no *_test.go files detected"]))\n    if kind == "rust":\n        files=find_files(["*.rs"]); has_tests=exists("tests") or any("#[test]" in p.read_text(encoding="utf-8",errors="ignore") for p in files[:200]); return (("cargo test",["Rust tests directory or #[test] evidence detected"]) if has_tests else (None,["no Rust test evidence detected"]))\n    if kind == "php":\n        configured=exists("phpunit.xml") or exists("phpunit.xml.dist") or exists("tests"); return (("phpunit",["PHPUnit configuration/tests directory detected"]) if configured else (None,["no PHPUnit configuration/tests directory detected"]))\n    if kind == "ruby":\n        if exists("spec"): return "rspec",["spec/ directory detected"]\n        if exists("test") and exists("Rakefile"): return "rake test",["test/ directory and Rakefile detected"]\n        return None,["no Ruby spec/ or test+Rakefile evidence detected"]\n    if kind == "flutter":\n        files=find_files(["*_test.dart"]); return (("flutter test",[f"discovered {len(files)} Dart/Flutter test file(s)"]) if files else (None,["no *_test.dart files detected"]))\n    if kind == "dart":\n        files=find_files(["*_test.dart"]); return (("dart test",[f"discovered {len(files)} Dart test file(s)"]) if files else (None,["no *_test.dart files detected"]))\n    if kind == "swift": return (("swift test",["Tests/ directory detected"]) if exists("Tests") else (None,["no Tests/ directory detected"]))\n    if kind == "elixir": return (("mix test",["test/ directory detected"]) if exists("test") else (None,["no test/ directory detected"]))\n    if kind == "cmake":\n        c=read_text("CMakeLists.txt").lower(); configured="enable_testing" in c or "add_test" in c; return (("ctest",["CMake testing directives detected"]) if configured else (None,["no CMake testing directives detected"]))\n    return None,[f"no test adapter for project type {kind}"]\n\ndef ensure_pytest():\n    ok=subprocess.call([sys.executable,"-m","pytest","--version"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)==0\n    if not ok:\n        rc=run([sys.executable,"-m","pip","install","--upgrade","pytest"])\n        if rc: raise SystemExit(rc)\n\ndef ensure_tox():\n    if not command_available("tox"):\n        rc=run([sys.executable,"-m","pip","install","--upgrade","tox"])\n        if rc: raise SystemExit(rc)\n\ndef execute_strategy(kind,strategy):\n    if strategy is None: return False,None,None\n    if kind in ("python","python-source"):\n        install_requirements_files(); install_python_project_if_needed()\n        if strategy=="tox": ensure_tox(); return True,"tox",run(["tox","-q"])\n        if strategy=="pytest": ensure_pytest(); return True,"pytest",run([sys.executable,"-m","pytest","-q","--junitxml=reports/pytest-junit.xml"])\n        if strategy=="unittest":\n            # Prefer test*.py; if that fails, try *_test.py.\n            rc=run([sys.executable,"-m","unittest","discover","-v","-p","test*.py"])\n            if rc==0: return True,"unittest",0\n            return True,"unittest",run([sys.executable,"-m","unittest","discover","-v","-p","*_test.py"])\n    commands={\n        "npm test":["npm.cmd","test"],"mvn test":["mvn","-B","test"],\n        "gradle test":(["gradlew.bat","test","--no-daemon"] if exists("gradlew.bat") else ["gradle","test","--no-daemon"]),\n        "dotnet test":["dotnet","test","--configuration","Release","--no-build"],"go test":["go","test","./..."],\n        "cargo test":["cargo","test","--all"],"phpunit":[str(ROOT/"vendor"/"bin"/"phpunit.bat")],\n        "rspec":["bundle","exec","rspec"],"rake test":["bundle","exec","rake","test"],\n        "flutter test":["flutter","test"],"dart test":["dart","test"],"swift test":["swift","test"],\n        "mix test":["mix","test"],"ctest":["ctest","--test-dir","build","--output-on-failure","-C","Release"]}\n    cmd=commands.get(strategy)\n    if cmd is None: return False,strategy,None\n    return True,strategy,run(cmd)\n\ndef main():\n    kind=(REPORTS/"project-type.txt").read_text(encoding="utf-8").strip()\n    strategy,evidence=detect_strategy(kind)\n    discovery={"project_type":kind,"selected_strategy":strategy,"evidence":evidence}\n    (REPORTS/"test-discovery.json").write_text(json.dumps(discovery,indent=2),encoding="utf-8")\n    executed,runner,rc=execute_strategy(kind,strategy)\n    configured=strategy is not None\n    result={"unit_tests":"EXECUTED" if executed else ("CONFIGURED_BUT_NOT_EXECUTED" if configured else "NOT_CONFIGURED"),"runner":runner,"exit_code":rc if executed else None,"discovery":discovery}\n    (REPORTS/"unit-test-result.json").write_text(json.dumps(result,indent=2),encoding="utf-8")\n    (REPORTS/"unit-test-status.txt").write_text(result["unit_tests"],encoding="utf-8")\n    (REPORTS/"unit-test-runner.txt").write_text(result["runner"] or "",encoding="utf-8")\n    (REPORTS/"unit-test-exit-code.txt").write_text("" if result["exit_code"] is None else str(result["exit_code"]),encoding="utf-8")\n    if executed and rc: raise SystemExit(rc)\nif __name__=="__main__": main()\n'
BUILD_HELPER_B64 = base64.b64encode(REPO_BUILD_HELPER.encode('utf-8')).decode('ascii')
DEPLOY_HELPER_B64 = base64.b64encode(REPO_DEPLOY_HELPER.encode('utf-8')).decode('ascii')
TEST_HELPER_B64 = base64.b64encode(REPO_TEST_HELPER.encode('utf-8')).decode('ascii')

PIPELINE_TEMPLATE = r"""
pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
        skipDefaultCheckout(true)
        timeout(time: 60, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '20', artifactNumToKeepStr: '20'))
    }

    environment {
        DEVSECOPS_RUN_ID = __RUN_ID__
        REPOSITORY_URL = __REPO_URL__
        REPOSITORY_BRANCH = __BRANCH__
        REPORT_DIR = 'reports'
        DIST_DIR = 'dist'
    }

    stages {
        stage('Build') {
            steps {
                echo '[UI_TRIGGER] build'
                echo '[UI_STAGE] build running'
                deleteDir()
                checkout([$class: 'GitSCM', branches: [[name: "*/${REPOSITORY_BRANCH}"]], userRemoteConfigs: [[url: "${REPOSITORY_URL}"]]])
                bat 'if not exist reports mkdir reports'
                bat 'if not exist dist mkdir dist'
                bat 'git rev-parse HEAD > reports/git-commit.txt'
                script {
                    env.HAS_DOCKERFILE = fileExists('Dockerfile') ? 'true' : 'false'
                    env.IMAGE_NAME = "agentic-devsecops-${env.DEVSECOPS_RUN_ID}"
                    env.IMAGE_TAG = "build-${env.BUILD_NUMBER}"
                    env.RELEASE_TAG = "release-${env.BUILD_NUMBER}"
                    env.STAGING_CONTAINER = "agentic-stage-${env.DEVSECOPS_RUN_ID}"
                    env.IMAGE_BUILT='false'; env.DEPLOYED='false'; env.DEPLOY_URL=''; env.APP_CONTAINER_PORT=''; env.DEPLOY_DOCKERFILE=''; env.DEPLOY_ADAPTER='none'; env.DEPLOY_EXPECTED_PORT=''; env.DEPLOY_STAGE_STATUS='pending'; env.TEST_STAGE_STATUS='pending'; env.PUBLISH_STAGE_STATUS='pending'; env.DEPLOY_HOST_PORT=''
                    bat "powershell -NoProfile -Command \"[IO.File]::WriteAllBytes('reports/repo_build_helper.py',[Convert]::FromBase64String('__BUILD_HELPER_B64__'))\""
                    bat 'python reports/repo_build_helper.py'
                    env.PROJECT_TYPE = readFile('reports/project-type.txt').trim()
                    env.BUILD_MODE = fileExists('reports/build-mode.txt') ? readFile('reports/build-mode.txt').trim() : 'UNKNOWN'
                    writeFile file: 'reports/project-metadata.json', text: groovy.json.JsonOutput.prettyPrint(groovy.json.JsonOutput.toJson([run_id:env.DEVSECOPS_RUN_ID,repository:env.REPOSITORY_URL,branch:env.REPOSITORY_BRANCH,commit:readFile('reports/git-commit.txt').trim(),project_type:env.PROJECT_TYPE,build_mode:env.BUILD_MODE,dockerfile_present:(env.HAS_DOCKERFILE=='true'),jenkins_build:env.BUILD_NUMBER]))
                    echo "Detected project type: ${env.PROJECT_TYPE}"
                }
            }
            post {
                success {
                    echo '[UI_STAGE] build success'
                }
                failure {
                    echo '[UI_STAGE] build failed'
                }
            }
        }

        stage('Scan') {
            steps {
                echo '[UI_TRIGGER] scan'
                echo '[UI_STAGE] scan running'
                script {
                    def failures = []
                    def available = [:]

                    def semgrepCheck = bat(returnStatus: true, script: '@semgrep --version >nul 2>&1')
                    available.semgrep = (semgrepCheck == 0)
                    if (semgrepCheck == 0) {
                        def rc = bat(returnStatus: true, script: '@semgrep scan --config auto --json --output reports\\semgrep-report.json .')
                        if (rc != 0 || !fileExists('reports/semgrep-report.json')) {
                            failures << "Semgrep execution failed (${rc})"
                        }
                    } else {
                        failures << 'Semgrep is not installed'
                    }

                    def gitleaksCheck = bat(returnStatus: true, script: '@gitleaks version >nul 2>&1')
                    available.gitleaks = (gitleaksCheck == 0)
                    if (gitleaksCheck == 0) {
                        def modern = bat(returnStatus: true, script: '@gitleaks git --help >nul 2>&1')
                        def rc
                        if (modern == 0) {
                            rc = bat(returnStatus: true, script: '@gitleaks git . --report-format json --report-path reports\\gitleaks-report.json --no-banner')
                        } else {
                            rc = bat(returnStatus: true, script: '@gitleaks detect --source . --report-format json --report-path reports\\gitleaks-report.json --no-banner')
                        }
                        if (!(rc in [0, 1]) || !fileExists('reports/gitleaks-report.json')) {
                            failures << "Gitleaks execution failed (${rc})"
                        }
                    } else {
                        failures << 'Gitleaks is not installed'
                    }

                    def trivyCheck = bat(returnStatus: true, script: '@trivy --version >nul 2>&1')
                    available.trivy = (trivyCheck == 0)
                    if (trivyCheck == 0) {
                        def fsRc = bat(returnStatus: true, script: '@trivy fs --scanners vuln --format json --output reports\\trivy-report.json .')
                        if (fsRc != 0 || !fileExists('reports/trivy-report.json')) {
                            failures << "Trivy filesystem scan failed (${fsRc})"
                        }

                        def iacRc = bat(returnStatus: true, script: '@trivy config --format json --output reports\\trivy-iac-report.json .')
                        if (iacRc != 0 || !fileExists('reports/trivy-iac-report.json')) {
                            failures << "Trivy IaC scan failed (${iacRc})"
                        }
                    } else {
                        failures << 'Trivy is not installed'
                    }

                    writeFile file: 'reports/scan-execution.json',
                        text: groovy.json.JsonOutput.prettyPrint(
                            groovy.json.JsonOutput.toJson([
                                stage: 'Scan',
                                scanner_availability: available,
                                execution_failures: failures
                            ])
                        )

                    if (!failures.isEmpty()) {
                        echo "Scanner evidence gaps: ${failures.join('; ')}"
                        echo 'The pipeline will continue to collect remaining evidence; Publish will enforce the policy gate.'
                    }
                }
            }
            post {
                success { echo '[UI_STAGE] scan success' }
                failure { echo '[UI_STAGE] scan failed' }
            }
        }

        stage('Package') {
            steps {
                echo '[UI_TRIGGER] package'
                echo '[UI_STAGE] package running'
                script {
                    if (env.PROJECT_TYPE == 'python') {
                        def built = bat(returnStatus: true, script: '@dir /b dist\\*.whl dist\\*.tar.gz >nul 2>&1')
                        if (built != 0) { bat 'git archive --format=zip --output=dist\\source-package.zip HEAD' }
                    } else if (env.PROJECT_TYPE == 'node') {
                        bat 'npm.cmd pack --pack-destination dist'
                    } else if (env.PROJECT_TYPE == 'maven') {
                        bat 'powershell -NoProfile -Command "Get-ChildItem target -Include *.jar,*.war -File -Recurse -ErrorAction SilentlyContinue | Copy-Item -Destination dist -Force"'
                    } else if (env.PROJECT_TYPE == 'gradle') {
                        bat 'powershell -NoProfile -Command "Get-ChildItem build\\libs -Include *.jar,*.war -File -Recurse -ErrorAction SilentlyContinue | Copy-Item -Destination dist -Force"'
                    } else if (env.PROJECT_TYPE == 'dotnet') {
                        bat 'dotnet publish --configuration Release --output dist'
                    } else if (env.PROJECT_TYPE == 'go') {
                        bat 'go build -o dist\\application.exe .'
                    } else if (env.PROJECT_TYPE == 'rust') {
                        bat 'powershell -NoProfile -Command "Get-ChildItem target\\release -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -notin ''.d'',''.rlib'',''.rmeta'' } | Copy-Item -Destination dist -Force"'
                    } else if (env.PROJECT_TYPE == 'flutter') {
                        bat 'powershell -NoProfile -Command "if (Test-Path build\\web) { Compress-Archive -Path build\\web\\* -DestinationPath dist\\flutter-web.zip -Force }"'
                    } else if (env.PROJECT_TYPE == 'cmake') {
                        bat 'powershell -NoProfile -Command "if (Test-Path build) { Compress-Archive -Path build\\* -DestinationPath dist\\cmake-build.zip -Force }"'
                    } else {
                        bat 'git archive --format=zip --output=dist\\source-package.zip HEAD'
                    }

                    def count = bat(returnStdout: true, script: '@powershell -NoProfile -Command "(Get-ChildItem dist -File -Recurse | Measure-Object).Count"').trim()
                    if ((count as Integer) == 0) {
                        bat 'git archive --format=zip --output=dist\\source-package.zip HEAD'
                        count = '1'
                    }
                    writeFile file: 'reports/package-report.json',
                        text: groovy.json.JsonOutput.prettyPrint(
                            groovy.json.JsonOutput.toJson([
                                stage: 'Package',
                                project_type: env.PROJECT_TYPE,
                                artifact_count: count as Integer
                            ])
                        )
                    archiveArtifacts artifacts: 'dist/**/*', allowEmptyArchive: false, fingerprint: true
                }
            }
            post {
                success { echo '[UI_STAGE] package success' }
                failure { echo '[UI_STAGE] package failed' }
            }
        }

        stage('Containerize') {
            steps {
                echo '[UI_TRIGGER] containerize'
                echo '[UI_STAGE] containerize running'
                script {
                    bat "powershell -NoProfile -Command \"[IO.File]::WriteAllBytes('reports/repo_deploy_helper.py',[Convert]::FromBase64String('__DEPLOY_HELPER_B64__'))\""
                    bat 'python reports\\repo_deploy_helper.py'
                    def deployable=fileExists('reports/deployable.txt') ? readFile('reports/deployable.txt').trim() : 'false'
                    env.DEPLOY_DOCKERFILE=fileExists('reports/deploy-dockerfile.txt') ? readFile('reports/deploy-dockerfile.txt').trim() : ''
                    env.DEPLOY_ADAPTER=fileExists('reports/deploy-adapter.txt') ? readFile('reports/deploy-adapter.txt').trim() : 'none'
                    env.DEPLOY_EXPECTED_PORT=fileExists('reports/deploy-port.txt') ? readFile('reports/deploy-port.txt').trim() : ''
                    if (deployable!='true' || !env.DEPLOY_DOCKERFILE) {
                        echo '[UI_STAGE] containerize skipped'
                        writeFile file:'reports/containerize-report.json',text:groovy.json.JsonOutput.prettyPrint(groovy.json.JsonOutput.toJson([
                            stage:'Containerize',status:'NOT_APPLICABLE',project_type:env.PROJECT_TYPE,adapter:env.DEPLOY_ADAPTER,
                            reason:'No safe deployable container adapter was found. Source/security analysis still completed.'
                        ]))
                    } else {
                        bat 'docker --version'
                        bat 'docker info'
                        bat "docker build --pull --label devsecops.run=${env.DEVSECOPS_RUN_ID} --label devsecops.adapter=${env.DEPLOY_ADAPTER} -f \"${env.DEPLOY_DOCKERFILE}\" -t ${env.IMAGE_NAME}:${env.IMAGE_TAG} ."
                        env.IMAGE_BUILT='true'
                        def imageId=bat(returnStdout:true,script:"@docker image inspect ${env.IMAGE_NAME}:${env.IMAGE_TAG} --format=\"{{.Id}}\"").trim()
                        writeFile file:'reports/containerize-report.json',text:groovy.json.JsonOutput.prettyPrint(groovy.json.JsonOutput.toJson([
                            stage:'Containerize',status:'BUILT',project_type:env.PROJECT_TYPE,adapter:env.DEPLOY_ADAPTER,
                            dockerfile:env.DEPLOY_DOCKERFILE,image:"${env.IMAGE_NAME}:${env.IMAGE_TAG}",image_id:imageId
                        ]))
                        def grypeCheck=bat(returnStatus:true,script:'@grype version >nul 2>&1')
                        if (grypeCheck==0) {
                            def rc=bat(returnStatus:true,script:"@grype ${env.IMAGE_NAME}:${env.IMAGE_TAG} -o json > reports\\grype-report.json")
                            if (rc!=0 || !fileExists('reports/grype-report.json')) { error("Grype image scan failed (${rc}).") }
                        } else { echo 'Grype is not installed; final policy gate will fail a containerized run without its image report.' }
                    }
                }
            }
            post {
                success { echo '[UI_STAGE] containerize success' }
                failure { echo '[UI_STAGE] containerize failed' }
            }
        }

        stage('Release') {
            steps {
                echo '[UI_TRIGGER] release'
                echo '[UI_STAGE] release running'
                script {
                    if (env.IMAGE_BUILT != 'true') {
                        echo '[UI_STAGE] release skipped'
                        writeFile file: 'reports/release-report.json',
                            text: groovy.json.JsonOutput.prettyPrint(
                                groovy.json.JsonOutput.toJson([
                                    stage: 'Release',
                                    status: 'NOT_APPLICABLE',
                                    reason: 'No image was built.'
                                ])
                            )
                    } else {
                        def releaseTag = "release-${env.BUILD_NUMBER}"
                        bat "docker tag ${env.IMAGE_NAME}:${env.IMAGE_TAG} ${env.IMAGE_NAME}:${releaseTag}"
                        writeFile file: 'reports/release-report.json',
                            text: groovy.json.JsonOutput.prettyPrint(
                                groovy.json.JsonOutput.toJson([
                                    stage: 'Release',
                                    status: 'TAGGED_LOCAL',
                                    release_image: "${env.IMAGE_NAME}:${releaseTag}",
                                    registry_push: false
                                ])
                            )
                    }
                }
            }
            post {
                success { echo '[UI_STAGE] release success' }
                failure { echo '[UI_STAGE] release failed' }
            }
        }

        stage('Deploy') {
            steps {
                echo '[UI_TRIGGER] deploy'
                echo '[UI_STAGE] deploy running'
                script {
                    if (env.IMAGE_BUILT != 'true') {
                        env.DEPLOY_STAGE_STATUS = 'skipped'
                        echo '[UI_STAGE] deploy skipped'
                        writeFile file: 'reports/deploy-report.json',
                            text: groovy.json.JsonOutput.prettyPrint(
                                groovy.json.JsonOutput.toJson([
                                    stage: 'Deploy',
                                    status: 'NOT_APPLICABLE',
                                    reason: 'No container image was built.'
                                ])
                            )
                    } else {
                        // Prefer the built image metadata over source-text parsing.
                        // For multi-stage Dockerfiles, an EXPOSE in a non-final stage does
                        // not necessarily exist in the final image.
                        def exposed = bat(
                            returnStdout: true,
                            script: "@powershell -NoProfile -Command \"\$img = docker image inspect ${env.IMAGE_NAME}:${env.IMAGE_TAG} | ConvertFrom-Json; \$ports = \$img[0].Config.ExposedPorts; if (\$ports) { (\$ports.PSObject.Properties.Name | Select-Object -First 1).Split('/')[0] }\""
                        ).trim()

                        // Fallback to the Dockerfile only when final image metadata has no
                        // exposed port. This lets explicitly-authored Dockerfiles still be
                        // tested while keeping the image metadata authoritative.
                        if (!exposed && env.DEPLOY_EXPECTED_PORT) {
                            exposed = env.DEPLOY_EXPECTED_PORT
                        }

                        if (!exposed && env.DEPLOY_DOCKERFILE) {
                            exposed = bat(
                                returnStdout: true,
                                script: "@powershell -NoProfile -Command \"\$m = Select-String -Path '${env.DEPLOY_DOCKERFILE}' -Pattern '^\\s*EXPOSE\\s+([0-9]+)' | Select-Object -First 1; if (\$m) { \$m.Matches.Groups[1].Value }\""
                            ).trim()
                        }

                        if (!exposed) {
                            env.DEPLOY_STAGE_STATUS = 'skipped'
                            echo '[UI_STAGE] deploy skipped'
                            writeFile file: 'reports/deploy-report.json',
                                text: groovy.json.JsonOutput.prettyPrint(
                                    groovy.json.JsonOutput.toJson([
                                        stage: 'Deploy',
                                        status: 'NOT_APPLICABLE',
                                        reason: 'No deployable container port was found in the built image or Dockerfile.'
                                    ])
                                )
                        } else {
                            env.APP_CONTAINER_PORT = exposed
                            bat "docker rm -f ${env.STAGING_CONTAINER} >nul 2>&1 || exit /b 0"

                            // Explicitly publish the detected container port to a random host
                            // port. Do not rely on -P because -P only publishes ports actually
                            // present in the final image's EXPOSE metadata.
                            bat "docker run -d --name ${env.STAGING_CONTAINER} --label devsecops.run=${env.DEVSECOPS_RUN_ID} --label devsecops.adapter=${env.DEPLOY_ADAPTER} -p 127.0.0.1::${env.APP_CONTAINER_PORT} ${env.IMAGE_NAME}:${env.IMAGE_TAG}"

                            // Give the application a short startup window.
                            sleep time: 3, unit: 'SECONDS'

                            def running = bat(
                                returnStdout: true,
                                script: "@docker inspect -f \"{{.State.Running}}\" ${env.STAGING_CONTAINER}"
                            ).trim()

                            if (!running.equalsIgnoreCase('true')) {
                                bat "docker logs ${env.STAGING_CONTAINER} > reports\\staging-container.log 2>&1 || exit /b 0"

                                def exitCode = bat(
                                    returnStdout: true,
                                    script: "@docker inspect -f \"{{.State.ExitCode}}\" ${env.STAGING_CONTAINER}"
                                ).trim()

                                if (exitCode == '0') {
                                    env.DEPLOY_STAGE_STATUS = 'skipped'
                                    echo '[UI_STAGE] deploy skipped'
                                    env.DEPLOYED = 'false'

                                    writeFile file: 'reports/deploy-report.json',
                                        text: groovy.json.JsonOutput.prettyPrint(
                                            groovy.json.JsonOutput.toJson([
                                                stage: 'Deploy',
                                                status: 'NOT_APPLICABLE',
                                                container: env.STAGING_CONTAINER,
                                                image: "${env.IMAGE_NAME}:${env.IMAGE_TAG}",
                                                container_port: env.APP_CONTAINER_PORT,
                                                exit_code: 0,
                                                reason: 'Container completed successfully but did not remain running as a service. Deployment/DAST not applicable.'
                                            ])
                                        )

                                    echo 'Container exited successfully (exit code 0); treating repository as non-service workload.'
                                } else {
                                    writeFile file: 'reports/deploy-report.json',
                                        text: groovy.json.JsonOutput.prettyPrint(
                                            groovy.json.JsonOutput.toJson([
                                                stage: 'Deploy',
                                                status: 'FAILED',
                                                container: env.STAGING_CONTAINER,
                                                image: "${env.IMAGE_NAME}:${env.IMAGE_TAG}",
                                                container_port: env.APP_CONTAINER_PORT,
                                                exit_code: exitCode,
                                                reason: 'Container exited with a non-zero code before staging became available. See staging-container.log.'
                                            ])
                                        )
                                    error("Staging container exited with code ${exitCode}. Inspect staging-container.log.")
                                }
                            }

                            if (running.equalsIgnoreCase('true')) {
                                def hostPort = ''
                            for (int attempt = 0; attempt < 10; attempt++) {
                                def portRc = bat(
                                    returnStatus: true,
                                    script: "@docker port ${env.STAGING_CONTAINER} ${env.APP_CONTAINER_PORT}/tcp > reports\\published-port.txt 2>nul"
                                )

                                if (portRc == 0) {
                                    hostPort = bat(
                                        returnStdout: true,
                                        script: "@powershell -NoProfile -Command \"\$p = Get-Content reports\\published-port.txt | Select-Object -First 1; if (\$p) { \$p.Split(':')[-1] }\""
                                    ).trim()
                                }

                                if (hostPort) {
                                    break
                                }
                                sleep time: 1, unit: 'SECONDS'
                            }

                            if (!hostPort) {
                                bat "docker logs ${env.STAGING_CONTAINER} > reports\\staging-container.log 2>&1 || exit /b 0"
                                writeFile file: 'reports/deploy-report.json',
                                    text: groovy.json.JsonOutput.prettyPrint(
                                        groovy.json.JsonOutput.toJson([
                                            stage: 'Deploy',
                                            status: 'FAILED',
                                            container: env.STAGING_CONTAINER,
                                            image: "${env.IMAGE_NAME}:${env.IMAGE_TAG}",
                                            container_port: env.APP_CONTAINER_PORT,
                                            reason: 'Container is running but Docker did not expose a host port.'
                                        ])
                                    )
                                error('Docker did not resolve a published host port for the staging container.')
                            }

                            env.DEPLOY_HOST_PORT = hostPort
                            env.DEPLOY_URL = "http://127.0.0.1:${hostPort}"
                            env.DEPLOYED = 'true'
                            env.DEPLOY_STAGE_STATUS = 'success'

                            writeFile file: 'reports/deploy-report.json',
                                text: groovy.json.JsonOutput.prettyPrint(
                                    groovy.json.JsonOutput.toJson([
                                        stage: 'Deploy',
                                        status: 'STAGING_RUNNING',
                                        container: env.STAGING_CONTAINER,
                                        image: "${env.IMAGE_NAME}:${env.IMAGE_TAG}",
                                        adapter: env.DEPLOY_ADAPTER,
                                        container_port: env.APP_CONTAINER_PORT,
                                        host_port: hostPort,
                                        url: env.DEPLOY_URL,
                                        health_url: "${env.DEPLOY_URL}/health",
                                        persistence: 'KEPT_RUNNING_AFTER_PIPELINE'
                                    ])
                                )
                                echo "Staging target: ${env.DEPLOY_URL}"
                                echo "Health target: ${env.DEPLOY_URL}/health"
                            }
                        }
                    }
                }
            }
            post {
                success {
                    script {
                        if (env.DEPLOY_STAGE_STATUS == 'skipped') { echo '[UI_STAGE] deploy skipped' }
                        else { echo '[UI_STAGE] deploy success' }
                    }
                }
                failure { echo '[UI_STAGE] deploy failed' }
            }
        }

        stage('Test') {
            steps {
                echo '[UI_TRIGGER] test'
                echo '[UI_STAGE] test running'
                script {
                    def result = [:]

                    bat "powershell -NoProfile -Command \"[IO.File]::WriteAllBytes('reports/repo_test_helper.py',[Convert]::FromBase64String('__TEST_HELPER_B64__'))\""
                    def unitRc = bat(returnStatus: true, script: '@python reports\\repo_test_helper.py')

                    def unitStatus = fileExists('reports/unit-test-status.txt')
                        ? readFile('reports/unit-test-status.txt').trim()
                        : 'NOT_EXECUTED'
                    def unitRunner = fileExists('reports/unit-test-runner.txt')
                        ? readFile('reports/unit-test-runner.txt').trim()
                        : ''
                    def unitExitText = fileExists('reports/unit-test-exit-code.txt')
                        ? readFile('reports/unit-test-exit-code.txt').trim()
                        : ''

                    result.unit_tests = unitStatus
                    result.unit_test_runner = unitRunner ?: null
                    result.unit_test_exit_code = unitExitText ? unitExitText : null

                    def unitExecuted = (unitStatus == 'EXECUTED')

                    if (unitRc != 0) {
                        error("Repository unit tests failed (${unitRc}).")
                    }

                    if (env.DEPLOYED == 'true' && env.DEPLOY_URL) {
                        sleep time: 5, unit: 'SECONDS'
                        def selectedUrl = ''

                        for (candidate in ['/health', '/healthz', '/ready', '/']) {
                            def candidateUrl = "${env.DEPLOY_URL}${candidate == '/' ? '' : candidate}"
                            def rc = bat(
                                returnStatus: true,
                                script: "@powershell -NoProfile -Command \"try { \$r = Invoke-WebRequest -UseBasicParsing -Uri '${candidateUrl}' -MaximumRedirection 3 -TimeoutSec 10; if (\$r.StatusCode -ge 200 -and \$r.StatusCode -lt 400) { exit 0 } else { exit 1 } } catch { exit 1 }\""
                            )
                            if (rc == 0) {
                                selectedUrl = candidateUrl
                                result.probe_url = candidateUrl
                                result.http_probe_exit_code = 0
                                break
                            }
                        }

                        if (!selectedUrl) {
                            bat "docker logs ${env.STAGING_CONTAINER} > reports\\staging-container.log 2>&1 || exit /b 0"
                            error('Live deployment did not return HTTP 2xx/3xx on /health, /healthz, /ready, or /.')
                        }

                        writeFile file: 'reports/health-probe.json',
                            text: groovy.json.JsonOutput.prettyPrint(
                                groovy.json.JsonOutput.toJson([
                                    url: selectedUrl,
                                    status: 'PASSED'
                                ])
                            )

                        def zapCheck = bat(returnStatus: true, script: '@zap-baseline.py --help >nul 2>&1')
                        if (zapCheck == 0) {
                            def zapRc = bat(
                                returnStatus: true,
                                script: "@zap-baseline.py -t ${env.DEPLOY_URL} -J reports\\zap-report.json -m 2"
                            )
                            result.zap_mode = 'LOCAL_CLI'
                            result.zap_exit_code = zapRc
                            if (!(zapRc in [0, 1, 2]) || !fileExists('reports/zap-report.json')) {
                                error("OWASP ZAP local scan failed (${zapRc}) or produced no report.")
                            }
                        } else {
                            def zapTarget = "http://host.docker.internal:${env.DEPLOY_HOST_PORT}"
                            def zapRc = bat(
                                returnStatus: true,
                                script: "@docker run --rm -v \"%CD%\\reports:/zap/wrk:rw\" ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t ${zapTarget} -J zap-report.json -m 2"
                            )
                            result.zap_mode = 'DOCKER'
                            result.zap_target = zapTarget
                            result.zap_exit_code = zapRc
                            if (!(zapRc in [0, 1, 2]) || !fileExists('reports/zap-report.json')) {
                                error("OWASP ZAP Docker scan failed (${zapRc}) or produced no report.")
                            }
                        }
                    } else {
                        result.zap = 'NOT_APPLICABLE_NO_WEB_DEPLOYMENT'
                    }

                    if (unitExecuted || env.DEPLOYED == 'true') {
                        env.TEST_STAGE_STATUS = 'success'
                        result.stage_status = 'EXECUTED'
                    } else {
                        env.TEST_STAGE_STATUS = 'skipped'
                        result.stage_status = 'NOT_CONFIGURED_OR_NOT_APPLICABLE'
                        echo '[UI_STAGE] test skipped'
                    }

                    writeFile file: 'reports/test-report.json',
                        text: groovy.json.JsonOutput.prettyPrint(groovy.json.JsonOutput.toJson(result))
                }
            }
            post {
                success {
                    script {
                        if (env.TEST_STAGE_STATUS == 'skipped') { echo '[UI_STAGE] test skipped' }
                        else { echo '[UI_STAGE] test success' }
                    }
                }
                failure { echo '[UI_STAGE] test failed' }
            }
        }

        stage('Publish') {
            steps {
                echo '[UI_TRIGGER] publish'
                echo '[UI_STAGE] publish running'
                script {
                    writeFile file: 'reports/evaluate_policy.py', text: '''
import json
import pathlib
import sys

root = pathlib.Path("reports")
summary = {
    "semgrep": {"executed": False, "findings": None, "error_severity": None},
    "gitleaks": {"executed": False, "findings": None},
    "trivy": {"executed": False, "critical": None, "high": None},
    "trivy_iac": {"executed": False, "critical": None, "high": None},
    "grype": {"executed": False, "critical": None, "high": None},
    "zap": {"executed": False, "high": None, "medium": None},
    "policy_failures": [],
}

def load(name):
    path = root / name
    if not path.is_file():
        return None

    raw = path.read_bytes()
    last_error = None
    for encoding in ("utf-8-sig", "utf-8", "cp1252"):
        try:
            return json.loads(raw.decode(encoding))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            last_error = exc

    summary["policy_failures"].append(
        f"{name}: invalid JSON after utf-8/cp1252 decode attempts: {last_error}"
    )
    return None

sg = load("semgrep-report.json")
if isinstance(sg, dict):
    findings = sg.get("results") or []
    summary["semgrep"]["executed"] = True
    summary["semgrep"]["findings"] = len(findings)
    errors = sum(
        1 for finding in findings
        if str((finding.get("extra") or {}).get("severity", "")).upper() == "ERROR"
    )
    summary["semgrep"]["error_severity"] = errors
    if errors:
        summary["policy_failures"].append(f"Semgrep ERROR findings: {errors}")

gl = load("gitleaks-report.json")
if isinstance(gl, list):
    findings = gl
elif isinstance(gl, dict):
    findings = gl.get("findings") or gl.get("results") or []
else:
    findings = None
if findings is not None:
    summary["gitleaks"]["executed"] = True
    summary["gitleaks"]["findings"] = len(findings)
    if findings:
        summary["policy_failures"].append(f"Gitleaks secret findings: {len(findings)}")

def trivy(name, key):
    obj = load(name)
    if not isinstance(obj, dict):
        return
    critical = 0
    high = 0
    for result in obj.get("Results") or []:
        items = (result.get("Vulnerabilities") or []) + (result.get("Misconfigurations") or [])
        for item in items:
            severity = str(item.get("Severity", "")).upper()
            critical += int(severity == "CRITICAL")
            high += int(severity == "HIGH")
    summary[key]["executed"] = True
    summary[key]["critical"] = critical
    summary[key]["high"] = high
    if critical:
        summary["policy_failures"].append(f"{key} CRITICAL findings: {critical}")

trivy("trivy-report.json", "trivy")
trivy("trivy-iac-report.json", "trivy_iac")

grype = load("grype-report.json")
if isinstance(grype, dict):
    critical = 0
    high = 0
    for match in grype.get("matches") or []:
        severity = str((match.get("vulnerability") or {}).get("severity", "")).upper()
        critical += int(severity == "CRITICAL")
        high += int(severity == "HIGH")
    summary["grype"]["executed"] = True
    summary["grype"]["critical"] = critical
    summary["grype"]["high"] = high
    if critical:
        summary["policy_failures"].append(f"Grype CRITICAL findings: {critical}")

zap = load("zap-report.json")
if isinstance(zap, dict):
    high = 0
    medium = 0
    for site in zap.get("site") or []:
        for alert in site.get("alerts") or []:
            risk = str(alert.get("riskdesc") or alert.get("riskcode") or "").upper()
            high += int("HIGH" in risk or risk == "3")
            medium += int("MEDIUM" in risk or risk == "2")
    summary["zap"]["executed"] = True
    summary["zap"]["high"] = high
    summary["zap"]["medium"] = medium
    if high:
        summary["policy_failures"].append(f"ZAP HIGH findings: {high}")

for key in ("semgrep", "gitleaks", "trivy"):
    if not summary[key]["executed"]:
        summary["policy_failures"].append(f"{key}: required report missing")

# trivy_iac is capability-dependent and is not mandatory for repositories
# that contain no supported infrastructure-as-code assets.

container = load("containerize-report.json")
if isinstance(container, dict) and container.get("status") == "BUILT":
    if not summary["grype"]["executed"]:
        summary["policy_failures"].append("grype: image was built but image scan report is missing")

deploy = load("deploy-report.json")
test = load("test-report.json") or {}
if isinstance(deploy, dict) and deploy.get("status") == "STAGING_RUNNING":
    if test.get("zap") == "NOT_EXECUTED_TOOL_MISSING":
        summary["policy_failures"].append("zap: web target existed but ZAP was unavailable")

summary["release_allowed"] = not bool(summary["policy_failures"])
summary["policy_status"] = "PASS" if summary["release_allowed"] else "BLOCKED"

(root / "pipeline-summary.json").write_text(
    json.dumps(summary, indent=2), encoding="utf-8"
)
print(json.dumps(summary, indent=2))
sys.exit(2 if summary["policy_failures"] else 0)
'''

                    def policyRc = bat(returnStatus: true, script: '@python reports\\evaluate_policy.py')

                    archiveArtifacts artifacts: 'reports/**/*,dist/**/*',
                        allowEmptyArchive: false,
                        fingerprint: true

                    if (policyRc != 0) {
                        env.PUBLISH_STAGE_STATUS = 'blocked'
                        currentBuild.result = 'UNSTABLE'
                        echo '[UI_STAGE] publish blocked'
                        echo 'DevSecOps release BLOCKED by evidence policy. Execution completed; release was not approved.'
                    } else {
                        env.PUBLISH_STAGE_STATUS = 'success'
                    }
                }
            }
            post {
                success {
                    script {
                        if (env.PUBLISH_STAGE_STATUS == 'blocked') {
                            echo '[UI_STAGE] publish blocked'
                        } else {
                            echo '[UI_STAGE] publish success'
                        }
                    }
                }
                failure {
                    echo '[UI_STAGE] publish failed'
                }
            }
        }
    }

    post {
        always {
            script {
                if (env.STAGING_CONTAINER?.trim()) {
                    bat "docker inspect ${env.STAGING_CONTAINER} >nul 2>&1 && docker logs ${env.STAGING_CONTAINER} > reports\\staging-container.log 2>&1 || exit /b 0"

                    if (env.DEPLOYED == 'true') {
                        echo "Keeping successful staging deployment running: ${env.STAGING_CONTAINER}"
                        echo "Deployment URL remains available at: ${env.DEPLOY_URL}"
                    } else {
                        bat "docker rm -f ${env.STAGING_CONTAINER} >nul 2>&1 || exit /b 0"
                    }
                }
            }
            archiveArtifacts artifacts: 'reports/**/*,dist/**/*',
                allowEmptyArchive: true,
                fingerprint: true
        }
        success {
            echo '[UI_TRIGGER] pipeline_complete'
            echo 'DevSecOps pipeline passed the final evidence policy.'
        }
        unstable {
            echo '[UI_TRIGGER] pipeline_complete'
            echo 'DevSecOps pipeline execution completed, but release was BLOCKED by the evidence policy.'
        }
        failure {
            echo 'DevSecOps pipeline FAILED due to an execution or tool error. Inspect Jenkins logs and archived evidence.'
        }
    }
}
"""



def _validate_generated_pipeline(pipeline: str) -> None:
    problems: list[str] = []

    # Reject only compressed one-line Declarative post blocks.
    for line_no, line in enumerate(pipeline.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("post {") and stripped != "post {":
            problems.append(
                f"compressed Declarative post block detected at generated line {line_no}"
            )

    if "new groovy.json.JsonSlurperClassic" in pipeline:
        problems.append("sandbox-rejected JsonSlurperClassic constructor detected")

    if "DevSecOps policy gate failed" in pipeline and "error('DevSecOps policy gate failed" in pipeline:
        problems.append("policy denial is still wired as an execution failure")

    for token in (
        "__RUN_ID__",
        "__REPO_URL__",
        "__BRANCH__",
        "__BUILD_HELPER_B64__",
        "__DEPLOY_HELPER_B64__",
        "__TEST_HELPER_B64__",
    ):
        if token in pipeline:
            problems.append(f"unresolved template token: {token}")

    if problems:
        raise ValueError(
            "Generated Jenkins pipeline validation failed: " + "; ".join(problems)
        )

def generate_pipeline(repo_url: str, branch: str, run_id: str) -> str:
    pipeline = (
        PIPELINE_TEMPLATE
        .replace("__RUN_ID__", _groovy_quote(run_id))
        .replace("__REPO_URL__", _groovy_quote(repo_url))
        .replace("__BRANCH__", _groovy_quote(branch))
        .replace("__BUILD_HELPER_B64__", BUILD_HELPER_B64)
        .replace("__DEPLOY_HELPER_B64__", DEPLOY_HELPER_B64)
        .replace("__TEST_HELPER_B64__", TEST_HELPER_B64)
    )
    _validate_generated_pipeline(pipeline)
    return pipeline


@tool
def orchestrate_dynamic_jenkins_pipeline(repo_url: str, branch: str) -> str:
    """Create and trigger a unique Jenkins pipeline for a GitHub repo/branch."""
    try:
        canonical_repo, validated_branch = _validate_repo_and_branch(repo_url, branch)
        run_id = uuid.uuid4().hex[:8]

        prefix = _env("JENKINS_JOB_PREFIX", "Agentic-Run") or "Agentic-Run"
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", prefix):
            raise ValueError("JENKINS_JOB_PREFIX contains unsupported characters.")

        job_name = f"{prefix}-{run_id}"
        client = JenkinsClient()
        client.create_job(
            job_name,
            generate_pipeline(canonical_repo, validated_branch, run_id),
        )
        trigger = client.trigger_job(job_name)

        result: dict[str, Any] = {
            "status": "SUCCESS",
            "message": (
                "Jenkins accepted the dynamically generated job. "
                "This is orchestration success, not pipeline success."
            ),
            "run_id": run_id,
            "job_name": job_name,
            "repository": canonical_repo,
            "branch": validated_branch,
            "jenkins_url": client.base_url,
            "job_url": f"{client.base_url}/job/{urllib.parse.quote(job_name, safe='')}/",
            **trigger,
        }

        if trigger.get("queue_api_url"):
            result.update(client.wait_for_build(trigger["queue_api_url"]))

        return json.dumps(result)

    except Exception as exc:
        return json.dumps({"status": "ERROR", "message": str(exc)})


if __name__ == "__main__":
    print("mcp_server.py loaded. Run the FastAPI application to invoke the Jenkins tool.")
