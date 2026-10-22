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
                git branch: env.REPOSITORY_BRANCH, url: env.REPOSITORY_URL
                bat 'if not exist reports mkdir reports'
                bat 'if not exist dist mkdir dist'
                bat 'git rev-parse HEAD > reports\\git-commit.txt'

                script {
                    // Mutable values must NOT be declared in the Declarative
                    // environment{} block because Jenkins prevents imperative
                    // env assignments from overriding those values.
                    env.PROJECT_TYPE = 'unknown'
                    env.HAS_DOCKERFILE = fileExists('Dockerfile') ? 'true' : 'false'
                    env.IMAGE_NAME = "agentic-devsecops-${env.DEVSECOPS_RUN_ID}"
                    env.IMAGE_TAG = "build-${env.BUILD_NUMBER}"
                    env.STAGING_CONTAINER = "agentic-stage-${env.DEVSECOPS_RUN_ID}"
                    env.IMAGE_BUILT = 'false'
                    env.DEPLOYED = 'false'
                    env.DEPLOY_URL = ''
                    env.APP_CONTAINER_PORT = ''

                    // Detect the application ecosystem independently from Docker support.
                    // A repository can be Python + Docker, Node + Docker, Java + Docker, etc.
                    if (fileExists('pyproject.toml') || fileExists('setup.py') || fileExists('requirements.txt')) {
                        env.PROJECT_TYPE = 'python'
                    } else if (fileExists('package.json')) {
                        env.PROJECT_TYPE = 'node'
                    } else if (fileExists('pom.xml')) {
                        env.PROJECT_TYPE = 'maven'
                    } else if (fileExists('gradlew.bat') || fileExists('build.gradle') || fileExists('build.gradle.kts')) {
                        env.PROJECT_TYPE = 'gradle'
                    } else if (fileExists('go.mod')) {
                        env.PROJECT_TYPE = 'go'
                    } else {
                        def dotnetRc = bat(returnStatus: true, script: '@dir /b *.sln *.csproj >nul 2>&1')
                        if (dotnetRc == 0) {
                            env.PROJECT_TYPE = 'dotnet'
                        } else {
                            // Generic source discovery without optional Jenkins plugins.
                            // findFiles belongs to Pipeline Utility Steps and is not guaranteed
                            // to exist on a minimal Jenkins installation, so use native Windows
                            // commands available to this Windows Jenkins agent.
                            def pythonSourceRc = bat(
                                returnStatus: true,
                                script: '@dir /s /b *.py *.ipynb >nul 2>&1'
                            )
                            def nodeSourceRc = bat(
                                returnStatus: true,
                                script: '@dir /s /b *.js *.ts *.jsx *.tsx >nul 2>&1'
                            )

                            if (pythonSourceRc == 0) {
                                env.PROJECT_TYPE = 'python'
                            } else if (nodeSourceRc == 0) {
                                env.PROJECT_TYPE = 'node-source'
                            } else if (env.HAS_DOCKERFILE == 'true') {
                                // Docker-only means no supported application ecosystem was
                                // identified, but the repository still supplies its own build.
                                env.PROJECT_TYPE = 'docker-only'
                            } else {
                                env.PROJECT_TYPE = 'unknown'
                            }
                        }
                    }

                    echo "Detected project type: ${env.PROJECT_TYPE}"
                    echo "Dockerfile present: ${env.HAS_DOCKERFILE}"

                    def metadata = [
                        run_id: env.DEVSECOPS_RUN_ID,
                        repository: env.REPOSITORY_URL,
                        branch: env.REPOSITORY_BRANCH,
                        commit: bat(returnStdout: true, script: '@git rev-parse HEAD').trim(),
                        project_type: env.PROJECT_TYPE,
                        dockerfile_present: (env.HAS_DOCKERFILE == 'true'),
                        jenkins_build: env.BUILD_NUMBER
                    ]
                    writeFile file: 'reports/project-metadata.json',
                        text: groovy.json.JsonOutput.prettyPrint(groovy.json.JsonOutput.toJson(metadata))

                    if (env.PROJECT_TYPE == 'python') {
                        bat 'python --version'
                        if (fileExists('requirements.txt')) {
                            bat 'python -m pip install --disable-pip-version-check -r requirements.txt'
                        }
                        if (fileExists('pyproject.toml') || fileExists('setup.py')) {
                            bat 'python -m pip install --disable-pip-version-check build'
                            bat 'python -m build'
                        }
                    } else if (env.PROJECT_TYPE == 'node') {
                        bat 'node --version'
                        bat 'npm --version'
                        if (fileExists('package-lock.json')) {
                            bat 'npm ci'
                        } else {
                            bat 'npm install'
                        }
                        bat 'npm run build --if-present'
                    } else if (env.PROJECT_TYPE == 'maven') {
                        bat 'mvn --version'
                        bat 'mvn -B -DskipTests package'
                    } else if (env.PROJECT_TYPE == 'gradle') {
                        if (fileExists('gradlew.bat')) {
                            bat 'gradlew.bat assemble --no-daemon'
                        } else {
                            bat 'gradle assemble --no-daemon'
                        }
                    } else if (env.PROJECT_TYPE == 'dotnet') {
                        bat 'dotnet --info'
                        bat 'dotnet restore'
                        bat 'dotnet build --configuration Release --no-restore'
                    } else if (env.PROJECT_TYPE == 'go') {
                        bat 'go version'
                        bat 'go mod download'
                        bat 'go build ./...'
                    } else if (env.PROJECT_TYPE == 'node-source') {
                        bat 'node --version'
                        echo 'JavaScript/TypeScript source detected without package.json; no dependency/build script was invented.'
                    } else if (env.PROJECT_TYPE == 'docker-only') {
                        bat 'docker --version'
                        echo 'Docker-only repository: application build is delegated to its Dockerfile.'
                    } else {
                        error('Unsupported repository: no recognized ecosystem, source type, or Dockerfile was detected.')
                    }
                }
            }
            post {
                success { echo '[UI_STAGE] build success' }
                failure { echo '[UI_STAGE] build failed' }
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
                        def wheelRc = bat(returnStatus: true, script: '@dir /b dist\\*.whl dist\\*.tar.gz >nul 2>&1')
                        if (wheelRc != 0) {
                            bat 'git archive --format=zip --output=dist\\source-package.zip HEAD'
                        }
                    } else if (env.PROJECT_TYPE == 'node') {
                        bat 'npm pack --pack-destination dist'
                    } else if (env.PROJECT_TYPE == 'maven') {
                        bat 'powershell -NoProfile -Command "Get-ChildItem target -Include *.jar,*.war -File -ErrorAction SilentlyContinue | Copy-Item -Destination dist -Force"'
                    } else if (env.PROJECT_TYPE == 'gradle') {
                        bat 'powershell -NoProfile -Command "Get-ChildItem build\\libs -Include *.jar,*.war -File -ErrorAction SilentlyContinue | Copy-Item -Destination dist -Force"'
                    } else if (env.PROJECT_TYPE == 'dotnet') {
                        bat 'dotnet publish --configuration Release --output dist'
                    } else if (env.PROJECT_TYPE == 'go') {
                        bat 'go build -o dist\\application.exe .'
                    } else {
                        // For source-only and docker-only repositories, a git archive is a
                        // real immutable package of the checked-out commit.
                        bat 'git archive --format=zip --output=dist\\source-package.zip HEAD'
                    }

                    def count = bat(returnStdout: true, script: '@powershell -NoProfile -Command "(Get-ChildItem dist -File -Recurse | Measure-Object).Count"').trim()
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
                    if (env.HAS_DOCKERFILE != 'true') {
                        echo '[UI_STAGE] containerize skipped'
                        writeFile file: 'reports/containerize-report.json',
                            text: groovy.json.JsonOutput.prettyPrint(
                                groovy.json.JsonOutput.toJson([
                                    stage: 'Containerize',
                                    status: 'NOT_APPLICABLE',
                                    reason: 'Repository has no Dockerfile; no image was fabricated.'
                                ])
                            )
                    } else {
                        bat 'docker --version'
                        bat 'docker info'
                        bat "docker build --pull --label devsecops.run=${env.DEVSECOPS_RUN_ID} -t ${env.IMAGE_NAME}:${env.IMAGE_TAG} ."
                        env.IMAGE_BUILT = 'true'

                        def imageId = bat(
                            returnStdout: true,
                            script: "@docker image inspect ${env.IMAGE_NAME}:${env.IMAGE_TAG} --format=\"{{.Id}}\""
                        ).trim()

                        writeFile file: 'reports/containerize-report.json',
                            text: groovy.json.JsonOutput.prettyPrint(
                                groovy.json.JsonOutput.toJson([
                                    stage: 'Containerize',
                                    status: 'BUILT',
                                    image: "${env.IMAGE_NAME}:${env.IMAGE_TAG}",
                                    image_id: imageId
                                ])
                            )

                        def grypeCheck = bat(returnStatus: true, script: '@grype version >nul 2>&1')
                        if (grypeCheck == 0) {
                            def rc = bat(returnStatus: true, script: "@grype ${env.IMAGE_NAME}:${env.IMAGE_TAG} -o json > reports\\grype-report.json")
                            if (rc != 0 || !fileExists('reports/grype-report.json')) {
                                error("Grype image scan failed (${rc}).")
                            }
                        } else {
                            echo 'Grype is not installed; final policy gate will fail a containerized run without its image report.'
                        }
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
                        if (!exposed) {
                            exposed = bat(
                                returnStdout: true,
                                script: "@powershell -NoProfile -Command \"\$m = Select-String -Path Dockerfile -Pattern '^\\s*EXPOSE\\s+([0-9]+)' | Select-Object -First 1; if (\$m) { \$m.Matches.Groups[1].Value }\""
                            ).trim()
                        }

                        if (!exposed) {
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
                            bat "docker run -d --name ${env.STAGING_CONTAINER} --label devsecops.run=${env.DEVSECOPS_RUN_ID} -p ${env.APP_CONTAINER_PORT} ${env.IMAGE_NAME}:${env.IMAGE_TAG}"

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

                            env.DEPLOY_URL = "http://127.0.0.1:${hostPort}"
                            env.DEPLOYED = 'true'

                            writeFile file: 'reports/deploy-report.json',
                                text: groovy.json.JsonOutput.prettyPrint(
                                    groovy.json.JsonOutput.toJson([
                                        stage: 'Deploy',
                                        status: 'STAGING_RUNNING',
                                        container: env.STAGING_CONTAINER,
                                        image: "${env.IMAGE_NAME}:${env.IMAGE_TAG}",
                                        container_port: env.APP_CONTAINER_PORT,
                                        host_port: hostPort,
                                        url: env.DEPLOY_URL
                                    ])
                                )
                                echo "Staging target: ${env.DEPLOY_URL}"
                            }
                        }
                    }
                }
            }
            post {
                success { echo '[UI_STAGE] deploy success' }
                failure { echo '[UI_STAGE] deploy failed' }
            }
        }

        stage('Test') {
            steps {
                echo '[UI_TRIGGER] test'
                echo '[UI_STAGE] test running'
                script {
                    def result = [:]

                    if (env.PROJECT_TYPE == 'python') {
                        def pytest = bat(returnStatus: true, script: '@python -m pytest --version >nul 2>&1')
                        if (pytest == 0) {
                            def rc = bat(returnStatus: true, script: '@python -m pytest -q --junitxml=reports\\pytest-junit.xml')
                            result.unit_test_exit_code = rc
                            if (rc != 0) { error("Python tests failed (${rc}).") }
                        } else {
                            result.unit_tests = 'NOT_CONFIGURED'
                            echo 'pytest not available; no Python test result is being invented.'
                        }
                    } else if (env.PROJECT_TYPE == 'node') {
                        def rc = bat(returnStatus: true, script: '@npm test --if-present')
                        result.unit_test_exit_code = rc
                        if (rc != 0) { error("Node tests failed (${rc}).") }
                    } else if (env.PROJECT_TYPE == 'maven') {
                        def rc = bat(returnStatus: true, script: '@mvn -B test')
                        result.unit_test_exit_code = rc
                        if (rc != 0) { error("Maven tests failed (${rc}).") }
                    } else if (env.PROJECT_TYPE == 'gradle') {
                        def command = fileExists('gradlew.bat') ? 'gradlew.bat test --no-daemon' : 'gradle test --no-daemon'
                        def rc = bat(returnStatus: true, script: command)
                        result.unit_test_exit_code = rc
                        if (rc != 0) { error("Gradle tests failed (${rc}).") }
                    } else if (env.PROJECT_TYPE == 'dotnet') {
                        def rc = bat(returnStatus: true, script: '@dotnet test --configuration Release --no-build')
                        result.unit_test_exit_code = rc
                        if (rc != 0) { error(".NET tests failed (${rc}).") }
                    } else if (env.PROJECT_TYPE == 'go') {
                        def rc = bat(returnStatus: true, script: '@go test ./...')
                        result.unit_test_exit_code = rc
                        if (rc != 0) { error("Go tests failed (${rc}).") }
                    } else {
                        result.unit_tests = 'NOT_APPLICABLE'
                    }

                    if (env.DEPLOYED == 'true' && env.DEPLOY_URL) {
                        sleep time: 5, unit: 'SECONDS'
                        def probe = bat(
                            returnStatus: true,
                            script: "@powershell -NoProfile -Command \"try { Invoke-WebRequest -UseBasicParsing -Uri '${env.DEPLOY_URL}' -TimeoutSec 15 | Out-Null; exit 0 } catch { exit 1 }\""
                        )
                        result.http_probe_exit_code = probe

                        def zapCheck = bat(returnStatus: true, script: '@zap-baseline.py --help >nul 2>&1')
                        if (zapCheck == 0) {
                            def zapRc = bat(
                                returnStatus: true,
                                script: "@zap-baseline.py -t ${env.DEPLOY_URL} -J reports\\zap-report.json -m 2"
                            )
                            result.zap_exit_code = zapRc
                            if (!fileExists('reports/zap-report.json')) {
                                error('OWASP ZAP did not produce zap-report.json.')
                            }
                        } else {
                            result.zap = 'NOT_EXECUTED_TOOL_MISSING'
                            echo 'OWASP ZAP CLI is unavailable; Publish will treat this as an evidence gap.'
                        }
                    } else {
                        result.zap = 'NOT_APPLICABLE_NO_WEB_DEPLOYMENT'
                    }

                    writeFile file: 'reports/test-report.json',
                        text: groovy.json.JsonOutput.prettyPrint(groovy.json.JsonOutput.toJson(result))
                }
            }
            post {
                success { echo '[UI_STAGE] test success' }
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
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        summary["policy_failures"].append(f"{name}: invalid JSON: {exc}")
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

for key in ("semgrep", "gitleaks", "trivy", "trivy_iac"):
    if not summary[key]["executed"]:
        summary["policy_failures"].append(f"{key}: required report missing")

container = load("containerize-report.json")
if isinstance(container, dict) and container.get("status") == "BUILT":
    if not summary["grype"]["executed"]:
        summary["policy_failures"].append("grype: image was built but image scan report is missing")

deploy = load("deploy-report.json")
test = load("test-report.json") or {}
if isinstance(deploy, dict) and deploy.get("status") == "STAGING_RUNNING":
    if test.get("zap") == "NOT_EXECUTED_TOOL_MISSING":
        summary["policy_failures"].append("zap: web target existed but ZAP was unavailable")

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
                        error('DevSecOps policy gate failed. Inspect reports/pipeline-summary.json and scanner artifacts.')
                    }
                }
            }
            post {
                success { echo '[UI_STAGE] publish success' }
                failure { echo '[UI_STAGE] publish failed' }
            }
        }
    }

    post {
        always {
            script {
                if (env.STAGING_CONTAINER?.trim()) {
                    bat "docker inspect ${env.STAGING_CONTAINER} >nul 2>&1 && docker logs ${env.STAGING_CONTAINER} > reports\\staging-container.log 2>&1 || exit /b 0"
                    bat "docker rm -f ${env.STAGING_CONTAINER} >nul 2>&1 || exit /b 0"
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
        failure {
            echo 'DevSecOps pipeline failed. Inspect Jenkins logs and archived evidence.'
        }
    }
}
"""


def generate_pipeline(repo_url: str, branch: str, run_id: str) -> str:
    return (
        PIPELINE_TEMPLATE
        .replace("__RUN_ID__", _groovy_quote(run_id))
        .replace("__REPO_URL__", _groovy_quote(repo_url))
        .replace("__BRANCH__", _groovy_quote(branch))
    )


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
