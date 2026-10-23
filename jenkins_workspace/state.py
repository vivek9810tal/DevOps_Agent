"""state.py - Shared state for the multi-agent Agentic DevSecOps graph."""
from typing import Annotated, Any, Dict, List, Literal, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages

StageStatus = Literal["pending", "queued", "running", "success", "failed", "skipped", "blocked"]


class StageStatuses(TypedDict, total=False):
    build: StageStatus
    scan: StageStatus
    package: StageStatus
    containerize: StageStatus
    release: StageStatus
    deploy: StageStatus
    test: StageStatus
    publish: StageStatus


class CICDState(TypedDict, total=False):
    # User request
    repo_url: str
    branch: str
    messages: Annotated[List[BaseMessage], add_messages]

    # Agent workflow
    active_phase: str
    repository_inventory: Dict[str, Any]
    repo_analysis: Dict[str, Any]
    build_strategy: Dict[str, Any]
    security_strategy: Dict[str, Any]
    deployment_strategy: Dict[str, Any]
    test_strategy: Dict[str, Any]
    execution_evidence: Dict[str, Any]
    policy_decision: Dict[str, Any]

    # Jenkins/run metadata
    run_id: str
    jenkins_job_name: str
    jenkins_build_number: int
    jenkins_build_url: str
    jenkins_queue_url: str
    pipeline_status: Literal[
        "pending", "queued", "running", "success", "failed", "blocked", "unknown"
    ]
    error_message: str
    jenkins_triggered: bool

    # Backward-compatible execution state
    build_complete: bool
    scan_complete: bool
    package_complete: bool
    containerize_complete: bool
    release_complete: bool
    deploy_complete: bool
    test_complete: bool
    publish_complete: bool
    stage_statuses: StageStatuses
    vulnerabilities_found: bool
    scan_results: Dict[str, Any]
    report_paths: Dict[str, str]
    report_urls: Dict[str, str]


def make_initial_state(repo_url: str, branch: str = "main") -> CICDState:
    return {
        "repo_url": repo_url,
        "branch": branch,
        "messages": [],
        "active_phase": "init",
        "repository_inventory": {},
        "repo_analysis": {},
        "build_strategy": {},
        "security_strategy": {},
        "deployment_strategy": {},
        "test_strategy": {},
        "execution_evidence": {},
        "policy_decision": {},
        "run_id": "",
        "jenkins_job_name": "",
        "jenkins_build_number": 0,
        "jenkins_build_url": "",
        "jenkins_queue_url": "",
        "pipeline_status": "pending",
        "error_message": "",
        "jenkins_triggered": False,
        "build_complete": False,
        "scan_complete": False,
        "package_complete": False,
        "containerize_complete": False,
        "release_complete": False,
        "deploy_complete": False,
        "test_complete": False,
        "publish_complete": False,
        "stage_statuses": {
            "build": "pending",
            "scan": "pending",
            "package": "pending",
            "containerize": "pending",
            "release": "pending",
            "deploy": "pending",
            "test": "pending",
            "publish": "pending",
        },
        "vulnerabilities_found": False,
        "scan_results": {},
        "report_paths": {},
        "report_urls": {},
    }
