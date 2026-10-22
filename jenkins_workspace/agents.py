"""agents.py - Supervisor agent that dispatches the planned run to Jenkins."""
import json
import os
from typing import Any

from dotenv import load_dotenv
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

from mcp_server import orchestrate_dynamic_jenkins_pipeline
from state import CICDState

load_dotenv()

jenkins_tools = [orchestrate_dynamic_jenkins_pipeline]


def _build_llm():
    key = os.getenv("OPENAI_API_KEY", "").strip().strip('"').strip("'")
    if not key:
        raise RuntimeError("OPENAI_API_KEY is missing.")
    return ChatOpenAI(
        model=(os.getenv("OPENAI_MODEL", "gpt-4o").strip() or "gpt-4o"),
        temperature=0,
        request_timeout=45,
        max_retries=2,
    )


llm_with_tools = _build_llm().bind_tools(jenkins_tools)

SYSTEM_INSTRUCTION = """
You are the Supervisor Agent for a multi-agent Agentic DevSecOps platform.

Specialized agents have already analyzed repository, build, security, deployment
and test strategy. Your responsibility is to review those plans and dispatch the
exact GitHub repository/branch to orchestrate_dynamic_jenkins_pipeline exactly once.

Jenkins remains the deterministic execution authority. Planning does not equal
execution. Never claim build, scan, deploy or test success before Jenkins proves it.
""".strip()


def jenkins_supervisor_agent(state: CICDState) -> dict[str, Any]:
    repo = str(state.get("repo_url", "")).strip()
    branch = str(state.get("branch", "main")).strip() or "main"

    if not repo:
        raise ValueError("Missing repo_url.")
    if not branch:
        raise ValueError("Missing branch.")

    plans = {
        "repo_analysis": state.get("repo_analysis", {}),
        "build_strategy": state.get("build_strategy", {}),
        "security_strategy": state.get("security_strategy", {}),
        "deployment_strategy": state.get("deployment_strategy", {}),
        "test_strategy": state.get("test_strategy", {}),
    }

    messages = [SystemMessage(content=SYSTEM_INSTRUCTION)]
    messages.extend(state.get("messages", []))
    messages.append(
        HumanMessage(
            content=(
                f"Repository: {repo}\nBranch: {branch}\n\n"
                f"Specialized agent plans:\n{json.dumps(plans, indent=2)}\n\n"
                "Dispatch this exact repository and branch to Jenkins now. "
                "Call orchestrate_dynamic_jenkins_pipeline exactly once."
            )
        )
    )

    response = llm_with_tools.invoke(messages)
    calls = getattr(response, "tool_calls", None) or []

    if not any(
        call.get("name") == "orchestrate_dynamic_jenkins_pipeline"
        for call in calls
    ):
        failure = AIMessage(
            content=(
                "ERROR: Supervisor did not issue the required Jenkins tool call. "
                "No Jenkins pipeline was triggered."
            )
        )
        return {
            "messages": [failure],
            "active_phase": "Supervisor failed to dispatch Jenkins",
            "jenkins_triggered": False,
            "error_message": "Required tool call missing.",
        }

    return {
        "messages": [response],
        "active_phase": "Supervisor dispatched Jenkins",
        "jenkins_triggered": True,
        "error_message": "",
    }
