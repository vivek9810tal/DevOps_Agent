"""graph.py - Multi-agent planning graph + post-execution policy graph."""
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import ToolNode, tools_condition

from agents import jenkins_supervisor_agent, jenkins_tools
from specialized_agents import (
    build_strategy_agent,
    container_deployment_agent,
    policy_release_agent,
    repository_analysis_agent,
    security_strategy_agent,
    test_strategy_agent,
)
from state import CICDState


def build_execution_graph():
    graph = StateGraph(CICDState)

    graph.add_node("Repository_Analysis_Agent", repository_analysis_agent)
    graph.add_node("Build_Strategy_Agent", build_strategy_agent)
    graph.add_node("Security_Strategy_Agent", security_strategy_agent)
    graph.add_node("Container_Deployment_Agent", container_deployment_agent)
    graph.add_node("Test_Strategy_Agent", test_strategy_agent)
    graph.add_node("Supervisor_Agent", jenkins_supervisor_agent)
    graph.add_node("MCP_Tool_Executor", ToolNode(jenkins_tools))

    graph.add_edge(START, "Repository_Analysis_Agent")
    graph.add_edge("Repository_Analysis_Agent", "Build_Strategy_Agent")
    graph.add_edge("Build_Strategy_Agent", "Security_Strategy_Agent")
    graph.add_edge("Security_Strategy_Agent", "Container_Deployment_Agent")
    graph.add_edge("Container_Deployment_Agent", "Test_Strategy_Agent")
    graph.add_edge("Test_Strategy_Agent", "Supervisor_Agent")

    graph.add_conditional_edges(
        "Supervisor_Agent",
        tools_condition,
        {"tools": "MCP_Tool_Executor", END: END},
    )
    graph.add_edge("MCP_Tool_Executor", END)

    return graph.compile()


def build_policy_graph():
    graph = StateGraph(CICDState)
    graph.add_node("Policy_Release_Agent", policy_release_agent)
    graph.add_edge(START, "Policy_Release_Agent")
    graph.add_edge("Policy_Release_Agent", END)
    return graph.compile()


agentic_pipeline = build_execution_graph()
policy_pipeline = build_policy_graph()
