from langgraph.graph import StateGraph, END
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from app.engine.nodes import (
    AgentState, load_history, detect_scam, 
    extract_intel, save_state, finalize_report,
    enrich_intel, fingerprint_scammer, submit_to_blacklist,
    guvi_reporting
)

def route_after_detection(state: AgentState):
    """
    Dynamic routing for True Agency:
    - If High Priority Intel detected: Skip small talk, go straight to enrichment.
    - If Scam detected: Go to forensics.
    - Otherwise: Persist state and wait for next message.
    """
    if state.get("high_priority"):
        return "enrich_intelligence"
    if state.get("scam_detected"):
        return "extract_forensics"
    return "persist_state"

def build_workflow():
    workflow = StateGraph(AgentState)

    workflow.add_node("load_history", load_history)
    workflow.add_node("process_interaction", detect_scam)
    workflow.add_node("extract_forensics", extract_intel)
    workflow.add_node("enrich_intelligence", enrich_intel)
    workflow.add_node("fingerprint_scammer", fingerprint_scammer)
    workflow.add_node("submit_to_blacklist", submit_to_blacklist)
    workflow.add_node("generate_takedown_report", finalize_report)
    workflow.add_node("persist_state", save_state)
    workflow.add_node("guvi_reporting", guvi_reporting)

    workflow.set_entry_point("load_history")
    
    workflow.add_edge("load_history", "process_interaction")
    
    # Conditional Edge: Decide path based on detection
    workflow.add_conditional_edges(
        "process_interaction",
        route_after_detection,
        {
            "extract_forensics": "extract_forensics",
            "enrich_intelligence": "enrich_intelligence",
            "persist_state": "persist_state"
        }
    )
    
    workflow.add_edge("extract_forensics", "enrich_intelligence")
    workflow.add_edge("enrich_intelligence", "fingerprint_scammer")
    workflow.add_edge("fingerprint_scammer", "submit_to_blacklist")
    workflow.add_edge("submit_to_blacklist", "generate_takedown_report")
    workflow.add_edge("generate_takedown_report", "persist_state")
    workflow.add_edge("persist_state", "guvi_reporting")
    workflow.add_edge("guvi_reporting", END)

    return workflow