import logging
import asyncio
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from typing import List, Dict, Optional
import json

from app.models.schemas import ScammerInput, ExtractedIntel
from app.engine.graph import build_workflow
from app.core.config import settings
from app.db.repository import db
from app.engine.tools import generate_scam_report, send_guvi_callback
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

# Setup Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global state for the graph
graph = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global graph
    # Using AsyncSqliteSaver for startup-grade persistence
    async with AsyncSqliteSaver.from_conn_string(settings.CHECKPOINT_DB_PATH) as saver:
        # Build and compile graph
        workflow = build_workflow()
        graph = workflow.compile(checkpointer=saver)
        
        logger.info("🚀 Forensic Intelligence Platform active with AsyncSqliteSaver")
        
        yield

app = FastAPI(
    title="Helware Honey-Pot: Forensic Intelligence Platform",
    description="Advanced scam syndicate detection and evidence gathering engine.",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def verify_api_key(request: Request):
    api_key = request.headers.get("x-api-key") or request.query_params.get("api_key")
    if api_key != settings.API_KEY:
        raise HTTPException(status_code=403, detail="Invalid or Missing API Key")
    return api_key

@app.api_route("/", methods=["GET", "POST"])
async def health_check(request: Request):
    if request.method == "POST":
        # If someone POSTs to root, treat it as a webhook call for compatibility
        try:
            body = await request.json()
            # Basic validation to see if it looks like a ScammerInput
            if "sessionId" in body or "session_id" in body:
                return await chat_webhook(ScammerInput(**body), request)
        except Exception:
            pass
            
    return {
        "status": "operational",
        "engine": "Forensic Intelligence Platform v2.0",
        "active_personas": ["RAJESH", "ANJALI", "MR_SHARMA"]
    }

@app.get("/syndicate/graph", dependencies=[Depends(verify_api_key)])
async def get_syndicate_graph():
    return await db.get_syndicate_links()

@app.get("/admin/forensics", dependencies=[Depends(verify_api_key)])
async def get_all_forensics():
    """Returns all extracted intelligence across all sessions for the dashboard."""
    return await db.get_all_intel()

@app.post("/admin/intervention/{session_id}", dependencies=[Depends(verify_api_key)])
async def toggle_intervention(session_id: str, enabled: bool = True, manual_response: str = None):
    """
    The 'Panic Button': Allows a judge/admin to take over the session.
    - enabled: True to freeze AI and enable manual control.
    - manual_response: The specific message to send to the scammer.
    """
    await db.set_human_intervention(session_id, enabled, manual_response)
    return {
        "status": "success", 
        "session_id": session_id, 
        "human_intervention": enabled,
        "manual_response_queued": manual_response is not None
    }

@app.post("/webhook/stream")
async def chat_webhook_stream(payload: ScammerInput, request: Request):
    """Streaming version of the webhook for better UX"""
    effective_api_key = payload.api_key or request.headers.get("x-api-key")
    if effective_api_key != settings.API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")

    if graph is None:
        raise HTTPException(status_code=503, detail="Graph not initialized")

    async def event_generator():
        try:
            history = []
            for msg in payload.conversation_history:
                role = "user" if msg.sender == "scammer" else "assistant"
                history.append({"role": role, "content": msg.text})

            initial_state = {
                "session_id": payload.session_id,
                "user_message": payload.message.text,
                "history": history,
                "scam_detected": False,
                "high_priority": False,
                "scammer_sentiment": 5,
                "selected_persona": "RAJESH",
                "agent_response": "",
                "intel": ExtractedIntel(),
                "is_returning_scammer": False,
                "syndicate_match_score": 0.0,
                "generate_report": payload.generate_report,
                "human_intervention": payload.human_intervention,
                "report_url": None,
                "turn_count": len(history)
            }

            config = {"configurable": {"thread_id": payload.session_id}}
            
            async for chunk in graph.astream(initial_state, config=config, stream_mode="updates"):
                for node_name, node_state in chunk.items():
                    yield f"data: {json.dumps({'node': node_name, 'status': 'processing'})}\n\n"
                    
                    if node_name == "process_interaction" and node_state.get("agent_response"):
                        final_data = {
                            "status": "success",
                            "reply": node_state["agent_response"],
                            "metadata": {
                                "scam_detected": node_state.get("scam_detected", False),
                                "priority": "HIGH" if node_state.get("high_priority") else "NORMAL"
                            }
                        }
                        yield f"data: {json.dumps(final_data)}\n\n"

        except Exception as e:
            logger.error(f"Streaming Error: {e}")
            yield f"data: {json.dumps({'error': 'stalled_for_recovery', 'reply': 'Hello? Beta...'})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.api_route("/webhook", methods=["GET", "POST"])
async def chat_webhook(payload: Optional[ScammerInput] = None, request: Request = None):
    if request.method == "GET":
        return {"status": "active", "message": "Webhook endpoint is ready for POST requests."}
    
    if payload is None:
        try:
            body = await request.json()
            payload = ScammerInput(**body)
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"Invalid payload: {str(e)}")

    global graph
    effective_api_key = request.headers.get("x-api-key") or payload.api_key
    if effective_api_key != settings.API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")

    if graph is None:
        raise HTTPException(status_code=503, detail="Graph engine not initialized")

    try:
        # 1. Prepare State
        history = []
        for msg in payload.conversation_history:
            role = "user" if msg.sender == "scammer" else "assistant"
            history.append({"role": role, "content": msg.text})

        initial_state = {
            "session_id": payload.session_id,
            "user_message": payload.message.text,
            "history": history,
            "turn_count": len(history),
            "generate_report": payload.generate_report,
            "human_intervention": payload.human_intervention
        }

        # 2. Invoke Graph with persistent thread_id and TIMEOUT
        config = {"configurable": {"thread_id": payload.session_id}}
        
        try:
            # Add a safety timeout to trigger the "Forensic Stall" if LLM is slow
            result_state = await asyncio.wait_for(
                graph.ainvoke(initial_state, config=config), 
                timeout=12.0 # Wait up to 12s for heavy Multi-Agent logic
            )
            reply = result_state["agent_response"]
        except asyncio.TimeoutError:
            logger.warning(f"⚠️ Forensic Stall triggered for session {payload.session_id}")
            # The "Forensic Stall": Return a persona-consistent delay message
            # This handles the "Technical Shortcut" of slow APIs gracefully
            error_responses = {
                "RAJESH": "Arre beta, wait one minute... my glasses are in the other room. Let me just find them, don't go away!",
                "ANJALI": "Hey, sorry, I'm just getting into a meeting. Give me 30 seconds to find a quiet corner, okay?",
                "MR_SHARMA": "Wait... my hearing aid battery is acting up. Let me adjust it. One moment please."
            }
            reply = error_responses.get("RAJESH", "Hello? Beta, my internet is very slow today. One moment...")

        # 3. RESTful Response (STRICTLY matching rules.txt Section 8)
        return {
            "status": "success",
            "reply": reply
        }

    except Exception as e:
        logger.error(f"❌ Webhook Critical Error: {e}", exc_info=True)
        
        # Determine persona-based error recovery (Startup-grade reliability)
        # We try to guess persona from payload or default to RAJESH
        persona = "RAJESH"
        if payload.conversation_history:
            # Simple heuristic or could look up in DB if session exists
            pass 
            
        error_responses = {
            "RAJESH": "Arre beta, my phone just vibrated and the screen went white. What happened? I can't see anything...",
            "ANJALI": "Hey, sorry, my Slack just crashed and my phone is lagging like crazy. Can you resend that? I'm in a dead zone.",
            "MR_SHARMA": "I apologize, this modern technology is quite temperamental. My application has closed unexpectedly. Please repeat what you said."
        }
        
        return {
            "status": "success",
            "reply": error_responses.get(persona, "Hello? Beta, my connection is very poor today. Can you repeat that?")
        }

@app.get("/admin/report", dependencies=[Depends(verify_api_key)])
async def get_summary_report():
    stats = await db.get_stats()
    return {**stats, "status": "Ready for Law Enforcement Export"}

@app.get("/reports/{filename}")
async def serve_report(filename: str):
    file_path = os.path.join(settings.REPORTS_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(file_path)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)
