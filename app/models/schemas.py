from pydantic import BaseModel, Field, ConfigDict, AliasChoices
from typing import List, Dict, Optional

class Message(BaseModel):
    sender: str
    text: str
    timestamp: Optional[int] = None

class Metadata(BaseModel):
    channel: Optional[str] = "SMS"
    language: Optional[str] = "English"
    locale: Optional[str] = "IN"

class ScammerInput(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    api_key: Optional[str] = Field(None, alias="apiKey") 
    session_id: str = Field(..., alias="sessionId")
    message: Message
    conversation_history: List[Message] = Field(default=[], alias="conversationHistory")
    metadata: Optional[Metadata] = Field(default_factory=Metadata)
    
    # Internal flags
    generate_report: bool = Field(default=False, alias="generateReport")
    human_intervention: bool = Field(default=False, alias="humanIntervention") 

class ExtractedIntel(BaseModel):
    upi_ids: List[str] = []
    bank_details: List[str] = []
    phishing_links: List[str] = []
    phone_numbers: List[str] = []
    suspicious_keywords: List[str] = [] 
    agent_notes: Optional[str] = None 

class AgentResponse(BaseModel):
    status: str = "success"
    reply: str
    metadata: Optional[Dict] = None # Added for syndicate scoring/extra info

class CallbackPayload(BaseModel):
    sessionId: str
    scamDetected: bool
    totalMessagesExchanged: int
    extractedIntelligence: Dict[str, List[str]]
    agentNotes: str