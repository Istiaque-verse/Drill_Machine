"""Pydantic schemas for QueueStorm Investigator API.

Input: customer ticket + transaction history.
Output: structured AI-copilot decision with all required fields and enums.
"""
from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# INPUT ENUMS
# ---------------------------------------------------------------------------
Language = Literal["en", "bn", "mixed"]
Channel = Literal[
    "in_app_chat", "call_center", "email", "merchant_portal", "field_agent"
]
UserType = Literal["customer", "merchant", "agent", "unknown"]
TxnType = Literal[
    "transfer", "payment", "cash_in", "cash_out", "settlement", "refund"
]
TxnStatus = Literal["completed", "failed", "pending", "reversed"]


# ---------------------------------------------------------------------------
# OUTPUT ENUMS
# ---------------------------------------------------------------------------
EvidenceVerdict = Literal["consistent", "inconsistent", "insufficient_data"]
CaseType = Literal[
    "wrong_transfer",
    "payment_failed",
    "refund_request",
    "duplicate_payment",
    "merchant_settlement_delay",
    "agent_cash_in_issue",
    "phishing_or_social_engineering",
    "other",
]
Severity = Literal["low", "medium", "high", "critical"]
Department = Literal[
    "customer_support",
    "dispute_resolution",
    "payments_ops",
    "merchant_operations",
    "agent_operations",
    "fraud_risk",
]


# ---------------------------------------------------------------------------
# INPUT MODEL
# ---------------------------------------------------------------------------
class Transaction(BaseModel):
    transaction_id: Optional[str] = None
    timestamp: Optional[str] = None
    type: Optional[TxnType] = None
    amount: Optional[float] = None
    counterparty: Optional[str] = None
    status: Optional[TxnStatus] = None


class TicketInput(BaseModel):
    ticket_id: str = Field(..., min_length=1)
    complaint: str = Field(..., min_length=1)
    language: Optional[Language] = None
    channel: Optional[Channel] = None
    user_type: Optional[UserType] = None
    campaign_context: Optional[str] = None
    transaction_history: Optional[List[Transaction]] = None
    metadata: Optional[dict] = None

    @field_validator("complaint")
    @classmethod
    def complaint_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("complaint must be non-empty")
        return v


# ---------------------------------------------------------------------------
# OUTPUT MODEL
# ---------------------------------------------------------------------------
class AnalyzeOutput(BaseModel):
    ticket_id: str
    relevant_transaction_id: Optional[str] = None
    evidence_verdict: EvidenceVerdict
    case_type: CaseType
    severity: Severity
    department: Department
    agent_summary: str
    recommended_next_action: str
    customer_reply: str
    human_review_required: bool
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    reason_codes: Optional[List[str]] = None