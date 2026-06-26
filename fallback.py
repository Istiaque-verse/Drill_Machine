"""Safe fallback JSON returned when Gemini fails or times out.

This is the deterministic safety net described in Step 6 of the master prompt.
The response shape matches AnalyzeOutput exactly, and human_review_required
is always True so a real agent picks up the ticket.
"""
from __future__ import annotations

from typing import Any


def build_fallback(ticket_id: str) -> dict[str, Any]:
    """Return the exact Step 6 fallback JSON, with ticket_id replaced."""
    return {
        "ticket_id": ticket_id,
        "relevant_transaction_id": None,
        "evidence_verdict": "insufficient_data",
        "case_type": "other",
        "severity": "medium",
        "department": "customer_support",
        "agent_summary": (
            "Unable to process ticket at this time. Manual review required."
        ),
        "recommended_next_action": (
            "Escalate to human agent for manual review."
        ),
        "customer_reply": (
            "Thank you for contacting us. Your case is being reviewed by our "
            "support team. Please do not share your PIN or OTP with anyone."
        ),
        "human_review_required": True,
        "confidence": 0.0,
        "reason_codes": ["processing_error", "fallback_response"],
    }