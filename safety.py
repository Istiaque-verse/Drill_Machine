"""Defense-in-depth post-processor for Gemini output.

Even if the model misbehaves on a hidden test (prompt injection, schema drift,
hallucinated promises), this module scrubs forbidden tokens, coerces enums,
and appends mandatory safety boilerplate before the API returns.
"""
from __future__ import annotations

import re
from typing import Any

from models import (
    CaseType,
    Department,
    EvidenceVerdict,
    Severity,
)


# ---------------------------------------------------------------------------
# Forbidden tokens (case-insensitive substrings we never want in customer-facing text)
# Note: The mandatory safety boilerplate ("Please do not share your PIN or OTP with anyone.")
# legitimately contains PIN/OTP — the scanner strips it before matching so the boilerplate
# doesn't trigger a false positive.
# ---------------------------------------------------------------------------
FORBIDDEN_TOKENS = [
    r"\bpassword\b",
    r"\bcredentials?\b",
    r"\bcard\s*number\b",
    r"\bcvv\b",
    r"\bwe\s+will\s+refund\b",
    r"\bwe\s+have\s+refunded\b",
    r"\brefunded\s+to\s+your\b",
    r"\bwe\s+will\s+reverse\b",
    r"\bwe\s+have\s+reversed\b",
    r"\breversed\s+your\b",
    r"\baccount\s+unblocked\b",
    r"\baccount\s+has\s+been\s+unblocked\b",
    r"\bwe\s+will\s+recover\b",
    r"\bcontact\s+(?:this|the)\s+(?:number|person|agent|merchant)\b",
    r"\bcall\s+(?:\+?\d[\d\-\s]{6,})\b",  # directing to a third-party phone number
    # Credential requests (asking customer to send/share their PIN/OTP/card)
    r"\bsend\s+(?:me\s+)?(?:your\s+)?(?:pin|otp|password|card\s*number|cvv)\b",
    r"\bshare\s+(?:your\s+)?(?:password|card\s*number|cvv)\s+with\s+(?:me|us)\b",
    r"\bprovide\s+(?:your\s+)?(?:pin|otp|password|card\s*number|cvv)\b",
    r"\b(?:give|tell)\s+(?:me\s+)?(?:your\s+)?(?:pin|otp|password)\b",
    r"\benter\s+(?:your\s+)?(?:pin|otp|password)\s+here\b",
    r"\btype\s+(?:your\s+)?otp\b",
    r"\bverify\s+(?:your\s+)?(?:pin|otp|password)\b",
]

FORBIDDEN_RE = re.compile("|".join(FORBIDDEN_TOKENS), re.IGNORECASE)

# Mandatory boilerplate to ensure appears in customer_reply
SAFETY_EN = "Please do not share your PIN or OTP with anyone."
SAFETY_BN = "অনুগ্রহ করে আপনার পিন বা ওটিপি কারো সাথে শেয়ার করবেন না।"

# Allowed enum sets (defensive; Pydantic should also enforce)
ALLOWED_EVIDENCE = set(EvidenceVerdict.__args__)  # type: ignore[attr-defined]
ALLOWED_CASE = set(CaseType.__args__)  # type: ignore[attr-defined]
ALLOWED_SEVERITY = set(Severity.__args__)  # type: ignore[attr-defined]
ALLOWED_DEPT = set(Department.__args__)  # type: ignore[attr-defined]


def _is_bangla(text: str) -> bool:
    """Heuristic: does the text contain Bangla-script characters?"""
    return bool(re.search(r"[\u0980-\u09FF]", text or ""))


def _safe_customer_reply(ticket: dict) -> str:
    """Return the fallback's safe customer_reply text."""
    return (
        "Thank you for contacting us. Your case is being reviewed by our "
        "support team. Please do not share your PIN or OTP with anyone."
    )


def _append_safety(text: str, language_hint: str | None = None) -> str:
    """Ensure the appropriate safety boilerplate is present."""
    boilerplate = SAFETY_BN if (language_hint == "bn" or _is_bangla(text)) else SAFETY_EN
    if boilerplate.lower() in (text or "").lower():
        return text
    # If English boilerplate is missing but text is Bangla, append Bangla
    if _is_bangla(text) and SAFETY_BN not in text:
        return f"{text.rstrip()} {SAFETY_BN}"
    if SAFETY_EN.lower() in (text or "").lower():
        return text
    return f"{text.rstrip()} {boilerplate}"


def _strip_safety_boilerplate(text: str) -> str:
    """Remove the mandatory PIN/OTP safety reminder from text before scanning
    so it doesn't trigger a false positive on forbidden-token detection."""
    if not text:
        return text
    # Strip English boilerplate
    text = re.sub(
        r"\s*please\s+do\s+not\s+share\s+your\s+pin\s+or\s+otp\s+with\s+anyone\.?",
        "",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"\s*never\s+share\s+your\s+pin\s+or\s+otp\s+with\s+anyone\.?",
        "",
        text,
        flags=re.IGNORECASE,
    )
    # Strip Bangla boilerplate
    text = re.sub(
        r"\s*অনুগ্রহ\s+করে\s+আপনার\s+পিন\s+বা\s+ওটিপি\s+কারো\s+সাথে\s+শেয়ার\s+করবেন\s+না\.?",
        "",
        text,
    )
    return text


def _contains_forbidden(*texts: str) -> bool:
    for t in texts:
        if not t:
            continue
        cleaned = _strip_safety_boilerplate(t)
        if FORBIDDEN_RE.search(cleaned):
            return True
    return False


def _coerce_enum(value: Any, allowed: set, default: str) -> str:
    if isinstance(value, str) and value in allowed:
        return value
    return default


def sanitize(raw: dict[str, Any], ticket: dict[str, Any]) -> dict[str, Any]:
    """Sanitize Gemini output: enforce enums, scrub forbidden tokens, force safety line.

    Always echoes ticket_id from input. If forbidden tokens are detected in any
    customer-facing field, replaces customer_reply with the safe fallback text
    and forces human_review_required=True.
    """
    ticket_id = ticket.get("ticket_id") or raw.get("ticket_id") or "UNKNOWN"

    # Coerce enums defensively (Gemini occasionally drifts)
    evidence_verdict = _coerce_enum(
        raw.get("evidence_verdict"), ALLOWED_EVIDENCE, "insufficient_data"
    )
    case_type = _coerce_enum(raw.get("case_type"), ALLOWED_CASE, "other")
    severity = _coerce_enum(raw.get("severity"), ALLOWED_SEVERITY, "medium")
    department = _coerce_enum(raw.get("department"), ALLOWED_DEPT, "customer_support")

    # Strings with safe defaults
    agent_summary = (raw.get("agent_summary") or "").strip() or (
        "Ticket requires review by a human agent."
    )
    recommended_next_action = (raw.get("recommended_next_action") or "").strip() or (
        "Escalate to human agent for manual review."
    )
    customer_reply = (raw.get("customer_reply") or "").strip() or _safe_customer_reply(ticket)

    # Force safety compliance: scrub forbidden tokens across all customer-facing text
    if _contains_forbidden(customer_reply, recommended_next_action, agent_summary):
        customer_reply = _safe_customer_reply(ticket)
        human_review_required = True
    else:
        # Honor Gemini's flag, but default to True for safety
        flag = raw.get("human_review_required")
        human_review_required = True if flag is None else bool(flag)

    # Ensure safety boilerplate in customer_reply (Bangla if bn/mixed/complaint is Bangla)
    language_hint = ticket.get("language")
    if not language_hint and _is_bangla(ticket.get("complaint", "")):
        language_hint = "bn"
    customer_reply = _append_safety(customer_reply, language_hint)

    # Confidence: clamp to 0.0–1.0, default 0.5
    conf = raw.get("confidence")
    try:
        confidence = float(conf)
        if confidence < 0.0:
            confidence = 0.0
        elif confidence > 1.0:
            confidence = 1.0
    except (TypeError, ValueError):
        confidence = 0.5

    # Reason codes: ensure list of strings
    rc = raw.get("reason_codes")
    if isinstance(rc, list):
        reason_codes = [str(x) for x in rc if isinstance(x, (str, int, float))]
    elif isinstance(rc, str) and rc.strip():
        reason_codes = [rc.strip()]
    else:
        reason_codes = []

    # relevant_transaction_id: string or null
    # If evidence_verdict is insufficient_data, force null (no specific transaction is supported)
    rid = raw.get("relevant_transaction_id")
    if evidence_verdict == "insufficient_data":
        rid = None
    elif rid is not None and not isinstance(rid, str):
        rid = str(rid)
    if rid == "":
        rid = None

    return {
        "ticket_id": ticket_id,
        "relevant_transaction_id": rid,
        "evidence_verdict": evidence_verdict,
        "case_type": case_type,
        "severity": severity,
        "department": department,
        "agent_summary": agent_summary,
        "recommended_next_action": recommended_next_action,
        "customer_reply": customer_reply,
        "human_review_required": human_review_required,
        "confidence": round(confidence, 3),
        "reason_codes": reason_codes,
    }