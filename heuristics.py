"""Lightweight rule-based heuristics for common ticket patterns.

This is a deterministic safety net that runs BEFORE the Gemini call.
If a pattern is matched with high confidence, we use the rule-based
decision and skip Gemini (saves quota, faster, deterministic). If no
high-confidence pattern matches, we let Gemini handle it.

This is NOT a replacement for Gemini — it's an optimization + safety
backstop. Hidden tests with novel patterns still go to Gemini.
"""
from __future__ import annotations

import re
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Keyword patterns (lowercase)
# ---------------------------------------------------------------------------
PHISHING_PATTERNS = [
    r"\botp\b",
    r"\basked?\s+(?:me\s+)?for\s+(?:my\s+)?otp",
    r"\bcalled\s+(?:me\s+)?(?:from\s+)?bkash",
    r"\bsms.*(?:otp|pin|password)\b",
    r"\baccount\s+(?:will|would)\s+be\s+blocked\b",
    r"\bscam\b",
    r"\bphishing\b",
    r"\bfraud(?:ster)?\b",
]

WRONG_TRANSFER_PATTERNS = [
    r"\bwrong\s+(?:number|recipient|person|account)\b",
    r"\bsent\s+(?:money\s+)?to\s+(?:the\s+)?wrong\b",
    r"\btyped\s+(?:the\s+)?wrong\b",
    r"\baccidentally\s+sent\b",
    r"\bmistaken(?:ly)?\s+sent\b",
    r"\bsent\s+to\s+wrong\b",
    # Bangla
    r"ভুল\s+নম্বর",
    r"ভুল\s+(?:ব্যক্তি|মানুষ|অ্যাকাউন্ট)",
    r"\bভুল\b.*\b(?:পাঠাই|পাঠিয়ে|পাঠিয়েছি|পাঠাইছি)\b",
    # Banglish (romanized Bangla)
    r"\bbhul\s+(?:number|person|manush|account)\b",
    r"\bbhul\s+e\s+pathi(?:ye|iye|i)\b",
    r"\bpathiye\s+diyechi\b",
    r"\bpathiye\s+diyesi\b",
    # Money gone / missing transfer language
    r"\bmy\s+money\s+gone\b",
    r"\bmoney\s+(?:is\s+)?gone\b",
    r"\bnot\s+(?:received|reflected)\b.*\b(?:brother|sister|friend|family|recipient|person)\b",
]

PAYMENT_FAILED_PATTERNS = [
    r"\bpayment\s+failed\b",
    r"\bfailed\s+but\s+(?:my\s+)?balance\b",
    r"\bbalance\s+(?:was\s+)?deducted\b",
    r"\bdeducted\s+but\b",
    r"\bshowed?\s+failed\b",
]

DUPLICATE_PATTERNS = [
    r"\bdeducted\s+twice\b",
    r"\bcharged\s+twice\b",
    r"\btwice\s+from\s+my\s+account\b",
    r"\bduplicate\s+(?:payment|charge|deduction)\b",
    r"\btwo\s+transactions?\b.*\bsame\s+amount\b",
    r"\b(?:paid|charged|deducted)\s+(?:me\s+)?(?:two|2|twice)\b",
    r"\b(?:paid|charged|deducted)\s+.*\b(?:twice|two\s+times)\b",
    r"\b(?:same\s+bill|same\s+amount).*(?:twice|two|deducted|charged)\b",
    # Bangla
    r"দুইবার\s+(?:কাটা|চার্জ|কেটে|কেটেছে)",
    # Banglish
    r"\bdoobar\s+(?:kate|kete|cut)\b",
    r"\b(?:do|dui)\s+bar\b.*\b(?:kete|cut|kate)\b",
]

MERCHANT_SETTLEMENT_PATTERNS = [
    r"\bsettlement\b.*\bnot\s+(?:received|settled|reflected)\b",
    r"\bnot\s+settled\b",
    r"\bmerchant\b.*\bnot\s+(?:received|settled|reflected)\b",
    r"\bsales\b.*\bnot\s+(?:received|settled|reflected)\b",
]

AGENT_CASH_IN_PATTERNS = [
    r"\bcash\s*[- ]?in\b",
    r"\bagent\b.*\bcash\b",
    r"\bcash\b.*\bagent\b",
    r"\bbalance\b.*\bnot\s+(?:received|reflected|credited|come|added|updated)\b",
    r"\bnot\s+(?:received|reflected|credited|come|added)\s+.*\bbalance\b",
    # Bangla patterns
    r"ক্যাশ\s*ইন",
    r"এজেন্ট",
    r"ব্যালেন্স",
    r"আসেনি",
    r"টাকা\s+আসেনি",
    r"জমা\s+হয়নি",
]

REFUND_PATTERNS = [
    r"\brefund\b",
    r"\bmoney\s+back\b",
    r"\bchanged?\s+my\s+mind\b",
    r"\bdon'?t\s+want\s+it\s+(?:any\s*more)?\b",
]

AMBIGUOUS_DISPUTE_PATTERNS = [
    # Customer says recipient didn't receive money AND there are multiple same-amount transfers
    r"\b(?:he|she|they)\s+(?:says?|said)\s+(?:he|she|they)?\s*(?:didn'?t|don'?t|did\s+not|doesn'?t|does\s+not)\s+(?:get|receive)\b",
    r"\b(?:didn'?t|don'?t|did\s+not)\s+(?:get|receive)\s+(?:it|the\s+money|the\s+amount)\b",
    r"\bbut\s+(?:he|she|they)\s+received\s+nothing\b",
    r"\bnot\s+received\b",
    r"\brecipient\s+denies?\b",
]

VAGUE_PATTERNS = [
    r"^something\s+is\s+wrong\b",
    r"^\s*help\s*me\s*\.?\s*$",
    r"^\s*check\s+(?:my\s+)?(?:account|balance)\s*\.?\s*$",
    r"^problem\s+with\s+my\s+account\s*\.?\s*$",
]


def _has_any(text: str, patterns: list[str]) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


# ---------------------------------------------------------------------------
# Bengali digit normalization
# ---------------------------------------------------------------------------
BENGALI_DIGITS = "০১২৩৪৫৬৭৮৯"
_BENGALI_TO_ASCII = str.maketrans(BENGALI_DIGITS, "0123456789")


def _normalize_digits(text: str) -> str:
    """Convert Bengali/Arabic-Indic digits to ASCII for regex matching."""
    return text.translate(_BENGALI_TO_ASCII)


def _extract_amounts(complaint: str) -> list[float]:
    """Extract numeric amounts from complaint, supporting Bengali digits."""
    normalized = _normalize_digits(complaint)
    amounts: list[float] = []
    for raw in re.findall(r"\b(\d{2,7})\s*(?:taka|tk|bdt)?\b", normalized):
        try:
            amounts.append(float(raw))
        except ValueError:
            pass
    return amounts


def _is_phone_shaped(s: Any) -> bool:
    """True if the string looks like a phone number (+880..., 01..., etc.)."""
    if not isinstance(s, str):
        return False
    s = s.strip()
    # +8801712345678, 8801712345678, 01712345678, +1-555-...
    if re.match(r"^\+?\d{1,3}[\s\-]?\d{3,4}[\s\-]?\d{3,4}[\s\-]?\d{0,4}$", s):
        return True
    return False


def _is_merchant_or_agent_counterparty(s: Any) -> bool:
    """True if counterparty looks like a merchant ID or agent ID (not a person)."""
    if not isinstance(s, str):
        return False
    s_upper = s.strip().upper()
    return any(prefix in s_upper for prefix in ("MERCHANT", "AGENT", "BILLER", "BANK"))


# ---------------------------------------------------------------------------
# Complaint semantic classifier
# ---------------------------------------------------------------------------
_PERSON_TRANSFER_SEMANTIC_PATTERNS = [
    r"\bwrong\s+(?:number|recipient|person|account)\b",
    r"\bsent\s+(?:money\s+)?to\s+(?:the\s+)?wrong\b",
    r"\bsent\s+to\s+wrong\b",
    r"\btypo\s+(?:in\s+)?(?:the\s+)?number\b",
    r"\btyped\s+(?:the\s+)?wrong\b",
    r"\baccidentally\s+sent\b",
    r"\bmistaken(?:ly)?\s+sent\b",
    r"\bmy\s+(?:brother|sister|friend|family|father|mother|wife|husband)\s+(?:says?|said)\s+(?:he|she|they)?\s*(?:didn'?t|don'?t|did\s+not)\s+(?:get|receive)\b",
    r"\bhe\s+(?:says?|said)\s+(?:he\s+)?didn'?t\s+(?:get|receive)\b",
    # Bangla
    r"ভুল\s+নম্বর",
    r"ভুল\s+(?:ব্যক্তি|মানুষ)",
    r"পাঠিয়েছি",
    r"পাঠাইছি",
]

_PAYMENT_SEMANTIC_PATTERNS = [
    r"\b(?:payment|pay|bill|recharge|biller)\b",
    r"\bmerchant\b",
    r"\belectricity\s+bill\b",
    r"\bgas\s+bill\b",
    r"\bwater\s+bill\b",
    r"\bmobile\s+recharge\b",
    r"\btop[\s\-]?up\b",
]

_CASH_IN_SEMANTIC_PATTERNS = [
    r"\bcash\s*[- ]?in\b",
    r"\bcash\s+deposit\b",
    r"\bdeposit\s+(?:via|through)\s+agent\b",
    # Bangla
    r"ক্যাশ\s*ইন",
    r"এজেন্ট",
    r"জমা",
]

_SETTLEMENT_SEMANTIC_PATTERNS = [
    r"\bsettlement\b",
    r"\bmerchant\s+sales?\b",
    r"\bsettled\s+to\s+my\s+account\b",
]


def _classify_complaint_semantic(complaint: str) -> str:
    """Classify what KIND of transaction the complaint implies.

    Returns one of: "person_transfer", "payment", "cash_in", "settlement", "neutral".
    Used by the transaction ranker to score type matches/mismatches.
    """
    if _has_any(complaint, _PERSON_TRANSFER_SEMANTIC_PATTERNS):
        return "person_transfer"
    if _has_any(complaint, _CASH_IN_SEMANTIC_PATTERNS):
        return "cash_in"
    if _has_any(complaint, _SETTLEMENT_SEMANTIC_PATTERNS):
        return "settlement"
    if _has_any(complaint, _PAYMENT_SEMANTIC_PATTERNS):
        return "payment"
    return "neutral"


# ---------------------------------------------------------------------------
# Scoring-based transaction ranking
# ---------------------------------------------------------------------------
# Weights for each signal. Tuned conservatively — type semantics dominate.
_TYPE_MATCH_WEIGHT = 4.0       # Strong positive: txn type matches complaint semantic
_TYPE_MISMATCH_PENALTY = -5.0  # Strong negative: txn type conflicts with complaint semantic
_AMOUNT_MATCH_WEIGHT = 3.0     # Strong positive: amount in complaint matches txn amount
_TYPE_KEYWORD_WEIGHT = 2.0     # Medium: complaint text contains the txn-type keyword
_COUNTERPARTY_MATCH_WEIGHT = 2.0   # Phone-shaped counterparty for person semantic
_COUNTERPARTY_MISMATCH_PENALTY = -3.0  # Merchant counterparty for person semantic
_FAILED_STATUS_BONUS = 1.0     # status=failed when complaint mentions failure
_PENDING_STATUS_BONUS = 0.5    # status=pending when complaint mentions "not received"
_RECENT_TIEBREAKER = 0.3       # Most recent transaction gets a small boost

# Threshold below which a transaction is considered an uncertain match
_MIN_ACCEPT_SCORE = 3.0
# If top two scores are within this delta, treat as ambiguous
_AMBIGUITY_DELTA = 1.0


def _score_transaction(
    txn: dict[str, Any],
    complaint: str,
    complaint_semantic: str,
    complaint_amounts: list[float],
    complaint_lower: str,
) -> tuple[float, list[str]]:
    """Compute a score for one transaction against the complaint.

    Returns (score, reasons) where `reasons` is a list of human-readable
    signals that contributed (useful for debugging and the agent_summary).
    """
    score = 0.0
    reasons: list[str] = []

    txn_type = (txn.get("type") or "").lower()
    txn_amount = txn.get("amount")
    txn_status = (txn.get("status") or "").lower()
    txn_counterparty = txn.get("counterparty")

    # ---- Type semantics ----
    expected_types: dict[str, set[str]] = {
        "person_transfer": {"transfer"},
        "payment": {"payment"},
        "cash_in": {"cash_in"},
        "settlement": {"settlement"},
        "neutral": set(),  # no preference
    }
    expected = expected_types.get(complaint_semantic, set())
    if expected:
        if txn_type in expected:
            score += _TYPE_MATCH_WEIGHT
            reasons.append(f"type={txn_type}_matches_{complaint_semantic}")
        else:
            score += _TYPE_MISMATCH_PENALTY
            reasons.append(f"type={txn_type}_conflicts_with_{complaint_semantic}")

    # ---- Amount match ----
    if complaint_amounts and txn_amount is not None:
        try:
            if float(txn_amount) in complaint_amounts:
                score += _AMOUNT_MATCH_WEIGHT
                reasons.append(f"amount_match={txn_amount}")
        except (TypeError, ValueError):
            pass

    # ---- Type keyword in complaint text ----
    type_keyword_map = {
        "transfer": [r"\btransfer(?:red|ring)?\b", r"\bsent\b", r"\bsend\b"],
        "payment": [r"\bpay(?:ment|ing)?\b", r"\bbill\b", r"\brecharge\b"],
        "cash_in": [r"\bcash\s*[- ]?in\b", r"\bdeposit\b"],
        "settlement": [r"\bsettlement\b"],
        "refund": [r"\brefund\b"],
    }
    if txn_type in type_keyword_map:
        if _has_any(complaint_lower, type_keyword_map[txn_type]):
            score += _TYPE_KEYWORD_WEIGHT
            reasons.append(f"complaint_mentions_{txn_type}")

    # ---- Counterparty shape vs semantic ----
    if complaint_semantic == "person_transfer":
        if _is_phone_shaped(txn_counterparty):
            score += _COUNTERPARTY_MATCH_WEIGHT
            reasons.append("phone_counterparty")
        elif _is_merchant_or_agent_counterparty(txn_counterparty):
            score += _COUNTERPARTY_MISMATCH_PENALTY
            reasons.append("merchant_counterparty_for_person_complaint")
    elif complaint_semantic in ("payment", "settlement"):
        if _is_merchant_or_agent_counterparty(txn_counterparty):
            score += _COUNTERPARTY_MATCH_WEIGHT
            reasons.append("merchant_counterparty_for_payment")
    elif complaint_semantic == "cash_in":
        if _is_merchant_or_agent_counterparty(txn_counterparty):
            score += _COUNTERPARTY_MATCH_WEIGHT
            reasons.append("agent_counterparty_for_cash_in")

    # ---- Status hints ----
    if txn_status == "failed" and re.search(r"\b(?:failed|deducted|but)\b", complaint_lower):
        score += _FAILED_STATUS_BONUS
        reasons.append("status_failed_matches_complaint")
    if txn_status == "pending" and re.search(
        r"\b(?:not\s+(?:received|reflected|credited|come|added|updated)|আসেনি)\b",
        complaint_lower,
    ):
        score += _PENDING_STATUS_BONUS
        reasons.append("status_pending_matches_complaint")

    return score, reasons


def _rank_transactions(
    complaint: str, history: list[dict[str, Any]]
) -> tuple[Optional[dict[str, Any]], float, list[tuple[dict[str, Any], float, list[str]]]]:
    """Rank all transactions in history by relevance to the complaint.

    Returns:
        best_txn: The top-ranked transaction, or None if no confident match.
        best_score: The top score (0.0 if no match).
        all_ranked: Full ranking list (txn, score, reasons) for debugging/audit.

    Selection rules:
        - Empty history  -> (None, 0.0, [])
        - Top score < _MIN_ACCEPT_SCORE -> (None, top_score, all_ranked)
        - Top two within _AMBIGUITY_DELTA -> (None, top_score, all_ranked) [ambiguous]
        - Otherwise -> (top_txn, top_score, all_ranked)
    """
    if not history:
        return None, 0.0, []

    complaint_lower = complaint.lower()
    complaint_semantic = _classify_complaint_semantic(complaint)
    complaint_amounts = _extract_amounts(complaint)

    scored: list[tuple[dict[str, Any], float, list[str]]] = []
    for idx, txn in enumerate(history):
        s, reasons = _score_transaction(
            txn, complaint, complaint_semantic, complaint_amounts, complaint_lower
        )
        # Recency tiebreaker: more recent (lower index in array = more recent) gets a tiny boost
        # so if scores tie, the most recent wins on tiebreak but doesn't override signal.
        s += _RECENT_TIEBREAKER * (1.0 / (idx + 1))
        scored.append((txn, s, reasons))

    # Sort by score descending
    scored.sort(key=lambda x: x[1], reverse=True)

    if not scored:
        return None, 0.0, []

    best_txn, best_score, _ = scored[0]

    # Insufficient evidence
    if best_score < _MIN_ACCEPT_SCORE:
        return None, best_score, scored

    # Ambiguous: top two are nearly tied
    if len(scored) >= 2:
        second_score = scored[1][1]
        if (best_score - second_score) < _AMBIGUITY_DELTA:
            # True tie — return None, let the caller escalate to human
            return None, best_score, scored

    return best_txn, best_score, scored


# Backwards-compatible alias used by some branches
def _find_matching_transaction(
    complaint: str, history: list[dict[str, Any]]
) -> Optional[dict[str, Any]]:
    """Thin wrapper around _rank_transactions for backwards compatibility.

    Returns the top-ranked transaction, or None if no confident match.
    Use _rank_transactions directly if you need the score or full ranking.
    """
    best, _, _ = _rank_transactions(complaint, history)
    return best


def rule_based_analyze(ticket: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Try to handle the ticket with pure rules. Return None if no high-confidence match.

    Only returns a dict when we're confident enough to skip Gemini.
    """
    ticket_id = ticket.get("ticket_id", "UNKNOWN")
    complaint = (ticket.get("complaint") or "").strip()
    language = ticket.get("language")
    history = ticket.get("transaction_history") or []
    user_type = ticket.get("user_type")

    # ---- Phishing (highest priority — safety critical) ----
    if _has_any(complaint, PHISHING_PATTERNS):
        return {
            "ticket_id": ticket_id,
            "relevant_transaction_id": None,
            "evidence_verdict": "insufficient_data",
            "case_type": "phishing_or_social_engineering",
            "severity": "critical",
            "department": "fraud_risk",
            "agent_summary": (
                "Customer reports a suspected phishing attempt asking for OTP/PIN. "
                "Account compromise risk — requires immediate fraud team review."
            ),
            "recommended_next_action": (
                "Escalate to fraud_risk team. Flag customer account for monitoring. "
                "Do not request any credentials from the customer."
            ),
            "customer_reply": (
                "Thank you for informing us. bKash never asks for your PIN or OTP by phone, "
                "SMS, or email. Please do not share your PIN or OTP with anyone. "
                "We are forwarding this case to our fraud team for review."
            ),
            "human_review_required": True,
            "confidence": 0.95,
            "reason_codes": ["phishing_keyword_match", "fraud_priority"],
        }

    # ---- Vague / insufficient_data ----
    if _has_any(complaint, VAGUE_PATTERNS) and len(complaint.split()) < 12:
        return {
            "ticket_id": ticket_id,
            "relevant_transaction_id": None,
            "evidence_verdict": "insufficient_data",
            "case_type": "other",
            "severity": "medium",
            "department": "customer_support",
            "agent_summary": (
                "Customer complaint is vague. Cannot identify a specific issue from "
                "the provided text and transaction history."
            ),
            "recommended_next_action": (
                "Contact the customer to gather more details about the issue: which "
                "transaction, what date, what amount."
            ),
            "customer_reply": (
                "Thank you for contacting us. To help you better, could you please share "
                "more details about the issue? For example, the transaction ID, date, "
                "and amount. Please do not share your PIN or OTP with anyone."
            ),
            "human_review_required": True,
            "confidence": 0.7,
            "reason_codes": ["vague_complaint", "needs_clarification"],
        }

    # ---- Ambiguous dispute (multiple possible matching transactions) ----
    # If complaint suggests recipient didn't receive AND there are 2+ similar transactions,
    # or any same-amount/same-type transactions exist, treat as ambiguous.
    if _has_any(complaint, AMBIGUOUS_DISPUTE_PATTERNS) and len(history) >= 2:
        # Count transactions with same amount + type
        same_amount_type = {}
        for t in history:
            key = (t.get("amount"), t.get("type"))
            same_amount_type[key] = same_amount_type.get(key, 0) + 1
        has_duplicates = any(c >= 2 for c in same_amount_type.values())
        if has_duplicates or len(history) >= 3:
            return {
                "ticket_id": ticket_id,
                "relevant_transaction_id": None,
                "evidence_verdict": "insufficient_data",
                "case_type": "wrong_transfer",
                "severity": "high",
                "department": "dispute_resolution",
                "agent_summary": (
                    "Multiple transactions in history could match the complaint. "
                    "Cannot identify the specific transfer without more information from "
                    "the customer."
                ),
                "recommended_next_action": (
                    "Contact the customer to confirm the recipient's phone number and "
                    "the exact time of the transfer. Then match against transaction history."
                ),
                "customer_reply": (
                    "Thank you for reporting this. To help us identify the correct "
                    "transaction, could you please confirm the recipient's phone number "
                    "and the exact time you sent the money? Please do not share your "
                    "PIN or OTP with anyone."
                ),
                "human_review_required": True,
                "confidence": 0.85,
                "reason_codes": ["ambiguous_match", "needs_clarification"],
            }

    # ---- Wrong transfer ----
    if _has_any(complaint, WRONG_TRANSFER_PATTERNS):
        txn, txn_score, _ = _rank_transactions(complaint, history)
        # Check for inconsistency: repeated transfers to same recipient = inconsistent
        recipient_count: dict[str, int] = {}
        for t in history:
            cp = t.get("counterparty")
            if cp:
                recipient_count[cp] = recipient_count.get(cp, 0) + 1
        is_inconsistent = any(c >= 3 for c in recipient_count.values())

        # If we have no confident match, force insufficient_data + lower confidence
        if txn is None:
            evidence_verdict = "insufficient_data"
            confidence = 0.7
        elif is_inconsistent:
            evidence_verdict = "inconsistent"
            confidence = 0.9
        else:
            evidence_verdict = "consistent"
            confidence = min(0.95, 0.75 + txn_score * 0.05)

        return {
            "ticket_id": ticket_id,
            "relevant_transaction_id": txn.get("transaction_id") if txn else None,
            "evidence_verdict": evidence_verdict,
            "case_type": "wrong_transfer",
            "severity": "high",
            "department": "dispute_resolution",
            "agent_summary": (
                f"Customer reports sending money to the wrong recipient. "
                f"Matching transaction: {txn.get('transaction_id') if txn else 'none identified'}. "
                + (
                    "Multiple prior transfers to the same recipient suggest pattern — flag for review."
                    if is_inconsistent
                    else ""
                )
            ),
            "recommended_next_action": (
                "Verify the transaction details with the customer and attempt to contact "
                "the unintended recipient through official channels. Escalate to "
                "dispute_resolution if the amount cannot be recovered."
            ),
            "customer_reply": (
                "We have noted your concern about the transfer. Our dispute resolution "
                "team will review the transaction and contact the recipient through "
                "official channels if needed. Any eligible amount will be returned "
                "through official channels. Please do not share your PIN or OTP with anyone."
            ),
            "human_review_required": True,
            "confidence": 0.9 if txn else 0.7,
            "reason_codes": ["wrong_transfer_keyword", "transaction_match" if txn else "no_match"],
        }

    # ---- Payment failed ----
    if _has_any(complaint, PAYMENT_FAILED_PATTERNS):
        txn, txn_score, _ = _rank_transactions(complaint, history)
        # If a failed payment exists, evidence supports complaint
        has_failed = any(t.get("status") == "failed" for t in history)
        # If we have no confident match OR no failed txn, mark as insufficient_data
        evidence_verdict = "consistent" if (txn and has_failed) else "insufficient_data"
        if txn and has_failed:
            confidence = min(0.95, 0.75 + txn_score * 0.05)
        elif txn:
            confidence = 0.7
        else:
            confidence = 0.6
        return {
            "ticket_id": ticket_id,
            "relevant_transaction_id": txn.get("transaction_id") if txn else None,
            "evidence_verdict": evidence_verdict,
            "case_type": "payment_failed",
            "severity": "high",
            "department": "payments_ops",
            "agent_summary": (
                f"Customer reports a failed payment with possible balance deduction. "
                f"Matching transaction: {txn.get('transaction_id') if txn else 'none identified'}."
            ),
            "recommended_next_action": (
                "Verify the transaction status with payments operations. If balance was "
                "deducted but payment failed, initiate reconciliation through official channels."
            ),
            "customer_reply": (
                "We have noted your concern about the failed payment. Our payments "
                "operations team will review the transaction. Any eligible amount will "
                "be returned through official channels. Please do not share your PIN "
                "or OTP with anyone."
            ),
            "human_review_required": True,
            "confidence": confidence,
            "reason_codes": ["payment_failed_keyword"],
        }

    # ---- Duplicate payment ----
    if _has_any(complaint, DUPLICATE_PATTERNS):
        # Find last duplicate by amount to same counterparty
        txn = None
        seen: dict[tuple, int] = {}
        for t in history:
            key = (t.get("amount"), t.get("counterparty"), t.get("type"))
            seen[key] = seen.get(key, 0) + 1
            if seen[key] >= 2:
                txn = t
        return {
            "ticket_id": ticket_id,
            "relevant_transaction_id": txn.get("transaction_id") if txn else None,
            "evidence_verdict": "consistent" if txn else "insufficient_data",
            "case_type": "duplicate_payment",
            "severity": "medium",
            "department": "payments_ops",
            "agent_summary": (
                f"Customer reports a duplicate payment. "
                f"Matching transaction: {txn.get('transaction_id') if txn else 'none identified'}."
            ),
            "recommended_next_action": (
                "Verify both transactions in payments_ops. If duplicate confirmed, "
                "process reversal through official channels."
            ),
            "customer_reply": (
                "We have noted your concern about the duplicate payment. Our payments "
                "operations team will review and verify. Any eligible amount will be "
                "returned through official channels. Please do not share your PIN or "
                "OTP with anyone."
            ),
            "human_review_required": True,
            "confidence": 0.9 if txn else 0.6,
            "reason_codes": ["duplicate_payment_keyword"],
        }

    # ---- Merchant settlement delay ----
    if _has_any(complaint, MERCHANT_SETTLEMENT_PATTERNS) or user_type == "merchant":
        txn, txn_score, _ = _rank_transactions(complaint, history)
        has_pending_settlement = any(
            t.get("type") == "settlement" and t.get("status") == "pending" for t in history
        )
        evidence_verdict = "consistent" if (txn and has_pending_settlement) else "insufficient_data"
        if txn and has_pending_settlement:
            confidence = min(0.95, 0.75 + txn_score * 0.05)
        elif txn:
            confidence = 0.7
        else:
            confidence = 0.6
        return {
            "ticket_id": ticket_id,
            "relevant_transaction_id": txn.get("transaction_id") if txn else None,
            "evidence_verdict": evidence_verdict,
            "case_type": "merchant_settlement_delay",
            "severity": "medium",
            "department": "merchant_operations",
            "agent_summary": (
                f"Merchant reports a pending settlement. "
                f"Matching transaction: {txn.get('transaction_id') if txn else 'none identified'}."
            ),
            "recommended_next_action": (
                "Verify the settlement status in merchant_operations. If pending beyond "
                "expected window, escalate to the settlement team."
            ),
            "customer_reply": (
                "Thank you for bringing this to our attention. We are reviewing your "
                "settlement status. Any eligible amount will be processed through official "
                "channels. Please do not share your PIN or OTP with anyone."
            ),
            "human_review_required": True,
            "confidence": confidence,
            "reason_codes": ["merchant_settlement_keyword"],
        }

    # ---- Agent cash-in issue ----
    if _has_any(complaint, AGENT_CASH_IN_PATTERNS):
        txn, txn_score, _ = _rank_transactions(complaint, history)
        has_pending_cashin = bool(txn and txn.get("status") == "pending")
        evidence_verdict = "consistent" if has_pending_cashin else "insufficient_data"
        if has_pending_cashin:
            confidence = min(0.95, 0.75 + txn_score * 0.05)
        elif txn:
            confidence = 0.7
        else:
            confidence = 0.6
        return {
            "ticket_id": ticket_id,
            "relevant_transaction_id": txn.get("transaction_id") if txn else None,
            "evidence_verdict": evidence_verdict,
            "case_type": "agent_cash_in_issue",
            "severity": "high",
            "department": "agent_operations",
            "agent_summary": (
                f"Customer reports a cash-in via agent that was not reflected in balance. "
                f"Matching transaction: {txn.get('transaction_id') if txn else 'none identified'}."
            ),
            "recommended_next_action": (
                "Verify the cash-in transaction with the agent and escalate to "
                "agent_operations for resolution."
            ),
            "customer_reply": (
                "আমরা আপনার এজেন্ট ক্যাশ-ইন সংক্রান্ত অভিযোগটি পেয়েছি। আমাদের এজেন্ট "
                "অপারেশন টিম এটি যাচাই করে দেখবে। অনুগ্রহ করে আপনার পিন বা ওটিপি কারো "
                "সাথে শেয়ার করবেন না।" if language == "bn" else
                "We have noted your concern about the cash-in transaction. Our agent "
                "operations team will verify and resolve this. Please do not share your "
                "PIN or OTP with anyone."
            ),
            "human_review_required": True,
            "confidence": confidence,
            "reason_codes": ["agent_cash_in_keyword"],
        }

    # ---- Refund request, low severity (simple refund, change of mind) — check FIRST ----
    if (
        _has_any(complaint, REFUND_PATTERNS)
        and ("changed my mind" in complaint.lower() or "don't want" in complaint.lower() or "do not want" in complaint.lower())
    ):
        txn, txn_score, _ = _rank_transactions(complaint, history)
        evidence_verdict = "consistent" if txn else "insufficient_data"
        if txn:
            confidence = min(0.95, 0.75 + txn_score * 0.05)
        else:
            confidence = 0.6
        return {
            "ticket_id": ticket_id,
            "relevant_transaction_id": txn.get("transaction_id") if txn else None,
            "evidence_verdict": evidence_verdict,
            "case_type": "refund_request",
            "severity": "low",
            "department": "customer_support",
            "agent_summary": (
                f"Customer requests a refund (change of mind). "
                f"Matching transaction: {txn.get('transaction_id') if txn else 'none identified'}."
            ),
            "recommended_next_action": (
                "Verify the transaction and the merchant's refund policy. If eligible, "
                "process through official channels."
            ),
            "customer_reply": (
                "Thank you for your refund request. We will review your case and "
                "any eligible amount will be returned through official channels. "
                "Please do not share your PIN or OTP with anyone."
            ),
            "human_review_required": False,
            "confidence": confidence,
            "reason_codes": ["refund_keyword", "change_of_mind"],
        }

    # ---- Refund request (general) ----
    if _has_any(complaint, REFUND_PATTERNS):
        txn, txn_score, _ = _rank_transactions(complaint, history)
        evidence_verdict = "consistent" if txn else "insufficient_data"
        if txn:
            confidence = min(0.9, 0.6 + txn_score * 0.05)
        else:
            confidence = 0.55
        return {
            "ticket_id": ticket_id,
            "relevant_transaction_id": txn.get("transaction_id") if txn else None,
            "evidence_verdict": evidence_verdict,
            "case_type": "refund_request",
            "severity": "low",
            "department": "customer_support",
            "agent_summary": (
                f"Customer requests a refund. "
                f"Matching transaction: {txn.get('transaction_id') if txn else 'none identified'}."
            ),
            "recommended_next_action": (
                "Verify the transaction and the merchant's refund policy. If eligible, "
                "process through official channels."
            ),
            "customer_reply": (
                "Thank you for your refund request. We will review your case and "
                "any eligible amount will be returned through official channels. "
                "Please do not share your PIN or OTP with anyone."
            ),
            "human_review_required": True,
            "confidence": confidence,
            "reason_codes": ["refund_keyword"],
        }

    # No high-confidence rule match — defer to Gemini
    return None