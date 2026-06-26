"""FastAPI app for QueueStorm Investigator.

Endpoints:
    GET  /health          -> {"status": "ok"}
    POST /analyze-ticket  -> structured AnalyzeOutput JSON

The endpoint uses a typed Pydantic body parameter (TicketInput) and declares
the response model (AnalyzeOutput), so OpenAPI / Swagger UI shows the full
request and response schemas with all fields, types, and enums.

Custom validation errors are preserved via a RequestValidationError handler:
- Malformed JSON body            -> 400 {"error":"invalid_json", ...}
- Non-dict body (e.g. [1,2,3])   -> 422 {"error":"schema_violation", ...}
- Schema mismatch                -> 422 {"error":"schema_violation", ...}
- Any unhandled exception        -> 500 {"error":"internal_error", ...}

The service never crashes on malformed input.
"""
from __future__ import annotations

import logging
import os
from typing import Any

# Load .env FIRST so that downstream modules see env vars at import time
from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError

import uvicorn

from fallback import build_fallback
from heuristics import rule_based_analyze
from llm_client import analyze as llm_analyze
from models import AnalyzeOutput, TicketInput
from safety import sanitize


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("queuestorm")

app = FastAPI(
    title="QueueStorm Investigator",
    version="1.0.0",
    description=(
        "AI/API copilot for bKash support agents. "
        "Receives a customer support ticket (complaint + recent transaction history) "
        "and returns a structured decision: case type, severity, routing department, "
        "agent summary, safe customer reply, and whether human review is required."
    ),
)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/health", response_model=dict[str, str])
async def health() -> dict[str, str]:
    """Health probe. Returns 200 with `{"status":"ok"}` if the service is running."""
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Analyze — main endpoint
# ---------------------------------------------------------------------------
@app.post(
    "/analyze-ticket",
    response_model=AnalyzeOutput,
    summary="Analyze a customer support ticket",
    description=(
        "Accepts a customer complaint plus their recent transaction history. "
        "Investigates what actually happened, classifies the case, and returns a "
        "structured decision with routing, severity, and a safe customer reply."
    ),
    responses={
        200: {
            "description": "Successful analysis. Body conforms to AnalyzeOutput schema.",
            "content": {
                "application/json": {
                    "example": {
                        "ticket_id": "TKT-001",
                        "relevant_transaction_id": "TXN-9101",
                        "evidence_verdict": "consistent",
                        "case_type": "wrong_transfer",
                        "severity": "high",
                        "department": "dispute_resolution",
                        "agent_summary": "Customer reports sending 5000 BDT to wrong recipient. TXN-9101 matches.",
                        "recommended_next_action": "Verify TXN-9101 and escalate to dispute_resolution.",
                        "customer_reply": "We have noted your concern about transaction TXN-9101. Any eligible amount will be returned through official channels. Please do not share your PIN or OTP with anyone.",
                        "human_review_required": True,
                        "confidence": 0.9,
                        "reason_codes": ["wrong_transfer_keyword", "transaction_match"],
                    }
                }
            },
        },
        400: {"description": "Malformed JSON body."},
        422: {"description": "Request body does not match the TicketInput schema."},
        500: {"description": "Internal server error. Body never contains stack traces or secrets."},
    },
)
async def analyze_ticket(ticket: TicketInput) -> AnalyzeOutput:
    # FastAPI has already parsed + validated the body. `ticket` is a valid TicketInput.
    ticket_dict = ticket.model_dump()

    # 1. Try rule-based heuristics first (fast, deterministic, no quota burn)
    rule_result = rule_based_analyze(ticket_dict)

    # 2. Call LLM only if rules didn't fire or have low confidence
    llm_raw = None
    if rule_result is None or rule_result.get("confidence", 0.0) < 0.8:
        llm_raw = await llm_analyze(ticket_dict)

    # 3. Build response: prefer LLM > rules > fallback
    if llm_raw is not None:
        result = sanitize(llm_raw, ticket_dict)
    elif rule_result is not None:
        result = sanitize(rule_result, ticket_dict)
    else:
        result = build_fallback(ticket_dict["ticket_id"])

    # 4. Final Pydantic validation — guarantees wire-format compliance
    try:
        final = AnalyzeOutput.model_validate(result)
    except ValidationError as ve:
        log.warning("Sanitized output failed Pydantic validation: %s", ve.errors())
        fallback_dict = build_fallback(ticket_dict["ticket_id"])
        final = AnalyzeOutput.model_validate(fallback_dict)

    # FastAPI will serialize via response_model=AnalyzeOutput.
    return final


# ---------------------------------------------------------------------------
# Exception handlers — preserve custom error shapes
# ---------------------------------------------------------------------------
def _is_malformed_json_error(errors: list[dict[str, Any]]) -> bool:
    """Distinguish malformed JSON from schema mismatches in FastAPI's errors list."""
    for err in errors:
        err_type = err.get("type", "")
        loc = err.get("loc", [])
        # FastAPI tags json-parse failures with type='json_invalid' or loc=['body'] with msg hint
        if err_type == "json_invalid":
            return True
        if err_type == "value_error.jsondecode":
            return True
        # Some versions: loc=('body',) with msg containing "JSON"
        if loc == ("body",) and "json" in err.get("msg", "").lower():
            return True
    return False


def _extract_ticket_id_from_errors(errors: list[dict[str, Any]]) -> str | None:
    """Best-effort: pull ticket_id out of validation errors if it was present."""
    for err in errors:
        if err.get("loc") == ("body", "ticket_id"):
            input_value = err.get("input")
            if isinstance(input_value, str):
                return input_value
    return None


def _sanitize_errors(errors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Make Pydantic error dicts JSON-serializable.

    FastAPI's exc.errors() can include a ``ctx`` field with non-JSON-serializable
    objects (e.g. the raw ``ValueError`` raised by a ``field_validator``).
    Passing these straight into ``JSONResponse`` would crash with a TypeError,
    which then falls through to the 500 handler instead of returning 422.

    We strip any non-serializable ``ctx`` contents here while preserving every
    other piece of the error dict so the response stays informative.
    """
    sanitized: list[dict[str, Any]] = []
    for err in errors:
        clean: dict[str, Any] = {}
        for key, value in err.items():
            if key == "ctx" and isinstance(value, dict):
                # Drop any non-primitive entries in ctx; keep primitives (str/int/float/bool/None)
                clean_ctx: dict[str, Any] = {}
                for k, v in value.items():
                    if isinstance(v, (str, int, float, bool, type(None))):
                        clean_ctx[k] = v
                    else:
                        # Replace non-serializable object with its string repr
                        clean_ctx[k] = repr(v)
                clean[key] = clean_ctx
            elif key == "input":
                # input can be arbitrary user-supplied data — repr if not primitive
                if isinstance(value, (str, int, float, bool, type(None), list, dict)):
                    clean[key] = value
                else:
                    clean[key] = repr(value)
            else:
                clean[key] = value
        sanitized.append(clean)
    return sanitized


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Preserve custom error shapes for malformed JSON (400) and schema mismatch (422)."""
    raw_errors = exc.errors()
    if _is_malformed_json_error(raw_errors):
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_json", "detail": "Request body is not valid JSON"},
        )
    safe_errors = _sanitize_errors(raw_errors)
    return JSONResponse(
        status_code=422,
        content={
            "error": "schema_violation",
            "detail": safe_errors,
            "ticket_id": _extract_ticket_id_from_errors(raw_errors),
        },
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": "http_error", "detail": exc.detail},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    log.exception("Unhandled exception")
    return JSONResponse(
        status_code=500,
        content={"error": "internal_error", "detail": "Internal processing error"},
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, log_level="info")