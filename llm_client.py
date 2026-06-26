"""Groq LLM client (OpenAI-compatible) — singleton, async, 25s timeout.

The client is configured once at module import. Each request calls
`analyze()` which wraps the SDK call in asyncio.wait_for() so a hung
model cannot exceed the per-request budget. Any failure (timeout, JSON
parse error, transport error) returns None and lets the caller fall
back to the deterministic safe-response path.

Provider: Groq (https://api.groq.com/openai/v1)
Model:    llama-3.3-70b-versatile
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from typing import Any, Optional

from openai import AsyncOpenAI

from prompts import SYSTEM_PROMPT, build_user_message


log = logging.getLogger("queuestorm.llm")

LLM_TIMEOUT_SECONDS = 25.0
GROQ_BASE_URL = "https://api.groq.com/openai/v1"
GROQ_MODEL_NAME = "llama-3.3-70b-versatile"

# Initialize exactly once at module import
_api_key = os.getenv("GROQ_API_KEY", "").strip()
if _api_key:
    _client = AsyncOpenAI(
        api_key=_api_key,
        base_url=GROQ_BASE_URL,
        timeout=LLM_TIMEOUT_SECONDS,
    )
    log.info("Groq LLM client initialized: model=%s", GROQ_MODEL_NAME)
else:
    _client = None
    log.warning("GROQ_API_KEY not set; analyze() will return None")


def is_configured() -> bool:
    """True if the LLM client was successfully configured at startup."""
    return _client is not None


_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def _extract_json(text: str) -> Optional[dict[str, Any]]:
    """Robustly extract a JSON object from a possibly noisy model response."""
    if not text:
        return None
    text = text.strip()
    # Strip markdown fences if present
    m = _JSON_FENCE_RE.search(text)
    if m:
        text = m.group(1)
    # First, try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Try to locate the first {...} block
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        snippet = text[start : end + 1]
        try:
            return json.loads(snippet)
        except json.JSONDecodeError:
            return None
    return None


async def analyze(ticket: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Call Groq LLM once and return parsed JSON dict, or None on any failure."""
    if _client is None:
        log.warning("LLM not configured; returning None")
        return None

    user_message = build_user_message(ticket)
    try:
        coro = _client.chat.completions.create(
            model=GROQ_MODEL_NAME,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            temperature=0.2,
            max_tokens=1024,
            response_format={"type": "json_object"},  # enforce JSON mode
        )
        response = await asyncio.wait_for(coro, timeout=LLM_TIMEOUT_SECONDS)
        if not response.choices:
            log.warning("Groq returned no choices")
            return None
        text = response.choices[0].message.content or ""
        parsed = _extract_json(text)
        if parsed is None:
            log.warning("LLM returned non-JSON or empty response: %r", text[:200])
            return None
        return parsed
    except asyncio.TimeoutError:
        log.warning("LLM call exceeded %.1fs timeout", LLM_TIMEOUT_SECONDS)
        return None
    except Exception as exc:  # noqa: BLE001
        log.warning("LLM call failed: %s", exc)
        return None