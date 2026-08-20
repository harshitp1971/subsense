"""Thin async client for a local Ollama instance. All AI use in subsense is opt-in and local —
no discovered data leaves the machine unless the user has pointed `ai.host` somewhere remote
themselves.
"""

from __future__ import annotations

import json
import logging

import httpx

from subsense.config import AiConfig

logger = logging.getLogger(__name__)


class OllamaError(Exception):
    pass


class OllamaClient:
    def __init__(self, config: AiConfig):
        self.config = config

    async def generate_json(self, prompt: str, *, system: str | None = None) -> dict | list:
        """Send `prompt` to the configured model in JSON mode and parse the response."""
        payload: dict = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": False,
        }
        if self.config.json_mode:
            payload["format"] = "json"
        if system:
            payload["system"] = system

        async with httpx.AsyncClient(timeout=120.0) as client:
            try:
                resp = await client.post(f"{self.config.host}/api/generate", json=payload)
                resp.raise_for_status()
            except httpx.HTTPError as exc:
                raise OllamaError(f"Ollama request failed: {exc}") from exc

        data = resp.json()
        raw = data.get("response", "")
        try:
            return json.loads(raw)
        except ValueError as exc:
            raise OllamaError(f"Ollama did not return valid JSON: {raw[:200]!r}") from exc

    async def is_available(self) -> bool:
        async with httpx.AsyncClient(timeout=3.0) as client:
            try:
                resp = await client.get(f"{self.config.host}/api/tags")
                return resp.status_code == 200
            except httpx.HTTPError:
                return False
