"""Production Ollama & OpenAI-compatible llama.cpp bridge with quantum-seeded exploration."""

from __future__ import annotations

from typing import Any

import httpx
from pydantic import BaseModel, Field

from qaegis.core.config import QuantumEntropyConfig
from qaegis.modules.quantum_entropy.harvester import QuantumEntropyPool


class QuantumBranchSamplingParams(BaseModel):
    """Quantum-derived sampling hyperparameters injected into a local LLM generation call."""

    seed: int = Field(ge=0)
    temperature: float = Field(ge=0.0, le=2.0)
    top_p: float = Field(gt=0.0, le=1.0)
    top_k: int = Field(ge=1)


class OllamaGenerationResult(BaseModel):
    """Structured response from a quantum-seeded Ollama / llama.cpp inference call."""

    model: str
    response_text: str
    sampling_params: QuantumBranchSamplingParams
    eval_count: int | None = None
    endpoint: str


class OllamaQuantumBridge:
    """Async client connecting local Ollama / llama.cpp agents to Q-Aegis quantum entropy."""

    def __init__(
        self,
        config: QuantumEntropyConfig | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._config = config or QuantumEntropyConfig()
        self._external_client = client

    def build_sampling_params(
        self,
        pool: QuantumEntropyPool,
        base_temperature: float = 0.7,
        temp_jitter: float = 0.15,
        base_top_p: float = 0.9,
        top_k: int = 40,
    ) -> QuantumBranchSamplingParams:
        """Derive a verified quantum seed and perturbed temperature/top_p from the entropy pool."""
        # Keep seed inside signed 31-bit integer range accepted by both Ollama and llama.cpp
        seed = pool.next_uint32() & 0x7FFF_FFFF
        delta_t = (pool.next_uniform() * 2.0 - 1.0) * temp_jitter
        temp = max(0.05, min(1.8, base_temperature + delta_t))
        delta_p = (pool.next_uniform() * 2.0 - 1.0) * 0.05
        top_p = max(0.5, min(0.99, base_top_p + delta_p))
        return QuantumBranchSamplingParams(
            seed=seed,
            temperature=round(temp, 4),
            top_p=round(top_p, 4),
            top_k=top_k,
        )

    async def check_health(self) -> tuple[bool, list[str]]:
        """Query local Ollama `/api/tags` to check reachability and available models."""
        url = f"{self._config.ollama_base_url.rstrip('/')}/api/tags"
        try:
            if self._external_client is not None:
                resp = await self._external_client.get(url)
            else:
                async with httpx.AsyncClient(timeout=self._config.ollama_timeout_s) as client:
                    resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
            models = [str(m["name"]) for m in data.get("models", []) if "name" in m]
            return (True, models)
        except Exception:
            return (False, [])

    async def generate_with_quantum_seed(
        self,
        prompt: str,
        pool: QuantumEntropyPool,
        model: str | None = None,
        base_temperature: float = 0.7,
        system_prompt: str | None = None,
    ) -> OllamaGenerationResult:
        """Execute `/api/generate` on local Ollama using verified quantum sampling parameters."""
        params = self.build_sampling_params(pool=pool, base_temperature=base_temperature)
        target_model = model or self._config.ollama_model
        url = f"{self._config.ollama_base_url.rstrip('/')}/api/generate"
        payload: dict[str, Any] = {
            "model": target_model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "seed": params.seed,
                "temperature": params.temperature,
                "top_p": params.top_p,
                "top_k": params.top_k,
            },
        }
        if system_prompt:
            payload["system"] = system_prompt

        if self._external_client is not None:
            resp = await self._external_client.post(url, json=payload)
        else:
            async with httpx.AsyncClient(timeout=self._config.ollama_timeout_s) as client:
                resp = await client.post(url, json=payload)
        resp.raise_for_status()
        body = resp.json()
        return OllamaGenerationResult(
            model=str(body.get("model", target_model)),
            response_text=str(body.get("response", "")),
            sampling_params=params,
            eval_count=int(body["eval_count"]) if "eval_count" in body else None,
            endpoint=url,
        )

    async def generate_openai_compatible(
        self,
        messages: list[dict[str, str]],
        pool: QuantumEntropyPool,
        model: str | None = None,
        base_temperature: float = 0.7,
    ) -> OllamaGenerationResult:
        """Execute `/v1/chat/completions` on llama.cpp or OpenAI-compatible local runtimes."""
        if not messages:
            raise ValueError("messages must contain at least one chat turn")
        params = self.build_sampling_params(pool=pool, base_temperature=base_temperature)
        target_model = model or self._config.ollama_model
        url = f"{self._config.ollama_base_url.rstrip('/')}/v1/chat/completions"
        payload: dict[str, Any] = {
            "model": target_model,
            "messages": messages,
            "seed": params.seed,
            "temperature": params.temperature,
            "top_p": params.top_p,
        }
        if self._external_client is not None:
            resp = await self._external_client.post(url, json=payload)
        else:
            async with httpx.AsyncClient(timeout=self._config.ollama_timeout_s) as client:
                resp = await client.post(url, json=payload)
        resp.raise_for_status()
        body = resp.json()
        choices = body.get("choices", [])
        text = str(choices[0]["message"]["content"]) if choices else ""
        usage = body.get("usage", {})
        return OllamaGenerationResult(
            model=str(body.get("model", target_model)),
            response_text=text,
            sampling_params=params,
            eval_count=int(usage["completion_tokens"]) if "completion_tokens" in usage else None,
            endpoint=url,
        )
