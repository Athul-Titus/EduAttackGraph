"""
LLM Providers for LLM-EduAttackGraph

Paper: "This prompt is passed to an LLM—specifically, DeepSeek—to generate
       a comprehensive and informed response."

Supported providers:
    - DeepSeek (paper's choice)
    - Groq (free tier, Llama/Mixtral)
    - NVIDIA NIM (free credits, Llama/DeepSeek)
    - OpenAI (GPT-4o-mini etc.)
    - Mock (deterministic, for testing)

All providers except Mock use the OpenAI-compatible API format.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from app.config import settings, LLMProvider


# ==============================================================================
# LLM Output Structure
# ==============================================================================

@dataclass
class LLMAnalysisOutput:
    """
    Structured output from LLM analysis.
    Paper: response includes vulnerability analysis, severity, remediation.

    ALL fields are INFERRED — not confirmed.
    """
    potential_vulnerability: Optional[str] = None
    category: str = "UNKNOWN"
    affected_technology: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    analysis: Optional[str] = None
    severity: Optional[str] = None
    remediation: List[str] = field(default_factory=list)
    uncertainty: Optional[str] = None
    validation_required: bool = True
    evidence_type: str = "inferred"   # Always INFERRED
    raw_response: str = ""
    parse_error: Optional[str] = None


# ==============================================================================
# Abstract Provider Interface
# ==============================================================================

class LLMProvider(ABC):
    """Abstract LLM provider interface."""

    @abstractmethod
    async def complete(self, prompt: str) -> str:
        """Send prompt, return raw text response."""

    @abstractmethod
    def get_provider_name(self) -> str:
        """Return provider identifier."""

    @abstractmethod
    def get_model_name(self) -> str:
        """Return model identifier."""


# ==============================================================================
# OpenAI-Compatible Base Provider
# ==============================================================================

class OpenAICompatibleProvider(LLMProvider):
    """
    Base for all OpenAI-compatible API providers
    (DeepSeek, Groq, NVIDIA NIM, OpenAI all use the same API format).
    """

    def __init__(
        self,
        api_key: str,
        base_url: str,
        model: str,
        max_tokens: int = 2048,
        temperature: float = 0.1,
    ):
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature

    async def complete(self, prompt: str) -> str:
        """Send to OpenAI-compatible API."""
        try:
            from openai import AsyncOpenAI

            client = AsyncOpenAI(
                api_key=self.api_key,
                base_url=self.base_url,
            )

            response = await client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity analysis assistant."},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=self.max_tokens,
                temperature=self.temperature,
            )

            return response.choices[0].message.content or ""

        except ImportError:
            raise RuntimeError("openai package required. Install: pip install openai")


# ==============================================================================
# DeepSeek Provider (paper's choice)
# ==============================================================================

class DeepSeekProvider(OpenAICompatibleProvider):
    """
    DeepSeek LLM provider.
    Paper: "This prompt is passed to an LLM—specifically, DeepSeek"
    """

    def __init__(self):
        if not settings.DEEPSEEK_API_KEY:
            raise ValueError("DEEPSEEK_API_KEY not configured.")
        super().__init__(
            api_key=settings.DEEPSEEK_API_KEY,
            base_url=settings.DEEPSEEK_BASE_URL,
            model=settings.DEEPSEEK_MODEL,
            max_tokens=settings.DEEPSEEK_MAX_TOKENS,
            temperature=settings.DEEPSEEK_TEMPERATURE,
        )

    def get_provider_name(self) -> str:
        return "deepseek"

    def get_model_name(self) -> str:
        return settings.DEEPSEEK_MODEL


# ==============================================================================
# Groq Provider (free tier)
# ==============================================================================

class GroqProvider(OpenAICompatibleProvider):
    """
    Groq API provider.
    Supports Llama 3.3 70B, Mixtral, Gemma with free tier.
    """

    def __init__(self):
        if not settings.GROQ_API_KEY:
            raise ValueError("GROQ_API_KEY not configured.")
        super().__init__(
            api_key=settings.GROQ_API_KEY,
            base_url=settings.GROQ_BASE_URL,
            model=settings.GROQ_MODEL,
            max_tokens=2048,
            temperature=0.1,
        )

    def get_provider_name(self) -> str:
        return "groq"

    def get_model_name(self) -> str:
        return settings.GROQ_MODEL


# ==============================================================================
# NVIDIA NIM Provider (free credits)
# ==============================================================================

class NVIDIAProvider(OpenAICompatibleProvider):
    """
    NVIDIA NIM API provider.
    Free credits for Llama, Mistral, DeepSeek-R1.
    """

    def __init__(self):
        if not settings.NVIDIA_API_KEY:
            raise ValueError("NVIDIA_API_KEY not configured.")
        super().__init__(
            api_key=settings.NVIDIA_API_KEY,
            base_url=settings.NVIDIA_BASE_URL,
            model=settings.NVIDIA_MODEL,
            max_tokens=2048,
            temperature=0.1,
        )

    def get_provider_name(self) -> str:
        return "nvidia"

    def get_model_name(self) -> str:
        return settings.NVIDIA_MODEL


# ==============================================================================
# OpenAI Provider
# ==============================================================================

class OpenAIProvider(OpenAICompatibleProvider):
    """OpenAI provider (GPT-4o-mini etc.)."""

    def __init__(self):
        if not settings.OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY not configured.")
        super().__init__(
            api_key=settings.OPENAI_API_KEY,
            base_url=settings.OPENAI_BASE_URL,
            model=settings.OPENAI_MODEL,
            max_tokens=2048,
            temperature=0.1,
        )

    def get_provider_name(self) -> str:
        return "openai"

    def get_model_name(self) -> str:
        return settings.OPENAI_MODEL


# ==============================================================================
# Mock Provider (testing and demo mode)
# ==============================================================================

class MockLLMProvider(LLMProvider):
    """
    Deterministic mock LLM for testing and demo mode.

    IMPORTANT: This is NOT a real LLM.
    Outputs are synthetic — clearly labeled as DEMO/MOCK.
    Never use for actual security analysis.
    """

    DEMO_RESPONSES = {
        "RuoYi": {
            "potential_vulnerability": "[DEMO] RuoYi framework may have weak default password vulnerabilities",
            "category": "O3_WEAK_PASSWORD",
            "affected_technology": "RuoYi Java Development Platform",
            "evidence": [
                "OBSERVED: RuoYi framework detected on port 8080",
                "RETRIEVED: RuoYi has known default admin credentials (admin/admin123)",
            ],
            "analysis": "[DEMO] The RuoYi framework was detected. Historical cases show that "
                       "RuoYi deployments frequently have default credentials not changed "
                       "post-deployment. The backend login page at /login may accept default "
                       "credentials. This is INFERRED from historical patterns and requires validation.",
            "severity": "high",
            "remediation": [
                "Change default admin credentials immediately",
                "Implement strong password policy",
                "Enable CAPTCHA on login page",
                "Review access control configuration",
            ],
            "uncertainty": "This is INFERRED from historical data. Actual exploitation requires "
                          "testing login with default credentials which must be done with authorization. "
                          "Confidence: Medium — based on known pattern match.",
            "validation_required": True,
        }
    }

    async def complete(self, prompt: str) -> str:
        """Return deterministic demo response based on fingerprint content."""
        # Check for known frameworks in the prompt
        for framework, response in self.DEMO_RESPONSES.items():
            if framework.lower() in prompt.lower():
                response_copy = dict(response)
                response_copy["_demo_mode"] = True
                response_copy["_warning"] = "THIS IS SYNTHETIC DEMO DATA — NOT REAL ANALYSIS"
                return json.dumps(response_copy, indent=2)

        # Generic demo response
        return json.dumps({
            "potential_vulnerability": "[DEMO] Generic potential vulnerability detected",
            "category": "UNKNOWN",
            "affected_technology": "Unknown",
            "evidence": ["OBSERVED: Target fingerprint analyzed", "RETRIEVED: Historical patterns reviewed"],
            "analysis": "[DEMO] This is a synthetic demo response. No real LLM was used.",
            "severity": "informational",
            "remediation": ["Configure a real LLM provider for actual analysis"],
            "uncertainty": "This is DEMO data — completely synthetic.",
            "validation_required": True,
            "_demo_mode": True,
            "_warning": "THIS IS SYNTHETIC DEMO DATA — NOT REAL ANALYSIS",
        }, indent=2)

    def get_provider_name(self) -> str:
        return "mock"

    def get_model_name(self) -> str:
        return "mock-llm-v1"


# ==============================================================================
# Output Parser
# ==============================================================================

class LLMOutputParser:
    """
    Parse LLM JSON response into structured LLMAnalysisOutput.

    Handles:
    - Valid JSON responses
    - JSON embedded in markdown code blocks
    - Malformed responses (with error recording)
    """

    def parse(self, raw_response: str) -> LLMAnalysisOutput:
        """Parse raw LLM output into structured format."""
        output = LLMAnalysisOutput(raw_response=raw_response)

        # Try to extract JSON from the response
        parsed_json = self._extract_json(raw_response)

        if parsed_json is None:
            output.parse_error = "Could not extract valid JSON from LLM response"
            output.analysis = raw_response[:2000]
            return output

        # Map fields
        output.potential_vulnerability = parsed_json.get("potential_vulnerability")
        output.category = parsed_json.get("category", "UNKNOWN")
        output.affected_technology = parsed_json.get("affected_technology")
        output.evidence = parsed_json.get("evidence", [])
        output.analysis = parsed_json.get("analysis")
        output.severity = self._normalize_severity(parsed_json.get("severity"))
        output.remediation = parsed_json.get("remediation", [])
        output.uncertainty = parsed_json.get("uncertainty")
        output.validation_required = parsed_json.get("validation_required", True)

        # Enforce: always require validation
        output.validation_required = True
        output.evidence_type = "inferred"

        return output

    def _extract_json(self, text: str) -> Optional[Dict[str, Any]]:
        """Try to extract JSON from various response formats."""
        # Direct JSON parse
        try:
            return json.loads(text.strip())
        except json.JSONDecodeError:
            pass

        # JSON in markdown code block
        matches = re.findall(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
        for m in matches:
            try:
                return json.loads(m)
            except json.JSONDecodeError:
                continue

        # Find any JSON object in text
        match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass

        return None

    def _normalize_severity(self, severity: Optional[str]) -> Optional[str]:
        """Normalize severity to standard values."""
        if not severity:
            return None
        severity = severity.lower().strip()
        valid = {"critical", "high", "medium", "low", "informational", "info"}
        if severity in valid:
            return "informational" if severity == "info" else severity
        return "informational"


# ==============================================================================
# Guardrails
# ==============================================================================

class LLMGuardrails:
    """
    Prompt injection protection and output validation.
    
    Retrieved vulnerability text is UNTRUSTED DATA and must not
    override system instructions.
    """

    MAX_CONTEXT_LENGTH = 8000       # Characters
    MAX_EVIDENCE_LENGTH = 3000      # Per evidence chunk

    def sanitize_evidence(self, text: str) -> str:
        """
        Sanitize retrieved knowledge base content before including in prompt.
        Prevents prompt injection from malicious knowledge base content.
        """
        # Truncate if too long
        text = text[:self.MAX_EVIDENCE_LENGTH]

        # Remove potentially injective patterns
        dangerous_patterns = [
            r'(?i)ignore (all |previous |above )?instructions?',
            r'(?i)you are (now |actually )?a',
            r'(?i)system:?\s*\n',
            r'(?i)assistant:?\s*\n',
        ]
        for pattern in dangerous_patterns:
            text = re.sub(pattern, '[REDACTED]', text)

        return text

    def sanitize_fingerprint(self, text: str) -> str:
        """Sanitize fingerprint text before including in prompt."""
        return text[:self.MAX_CONTEXT_LENGTH]

    def validate_output(self, output: LLMAnalysisOutput) -> LLMAnalysisOutput:
        """
        Validate LLM output doesn't contain dangerous content.
        Enforces that validation_required is always True.
        """
        # Always require validation — never auto-confirm
        output.validation_required = True

        # Reject outputs that claim certainty without qualification
        if output.uncertainty and len(output.uncertainty) < 10:
            output.uncertainty = (
                "Note: Human validation required before treating this as a confirmed vulnerability. "
                + (output.uncertainty or "")
            )

        return output


# ==============================================================================
# Factory
# ==============================================================================

def get_llm_provider() -> LLMProvider:
    """
    Factory: returns configured LLM provider.
    Falls back to Mock if no API key is configured.
    """
    provider_setting = settings.LLM_PROVIDER

    try:
        if provider_setting.value == "deepseek" and settings.DEEPSEEK_API_KEY:
            return DeepSeekProvider()
        elif provider_setting.value == "groq" and settings.GROQ_API_KEY:
            return GroqProvider()
        elif provider_setting.value == "nvidia" and settings.NVIDIA_API_KEY:
            return NVIDIAProvider()
        elif provider_setting.value == "openai" and settings.OPENAI_API_KEY:
            return OpenAIProvider()
    except ValueError:
        pass

    # Fall back to mock if no key
    return MockLLMProvider()
