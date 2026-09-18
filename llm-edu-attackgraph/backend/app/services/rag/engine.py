"""
RAG Engine — Stage 2 of LLM-EduAttackGraph

Implements Algorithm 2 from the paper:

    procedure PROCESS_USER_QUERY(vector_db):
        query_vector ← EMBEDTEXT(user_query, embedding_model)
        max_similarity ← 0.0
        for each vector in vector_db:
            similarity ← COSINESIMILARITY(query_vector, vector)
            if similarity > max_similarity:
                max_similarity ← similarity
                top_match ← GETTEXTBYINDEX(index)
        if max_similarity >= similarity_threshold:
            prompt ← COMBINATION(top_match, user_query)
            llm_response ← Get_LLM(prompt, llm_model)
            answer ← FORMATRESPONSE(llm_response)
        else:
            return "No relevant vulnerabilities were detected"

    function COSINESIMILARITY(vecA, vecB):
        dot_product ← DOT(vecA, vecB)
        normA ← NORM(vecA)
        normB ← NORM(vecB)
        return dot_product / (normA * normB)

Prompt construction (from paper):
    Prompt = Φ(T₂) ⊕ Ψ(T) ⊕ Γ
    Where:
        Φ(T₂) = user input (fingerprint)
        Ψ(T)  = historical vulnerability with highest similarity
        Γ      = instruction template
        ⊕      = concatenation/combination
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

import numpy as np

from app.config import settings
from app.services.embeddings.provider import EmbeddingProvider, get_embedding_provider
from app.services.vector_store.faiss_store import FAISSVectorStore, SearchResult, get_vector_store
from app.services.fingerprinting.engine import StructuredFingerprint


# ==============================================================================
# Similarity Engine
# ==============================================================================

class SimilarityEngine:
    """
    Cosine similarity computation and threshold filtering.

    Paper formula:
        sim(vᵢ, vⱼ) = (vᵢ · vⱼ) / (‖vᵢ‖ · ‖vⱼ‖) = cos θ ∈ [-1, 1]

    Threshold (paper): 0.6
        "If the computed similarity score exceeds this threshold,
         the current user query is determined to involve vulnerability-related content."

    CRITICAL NOTE: Similarity ≥ threshold means:
        "Historical evidence is relevant enough for LLM analysis"
    It does NOT mean:
        "Vulnerability is confirmed"
    """

    def __init__(self, threshold: float = None):
        self.threshold = threshold or settings.SIMILARITY_THRESHOLD

    def cosine_similarity(self, vec_a: np.ndarray, vec_b: np.ndarray) -> float:
        """
        Compute cosine similarity between two vectors.
        Paper formula: sim(vᵢ, vⱼ) = (vᵢ · vⱼ) / (‖vᵢ‖ · ‖vⱼ‖)
        """
        dot_product = float(np.dot(vec_a, vec_b))
        norm_a = float(np.linalg.norm(vec_a))
        norm_b = float(np.linalg.norm(vec_b))

        if norm_a == 0.0 or norm_b == 0.0:
            return 0.0

        return dot_product / (norm_a * norm_b)

    def filter_by_threshold(
        self,
        results: List[SearchResult],
        threshold: Optional[float] = None,
    ) -> List[SearchResult]:
        """Filter retrieval results by similarity threshold."""
        t = threshold or self.threshold
        return [r for r in results if r.similarity_score >= t]

    def passes_threshold(self, max_similarity: float, threshold: Optional[float] = None) -> bool:
        """Check if the maximum similarity exceeds the threshold."""
        t = threshold or self.threshold
        return max_similarity >= t


# ==============================================================================
# Retrieval Result
# ==============================================================================

@dataclass
class RetrievalResult:
    """Complete RAG retrieval result."""
    query_text: str
    embedding_model: str
    top_k: int
    similarity_threshold: float
    results: List[SearchResult]
    max_similarity: float
    threshold_passed: bool
    # Clear note: all results are RETRIEVED, not OBSERVED or INFERRED
    evidence_type: str = "retrieved"

    @property
    def top_result(self) -> Optional[SearchResult]:
        """The best matching result (Ψ(T) in paper's notation)."""
        if self.results:
            return max(self.results, key=lambda r: r.similarity_score)
        return None


# ==============================================================================
# RAG Context
# ==============================================================================

@dataclass
class RAGContext:
    """
    Complete RAG context ready for LLM inference.
    Paper: Prompt = Φ(T₂) ⊕ Ψ(T) ⊕ Γ
    """
    query_text: str          # Φ(T₂) — user input (fingerprint)
    evidence_text: str       # Ψ(T) — best matching historical vulnerability
    template: str            # Γ — instruction template
    full_prompt: str         # Combined prompt sent to LLM
    retrieval: RetrievalResult


# ==============================================================================
# RAG Engine
# ==============================================================================

class RAGEngine:
    """
    Main RAG pipeline implementing Algorithm 2 from the paper.

    Workflow:
    1. Embed fingerprint/query (same model as offline phase — critical)
    2. FAISS retrieval
    3. Cosine similarity + threshold filtering
    4. Prompt construction: Φ(T₂) ⊕ Ψ(T) ⊕ Γ
    5. Return RAGContext for LLM inference
    """

    def __init__(
        self,
        embedding_provider: Optional[EmbeddingProvider] = None,
        vector_store: Optional[FAISSVectorStore] = None,
        similarity_engine: Optional[SimilarityEngine] = None,
        prompt_templates_path: Optional[str] = None,
    ):
        self._embedding_provider = embedding_provider
        self._vector_store = vector_store
        self._similarity_engine = similarity_engine or SimilarityEngine()
        self.prompt_templates_path = prompt_templates_path or settings.PROMPT_TEMPLATES_PATH
        self._prompt_template: Optional[str] = None

    @property
    def embedding_provider(self) -> EmbeddingProvider:
        if self._embedding_provider is None:
            self._embedding_provider = get_embedding_provider()
        return self._embedding_provider

    @property
    def vector_store(self) -> FAISSVectorStore:
        if self._vector_store is None:
            self._vector_store = get_vector_store()
        return self._vector_store

    def load_prompt_template(self) -> str:
        """Load the vulnerability analysis prompt template (Γ)."""
        if self._prompt_template is None:
            template_path = f"{self.prompt_templates_path}/vulnerability_analysis.txt"
            try:
                with open(template_path, "r", encoding="utf-8") as f:
                    self._prompt_template = f.read()
            except FileNotFoundError:
                # Default template if file not found
                self._prompt_template = self._default_template()
        return self._prompt_template

    def _default_template(self) -> str:
        """Default prompt template (Γ)."""
        return """You are a cybersecurity expert analyzing a web application's security posture.

You have been provided with:
1. A technical fingerprint of a target web application (what was OBSERVED)
2. A historical vulnerability case from a knowledge base (RETRIEVED reference material)

Your task is to analyze whether the fingerprint suggests potential vulnerabilities based on the historical case.

CRITICAL INSTRUCTIONS:
- Base your analysis on the provided evidence
- Clearly distinguish what is OBSERVED (from fingerprint) vs RETRIEVED (from history)
- Your analysis is INFERRED — it is NOT a confirmed vulnerability
- State your uncertainty explicitly
- Provide practical remediation guidance
- Do NOT claim a vulnerability is confirmed without human validation
- Never produce exploit code or payloads

Respond with a structured JSON object:
{
  "potential_vulnerability": "Brief description of potential vulnerability",
  "category": "O1_RCE|O2_SQL_INJECTION|O3_WEAK_PASSWORD|O4_UNAUTHORIZED|O5_TOKEN_TAMPERING|O6_INFO_DISCLOSURE|UNKNOWN",
  "affected_technology": "Technology/component that may be affected",
  "evidence": ["List of evidence points from fingerprint"],
  "analysis": "Detailed analysis explaining why this may be vulnerable",
  "severity": "critical|high|medium|low|informational",
  "remediation": ["Step 1", "Step 2", "Step 3"],
  "uncertainty": "Statement of confidence level and what would confirm/deny this",
  "validation_required": true
}"""

    async def retrieve(
        self,
        query_text: str,
        top_k: Optional[int] = None,
        threshold: Optional[float] = None,
    ) -> RetrievalResult:
        """
        Perform RAG retrieval.

        Algorithm 2 PROCESS_USER_QUERY:
        1. query_vector ← EMBEDTEXT(user_query, embedding_model)
        2. For each vector: similarity ← COSINESIMILARITY(query_vector, vector)
        3. Find max_similarity and top_match
        4. if max_similarity >= threshold: proceed; else: "no vulnerabilities detected"
        """
        k = top_k or settings.TOP_K
        t = threshold or settings.SIMILARITY_THRESHOLD

        # Step 1: Embed query (same model as offline phase)
        query_vector = self.embedding_provider.embed_text(query_text)

        # Step 2: FAISS retrieval (efficiently computes cosine similarity)
        if not self.vector_store.is_loaded:
            raise RuntimeError(
                "FAISS index not loaded. Run 'python scripts/build_faiss_index.py' first, "
                "or use demo mode."
            )

        results = self.vector_store.search(query_vector, k=k)

        # Step 3: Find max similarity
        max_similarity = max((r.similarity_score for r in results), default=0.0)

        # Step 4: Check threshold
        threshold_passed = self._similarity_engine.passes_threshold(max_similarity, t)

        return RetrievalResult(
            query_text=query_text,
            embedding_model=self.embedding_provider.get_model_name(),
            top_k=k,
            similarity_threshold=t,
            results=results,
            max_similarity=max_similarity,
            threshold_passed=threshold_passed,
        )

    async def build_context(
        self,
        fingerprint: StructuredFingerprint,
        top_k: Optional[int] = None,
        threshold: Optional[float] = None,
    ) -> Optional[RAGContext]:
        """
        Build complete RAG context for LLM inference.
        Returns None if no relevant vulnerabilities found (threshold not passed).

        Paper: Prompt = Φ(T₂) ⊕ Ψ(T) ⊕ Γ
        """
        # Convert fingerprint to text — this is Φ(T₂)
        query_text = fingerprint.to_text()

        # Retrieve relevant historical evidence
        retrieval = await self.retrieve(query_text, top_k=top_k, threshold=threshold)

        if not retrieval.threshold_passed:
            return None  # Paper: "No relevant vulnerabilities were detected"

        # Get best matching evidence — Ψ(T)
        top_result = retrieval.top_result
        if not top_result:
            return None

        evidence_text = top_result.chunk_text

        # Load instruction template — Γ
        template = self.load_prompt_template()

        # Construct prompt: Φ(T₂) ⊕ Ψ(T) ⊕ Γ
        # Paper: "COMBINATION(top_match, user_query)"
        full_prompt = self._build_prompt(
            query_text=query_text,
            evidence_text=evidence_text,
            template=template,
            top_result=top_result,
        )

        return RAGContext(
            query_text=query_text,
            evidence_text=evidence_text,
            template=template,
            full_prompt=full_prompt,
            retrieval=retrieval,
        )

    def _build_prompt(
        self,
        query_text: str,
        evidence_text: str,
        template: str,
        top_result: SearchResult,
    ) -> str:
        """
        Construct the full prompt for LLM.
        Paper: Prompt = Φ(T₂) ⊕ Ψ(T) ⊕ Γ
        """
        prompt = f"""{template}

---

## OBSERVED Fingerprint (Φ — Target Information)
{query_text}

---

## RETRIEVED Historical Vulnerability (Ψ — from {top_result.source})
Source: {top_result.source}
Title: {top_result.title or 'N/A'}
Technology: {top_result.technology or 'N/A'}
Category: {top_result.category or 'N/A'}
Similarity Score: {top_result.similarity_score:.4f}

Content:
{evidence_text}

---

Based on the OBSERVED fingerprint and the RETRIEVED historical vulnerability case above,
provide your security analysis as a structured JSON response.
Remember: your output is INFERRED analysis, not a confirmed finding.
"""
        return prompt
