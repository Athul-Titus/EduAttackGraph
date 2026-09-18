"""
BGE Embedding Provider

Paper: "Each text chunk is then encoded into vector representations using
       the BGE embedding algorithm, specifically the pretrained bge-small-zh
       model from HuggingFace"

Implementation: Uses BAAI/bge-m3 (multilingual) as default.
The SAME model must be used for both:
  1. Offline: embedding knowledge base chunks
  2. Online: embedding runtime fingerprint queries

Critical requirement from the paper:
    vᵢ = BGE(tᵢ)   — knowledge base chunks
    vⱼ = BGE(tⱼ)   — query vector
Both must be in the same embedding space.
"""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from typing import List, Optional

import numpy as np

from app.config import settings


# ==============================================================================
# Abstract Interface — allows swapping embedding models
# ==============================================================================

class EmbeddingProvider(ABC):
    """
    Abstract embedding provider interface.
    Implementations: BGEEmbeddingProvider, MockEmbeddingProvider
    """

    @abstractmethod
    def embed_text(self, text: str) -> np.ndarray:
        """Embed a single text string. Returns numpy array."""

    @abstractmethod
    def embed_batch(self, texts: List[str]) -> np.ndarray:
        """Embed multiple texts. Returns 2D numpy array of shape (n, dim)."""

    @abstractmethod
    def get_model_name(self) -> str:
        """Return the model identifier."""

    @abstractmethod
    def get_dimension(self) -> int:
        """Return the embedding vector dimension."""

    def get_model_metadata(self) -> dict:
        """Return metadata for audit/traceability."""
        return {
            "model_name": self.get_model_name(),
            "dimension": self.get_dimension(),
            "provider": self.__class__.__name__,
        }


# ==============================================================================
# BGE Embedding Provider (real implementation)
# ==============================================================================

class BGEEmbeddingProvider(EmbeddingProvider):
    """
    BGE embedding provider using sentence-transformers.

    Paper: "pretrained bge-small-zh model from HuggingFace"
    Implementation: BAAI/bge-m3 (multilingual, same embedding space principle)

    The BGE model maps text sequences to fixed-length dense vector representations.
    BGE builds on BERT, learning semantic features through deep neural networks.
    """

    _instance: Optional[BGEEmbeddingProvider] = None

    def __init__(self, model_name: Optional[str] = None, device: Optional[str] = None):
        self.model_name = model_name or settings.EMBEDDING_MODEL
        self.device = device or settings.EMBEDDING_DEVICE
        self._model = None  # Lazy load
        self._dimension: Optional[int] = None

    @classmethod
    def get_instance(cls) -> BGEEmbeddingProvider:
        """Singleton instance to avoid reloading model."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _load_model(self):
        """Lazy model loading."""
        if self._model is None:
            try:
                from sentence_transformers import SentenceTransformer
                self._model = SentenceTransformer(
                    self.model_name,
                    device=self.device,
                )
                # Determine dimension
                test_embed = self._model.encode("test", convert_to_numpy=True)
                self._dimension = len(test_embed)
            except ImportError:
                raise RuntimeError(
                    "sentence-transformers is required for BGE embeddings. "
                    "Install with: pip install sentence-transformers"
                )

    def embed_text(self, text: str) -> np.ndarray:
        """
        Embed a single text.
        Paper: vᵢ = BGE(tᵢ)
        """
        self._load_model()
        embedding = self._model.encode(
            text,
            convert_to_numpy=True,
            normalize_embeddings=True,  # L2 normalization for cosine similarity
        )
        return embedding.astype(np.float32)

    def embed_batch(self, texts: List[str], batch_size: Optional[int] = None) -> np.ndarray:
        """
        Embed multiple texts efficiently.
        Used for offline knowledge base construction.
        """
        self._load_model()
        bs = batch_size or settings.EMBEDDING_BATCH_SIZE
        embeddings = self._model.encode(
            texts,
            batch_size=bs,
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=len(texts) > 100,
        )
        return embeddings.astype(np.float32)

    def get_model_name(self) -> str:
        return self.model_name

    def get_dimension(self) -> int:
        if self._dimension is None:
            self._load_model()
        return self._dimension


# ==============================================================================
# Mock Embedding Provider (for testing and demo mode)
# ==============================================================================

class MockEmbeddingProvider(EmbeddingProvider):
    """
    Deterministic mock embedding provider for testing.

    IMPORTANT: This is NOT a real embedding model.
    It produces deterministic but semantically meaningless vectors.
    Use ONLY for testing — never for production analysis.
    """

    DIMENSION = 1024  # Same as bge-m3 default

    def __init__(self, dimension: int = DIMENSION):
        self._dim = dimension

    def embed_text(self, text: str) -> np.ndarray:
        """
        Deterministic embedding based on text hash.
        NOT semantically meaningful.
        """
        # Use hash for determinism
        np.random.seed(hash(text) % (2**31))
        vec = np.random.randn(self._dim).astype(np.float32)
        # L2 normalize
        vec = vec / np.linalg.norm(vec)
        return vec

    def embed_batch(self, texts: List[str]) -> np.ndarray:
        return np.array([self.embed_text(t) for t in texts])

    def get_model_name(self) -> str:
        return "mock-embedding-provider"

    def get_dimension(self) -> int:
        return self._dim


# ==============================================================================
# Factory
# ==============================================================================

def get_embedding_provider() -> EmbeddingProvider:
    """
    Factory function. Returns appropriate embedding provider.
    Uses BGE in normal mode, Mock in test/demo mode (if configured).
    """
    if settings.is_demo_mode and os.environ.get("USE_MOCK_EMBEDDINGS") == "1":
        return MockEmbeddingProvider()
    return BGEEmbeddingProvider.get_instance()
