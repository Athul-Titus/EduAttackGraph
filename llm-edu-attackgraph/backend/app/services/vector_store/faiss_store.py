"""
FAISS Vector Store

Paper: "All embedded vectors of vulnerability descriptions are stored in a
       vector database (e.g., Faiss), enabling efficient similarity-based
       retrieval at scale."

Implements:
    INITFAISSDB()  → build_index()
    vector_db.add(embeddings) → add()
    Search → search()

Architecture:
    - FAISS stores vectors only
    - PostgreSQL stores chunk metadata (text, document_id, source)
    - Metadata mapping: FAISS vector ID → chunk_id → document metadata
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np

from app.config import settings


# ==============================================================================
# Data Classes
# ==============================================================================

@dataclass
class SearchResult:
    """One result from FAISS similarity search."""
    faiss_index_id: int
    chunk_id: str
    document_id: str
    source: str
    title: Optional[str]
    technology: Optional[str]
    category: Optional[str]
    chunk_text: str
    similarity_score: float          # cosine similarity ∈ [-1, 1]
    evidence_type: str = "retrieved" # Always RETRIEVED — from knowledge base


@dataclass
class IndexMetadata:
    """Metadata stored alongside FAISS index."""
    index_version: str
    embedding_model: str
    embedding_dimension: int
    dataset_version: str
    creation_timestamp: str
    num_vectors: int
    # Mapping: FAISS index position → chunk metadata
    id_to_chunk: Dict[int, Dict] = field(default_factory=dict)


# ==============================================================================
# FAISS Vector Store
# ==============================================================================

class FAISSVectorStore:
    """
    FAISS-based vector store for vulnerability knowledge base.

    Paper specifies FAISS for efficient similarity-based retrieval.
    This class maintains:
      - FAISS index (vectors only)
      - Metadata mapping (FAISS ID → chunk data)
    These are stored separately (index.bin + metadata.json).
    """

    def __init__(
        self,
        index_path: Optional[str] = None,
        metadata_path: Optional[str] = None,
    ):
        self.index_path = index_path or settings.FAISS_INDEX_PATH
        self.metadata_path = metadata_path or settings.FAISS_METADATA_PATH
        self._index = None
        self._metadata: Optional[IndexMetadata] = None

    def _ensure_dirs(self):
        os.makedirs(os.path.dirname(self.index_path) or ".", exist_ok=True)
        os.makedirs(os.path.dirname(self.metadata_path) or ".", exist_ok=True)

    def build_index(
        self,
        vectors: np.ndarray,
        chunk_metadata: List[Dict],
        embedding_model: str,
        dataset_version: str = "1.0",
        index_version: str = "1.0",
    ) -> None:
        """
        Build FAISS index from vectors.
        Paper: INITFAISSDB() then vector_db.add(embeddings)

        Args:
            vectors: 2D numpy array of shape (n, dimension)
            chunk_metadata: List of dicts with chunk_id, document_id, source, etc.
        """
        try:
            import faiss
        except ImportError:
            raise RuntimeError(
                "faiss-cpu is required. Install with: pip install faiss-cpu"
            )

        if len(vectors) == 0:
            raise ValueError("Cannot build FAISS index from empty vectors.")

        dimension = vectors.shape[1]

        # Inner product index (for normalized vectors = cosine similarity)
        self._index = faiss.IndexFlatIP(dimension)
        self._index.add(vectors.astype(np.float32))

        # Build metadata mapping
        from datetime import datetime
        id_to_chunk = {}
        for i, chunk_meta in enumerate(chunk_metadata):
            id_to_chunk[i] = chunk_meta

        self._metadata = IndexMetadata(
            index_version=index_version,
            embedding_model=embedding_model,
            embedding_dimension=dimension,
            dataset_version=dataset_version,
            creation_timestamp=datetime.utcnow().isoformat(),
            num_vectors=len(vectors),
            id_to_chunk=id_to_chunk,
        )

    def save(self) -> None:
        """Persist FAISS index and metadata to disk."""
        if self._index is None:
            raise RuntimeError("No index to save. Call build_index() first.")

        import faiss

        self._ensure_dirs()
        faiss.write_index(self._index, self.index_path)

        # Save metadata
        with open(self.metadata_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "index_version": self._metadata.index_version,
                    "embedding_model": self._metadata.embedding_model,
                    "embedding_dimension": self._metadata.embedding_dimension,
                    "dataset_version": self._metadata.dataset_version,
                    "creation_timestamp": self._metadata.creation_timestamp,
                    "num_vectors": self._metadata.num_vectors,
                    "id_to_chunk": {
                        str(k): v for k, v in self._metadata.id_to_chunk.items()
                    },
                },
                f,
                ensure_ascii=False,
                indent=2,
            )

    def load(self) -> None:
        """Load FAISS index and metadata from disk."""
        if not os.path.exists(self.index_path):
            raise FileNotFoundError(f"FAISS index not found at {self.index_path}")
        if not os.path.exists(self.metadata_path):
            raise FileNotFoundError(f"FAISS metadata not found at {self.metadata_path}")

        import faiss

        self._index = faiss.read_index(self.index_path)

        with open(self.metadata_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self._metadata = IndexMetadata(
            index_version=data["index_version"],
            embedding_model=data["embedding_model"],
            embedding_dimension=data["embedding_dimension"],
            dataset_version=data["dataset_version"],
            creation_timestamp=data["creation_timestamp"],
            num_vectors=data["num_vectors"],
            id_to_chunk={int(k): v for k, v in data["id_to_chunk"].items()},
        )

    def search(
        self,
        query_vector: np.ndarray,
        k: int = 5,
    ) -> List[SearchResult]:
        """
        Search for top-K most similar vectors.
        Paper: "cosine similarity is computed between the query vector
               and all stored vulnerability vectors"

        Returns SearchResult list sorted by similarity (descending).
        Note: With normalized vectors + IndexFlatIP, inner product = cosine similarity.
        """
        if self._index is None:
            raise RuntimeError("FAISS index not loaded. Call load() or build_index() first.")

        # Normalize query vector for cosine similarity
        query_vector = query_vector.astype(np.float32)
        norm = np.linalg.norm(query_vector)
        if norm > 0:
            query_vector = query_vector / norm

        query_2d = query_vector.reshape(1, -1)
        distances, indices = self._index.search(query_2d, k)

        results = []
        for dist, idx in zip(distances[0], indices[0]):
            if idx == -1:  # FAISS returns -1 for empty slots
                continue

            chunk_meta = self._metadata.id_to_chunk.get(int(idx), {})
            results.append(SearchResult(
                faiss_index_id=int(idx),
                chunk_id=chunk_meta.get("chunk_id", f"chunk_{idx}"),
                document_id=chunk_meta.get("document_id", ""),
                source=chunk_meta.get("source", "unknown"),
                title=chunk_meta.get("title"),
                technology=chunk_meta.get("technology"),
                category=chunk_meta.get("category"),
                chunk_text=chunk_meta.get("chunk_text", ""),
                similarity_score=float(dist),
                evidence_type="retrieved",
            ))

        return sorted(results, key=lambda r: r.similarity_score, reverse=True)

    @property
    def is_loaded(self) -> bool:
        return self._index is not None

    @property
    def num_vectors(self) -> int:
        return self._metadata.num_vectors if self._metadata else 0

    @property
    def embedding_model(self) -> Optional[str]:
        return self._metadata.embedding_model if self._metadata else None

    def validate_compatibility(self, embedding_model: str, dimension: int) -> None:
        """
        Validate that the loaded index is compatible with the current embedding model.
        Changing embedding model/dimension requires rebuilding the index.
        """
        if not self._metadata:
            raise RuntimeError("Index metadata not loaded.")

        if self._metadata.embedding_model != embedding_model:
            raise ValueError(
                f"Embedding model mismatch: index was built with "
                f"'{self._metadata.embedding_model}' but current model is "
                f"'{embedding_model}'. Rebuild the FAISS index."
            )

        if self._metadata.embedding_dimension != dimension:
            raise ValueError(
                f"Embedding dimension mismatch: index has dimension "
                f"{self._metadata.embedding_dimension} but model produces "
                f"dimension {dimension}. Rebuild the FAISS index."
            )


# ==============================================================================
# Global instance
# ==============================================================================

_vector_store: Optional[FAISSVectorStore] = None


def get_vector_store() -> FAISSVectorStore:
    """Get the global FAISS vector store instance."""
    global _vector_store
    if _vector_store is None:
        _vector_store = FAISSVectorStore()
        # Try to load existing index
        try:
            _vector_store.load()
        except FileNotFoundError:
            pass  # Index will be built when knowledge base is ingested
    return _vector_store
