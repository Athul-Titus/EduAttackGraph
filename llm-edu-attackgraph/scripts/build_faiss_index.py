"""
Build FAISS Index Script

This script implements the offline phase of Algorithm 2 from the paper:
    raw_vulns ← DOWNLOADFILES(history_repo)
    for each vuln_file in raw_vulns:
        description ← EXTRACTDESCRIPTION(vuln_file)
        chunk ← CREAT_CHUNK(description)
        text_chunks.append(chunk)
    for each chunk in text_chunks:
        vector ← EMBEDTEXT(chunk, embedding_model)
        embeddings.append(vector)
    vector_db ← INITFAISSDB()
    vector_db.add(embeddings)

Usage:
    python scripts/build_faiss_index.py
    python scripts/build_faiss_index.py --source awesome-poc
    python scripts/build_faiss_index.py --awesome-poc-path ./rag/data/raw/awesome-poc
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.config import settings
from app.services.embeddings.provider import BGEEmbeddingProvider
from app.services.vector_store.faiss_store import FAISSVectorStore

# Add rag directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from rag.ingestion.loader import KnowledgeBaseManager


def build_index(
    awesome_poc_path: str = None,
    index_path: str = None,
    metadata_path: str = None,
) -> None:
    """
    Build FAISS index from Awesome-POC knowledge base.
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

    start_time = time.time()

    # Configuration
    kb_path = awesome_poc_path or settings.AWESOME_POC_LOCAL_PATH
    idx_path = index_path or settings.FAISS_INDEX_PATH
    meta_path = metadata_path or settings.FAISS_METADATA_PATH

    print(f"\n{'='*60}")
    print("LLM-EduAttackGraph — FAISS Index Builder")
    print(f"Paper: Algorithm 2 (Offline Knowledge Base Construction)")
    print(f"{'='*60}")
    print(f"Embedding model:  {settings.EMBEDDING_MODEL}")
    print(f"Awesome-POC path: {kb_path}")
    print(f"FAISS index:      {idx_path}")
    print(f"Metadata:         {meta_path}")
    print(f"Chunk size:       {settings.CHUNK_SIZE} tokens")
    print(f"Chunk overlap:    {settings.CHUNK_OVERLAP} tokens")
    print(f"{'='*60}\n")

    # Step 1: Load and chunk documents
    print("[1/4] Loading Awesome-POC documents...")
    manager = KnowledgeBaseManager(repo_path=kb_path)

    if not os.path.exists(kb_path) and not (kb_path and kb_path.endswith('.json')):
        print(f"  Awesome-POC raw folder '{kb_path}' not found.")
        print("  Utilizing local knowledge base dataset (rag/data/samples/demo_knowledge_base.json)...")

    docs, chunks = manager.load_and_chunk()
    print(f"  Loaded {len(docs)} documents")
    print(f"  Produced {len(chunks)} text chunks")

    if not chunks:
        print("ERROR: No text chunks produced. Check the Awesome-POC path.")
        sys.exit(1)

    # Step 2: Embed all chunks
    print(f"\n[2/4] Embedding {len(chunks)} chunks with {settings.EMBEDDING_MODEL}...")
    provider = BGEEmbeddingProvider()

    texts = [chunk.text for chunk in chunks]
    batch_size = settings.EMBEDDING_BATCH_SIZE

    import numpy as np
    all_embeddings = []
    for i in range(0, len(texts), batch_size):
        batch = texts[i:i+batch_size]
        batch_embeddings = provider.embed_batch(batch)
        all_embeddings.append(batch_embeddings)
        print(f"  Embedded {min(i+batch_size, len(texts))}/{len(texts)} chunks...")

    vectors = np.vstack(all_embeddings)
    print(f"  Embedding shape: {vectors.shape}")
    print(f"  Embedding dimension: {vectors.shape[1]}")

    # Step 3: Build FAISS index
    print(f"\n[3/4] Building FAISS index...")

    # Prepare chunk metadata for mapping
    chunk_metadata = []
    for i, chunk in enumerate(chunks):
        chunk_metadata.append({
            "chunk_id": chunk.chunk_id,
            "document_id": chunk.document_metadata.source_path,
            "source": chunk.document_metadata.source,
            "source_path": chunk.document_metadata.source_path,
            "title": chunk.document_metadata.title,
            "technology": chunk.document_metadata.technology,
            "category": chunk.document_metadata.category,
            "cve_id": chunk.document_metadata.cve_id,
            "chunk_position": chunk.chunk_position,
            "chunk_text": chunk.text,
            "chunk_size_chars": len(chunk.text),
        })

    vector_store = FAISSVectorStore(index_path=idx_path, metadata_path=meta_path)
    vector_store.build_index(
        vectors=vectors,
        chunk_metadata=chunk_metadata,
        embedding_model=settings.EMBEDDING_MODEL,
        dataset_version=datetime.utcnow().strftime("%Y%m%d"),
    )

    # Step 4: Save
    print(f"\n[4/4] Saving FAISS index...")
    vector_store.save()

    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"[OK] FAISS index built successfully!")
    print(f"  Vectors stored: {vector_store.num_vectors}")
    print(f"  Dimension: {vectors.shape[1]}")
    print(f"  Index path: {idx_path}")
    print(f"  Elapsed: {elapsed:.1f}s")
    print(f"{'='*60}")
    print(f"\nNext step: Configure your LLM_PROVIDER in .env and start the backend.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Build FAISS index from Awesome-POC knowledge base"
    )
    parser.add_argument("--awesome-poc-path", default=None)
    parser.add_argument("--index-path", default=None)
    parser.add_argument("--metadata-path", default=None)

    args = parser.parse_args()
    build_index(
        awesome_poc_path=args.awesome_poc_path,
        index_path=args.index_path,
        metadata_path=args.metadata_path,
    )
