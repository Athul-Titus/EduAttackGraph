# Research-to-Implementation Mapping

## Purpose

This document maps every major research component from the paper to the corresponding implementation component, clearly distinguishing paper facts from engineering decisions.

---

## Component Mapping Table

| Research Component | Paper Reference | Implementation Component | Notes |
|---|---|---|---|
| Website Fingerprinting Module | Algorithm 1, Figure 2 | `FingerprintEngine` | Orchestrates all fingerprinting |
| Active TCP Probing | Algorithm 1 line 8 | `PortScanner` | Python socket + port-go.exe adapter |
| `port-go.exe` | Algorithm 1 parameter | `PortScannerAdapter` | Optional exe backend |
| Service Version Identification | Algorithm 1 lines 10-12 | `ServiceIdentifier` | Banner grab + server-go.exe adapter |
| `server-go.exe` | Algorithm 1 parameter | `ServiceScannerAdapter` | Optional exe backend |
| Web Application Fingerprinting | Algorithm 1 lines 13-20 | `WebFingerprintProvider` | HTTP analysis + finger.exe adapter |
| `finger.exe` | Algorithm 1 parameter | `WebFingerprintAdapter` | Optional exe backend |
| `spark-api` | Algorithm 1 parameter | `SparkAPIAdapter` (optional) | Per-fingerprint AI analysis, optional |
| Structured CSV Report | Paper section III.A | `StructuredFingerprint` (Pydantic model) | JSON format used instead of CSV |
| Historical Vulnerability Data | Algorithm 2 line 8 | `KnowledgeBaseManager` | Manages Awesome-POC ingestion |
| Awesome-POC | Paper section III.B | `AwesomePOCIngestionAdapter` | Parses GitHub repository markdown |
| Document Loading | Algorithm 2 lines 8-9 | `DocumentLoader` | |
| Description Extraction | Algorithm 2 line 11 | `MetadataExtractor` | |
| Text Chunking | Algorithm 2 lines 12-14 | `TextChunker` | Semantic + fixed-size chunking |
| BGE-small-zh | Algorithm 2 parameter, section III.B | `BGEEmbeddingProvider` | Uses bge-m3 (multilingual) |
| `EMBEDTEXT()` function | Algorithm 2 lines 16, 42-43 | `EmbeddingProvider.embed_text()` | |
| FAISS vector database | Algorithm 2 lines 19-20 | `FAISSVectorStore` | |
| `INITFAISSDB()` | Algorithm 2 line 19 | `FAISSVectorStore.build_index()` | |
| User query submission | Algorithm 2 lines 23-24 | `ScanManager.start_analysis()` | Fingerprint as query |
| Query embedding | Algorithm 2 line 24 | `EmbeddingProvider.embed_text()` | Same model as offline phase |
| `COSINESIMILARITY()` | Algorithm 2 lines 27, 45-50 | `SimilarityEngine.cosine_similarity()` | Formula: dot(A,B)/(norm(A)*norm(B)) |
| Similarity threshold 0.6 | Algorithm 2 line 4, section III.B | `SimilarityEngine.THRESHOLD=0.6` | Configurable via env var |
| Top-match retrieval | Algorithm 2 lines 28-31 | `RetrievalEngine.retrieve()` | Returns top-K with scores |
| Prompt construction | Algorithm 2 line 34, section III.B | `RAGEngine.build_prompt()` | Φ(T₂) ⊕ Ψ(T) ⊕ Γ |
| `COMBINATION(top_match, user_query)` | Algorithm 2 line 34 | `ContextBuilder.combine()` | |
| Φ(T₂) | Paper section III.B | Query fingerprint text | User input content |
| Ψ(T) | Paper section III.B | Retrieved historical vulnerability | Best match from FAISS |
| Γ | Paper section III.B | Instruction template | `llm/prompts/vulnerability_analysis.txt` |
| DeepSeek LLM | Algorithm 2 line 5, section III.B | `DeepSeekProvider` | |
| `Get_LLM()` | Algorithm 2 line 35 | `LLMProvider.complete()` | |
| Vulnerability analysis output | Paper section III.B | `AnalysisResult` (Pydantic model) | Structured JSON |
| Remediation suggestions | Paper section III.B | `AnalysisResult.remediation` | Part of LLM output |
| Human-in-the-loop | Paper abstract, section I | `ValidationService` | |
| No exploit payloads | Paper section I | Enforced: no shell execution | System constraint |

---

## Research Parameters Used Exactly

| Parameter | Paper Value | Implementation Default | Source |
|---|---|---|---|
| Similarity threshold | 0.6 | `SIMILARITY_THRESHOLD=0.60` | Algorithm 2 line 4, section III.B |
| LLM | DeepSeek | `LLM_PROVIDER=deepseek` | Algorithm 2 line 5 |
| Knowledge source | Awesome-POC | `KNOWLEDGE_BASE_SOURCE=awesome-poc` | Paper section III.B |
| Embedding model | bge-small-zh | `EMBEDDING_MODEL=BAAI/bge-m3` | Algorithm 2 parameter (see note) |

**Note on bge-m3**: The paper specifies `bge-small-zh`. This implementation uses `BAAI/bge-m3` (multilingual) because Awesome-POC contains English text. `bge-small-zh` is available as an option via the `EMBEDDING_MODEL` configuration variable. This is an **[IMPLEMENTATION DECISION]** documented in `28-known-gaps-and-assumptions.md`.

---

## What Was NOT Directly Specified by Paper

| Component | Reason | Decision |
|---|---|---|
| Prompt template text | Not provided in paper | Written from paper's output description + security best practices |
| Chunk size/overlap | Not specified | 512 tokens, 50 overlap (industry default) |
| Top-K value | Not specified | Default K=5, configurable |
| Database schema | Not specified | PostgreSQL with SQLAlchemy ORM |
| API structure | Not specified | FastAPI with /api/v1/ versioning |
| Frontend | Not specified | React/TypeScript/Vite |
| Report format | Partially specified | JSON + Markdown, with evidence provenance |
| Audit logging | Not specified | Structured logging to PostgreSQL audit_events table |
| Human validation states | Not specified | POTENTIAL → PENDING_REVIEW → VALIDATED/REJECTED/NEEDS_MORE_EVIDENCE |
| Demo mode | Not specified | Synthetic data with RuoYi fingerprint (mentioned in paper) |

---

## Algorithms Implemented

### Algorithm 1 (Fingerprinting) — Implementation

```python
class FingerprintEngine:
    async def scan_target(self, target_ip: str) -> StructuredFingerprint:
        # Authorization check (not in paper, added for safety)
        self.auth_manager.validate(target_ip)
        
        # PORT_SCAN(ip, scanner)
        open_ports = await self.port_scanner.scan(target_ip)
        
        service_map = {}
        for port in open_ports:
            # SERVICE_IDENTIFY(target_ip:port, service_scanner)
            service = await self.service_identifier.identify(target_ip, port)
            service_map[port] = PortRecord(port=port, service=service)
            
            if service.name in ("http", "https"):
                # BUILD_URL + WEB_FINGERPRINT
                url = build_url(service.name, target_ip, port)
                fingerprint = await self.web_fingerprint.fingerprint(url)
                service_map[port].url = url
                service_map[port].fingerprint = fingerprint
                
                if fingerprint and self.spark_adapter:
                    # AI_ANALYZE (optional spark-api step)
                    vulnerability = await self.spark_adapter.analyze(fingerprint)
                    service_map[port].vulnerability = vulnerability
        
        return self.generate_report(target_ip, service_map)
```

### Algorithm 2 (RAG) — Implementation

```python
class RAGEngine:
    # OFFLINE: build_knowledge_base()
    async def build_knowledge_base(self, repo_path: str) -> None:
        docs = self.document_loader.load(repo_path)
        chunks = self.text_chunker.chunk(docs)
        vectors = self.embedding_provider.embed_batch([c.text for c in chunks])
        self.vector_store.add(vectors, chunks)
        self.vector_store.save()
    
    # ONLINE: process_query()
    async def process_query(self, fingerprint: StructuredFingerprint) -> AnalysisResult:
        query_text = fingerprint.to_text()
        query_vector = self.embedding_provider.embed_text(query_text)
        
        # FAISS retrieval
        results = self.vector_store.search(query_vector, k=self.top_k)
        
        # Find max_similarity
        max_similarity = max(r.score for r in results)
        top_match = max(results, key=lambda r: r.score)
        
        if max_similarity >= self.threshold:
            # COMBINATION(top_match, user_query)
            prompt = self.context_builder.build(
                query=query_text,           # Φ(T₂)
                evidence=top_match.text,   # Ψ(T)
                template=self.template     # Γ
            )
            response = await self.llm.complete(prompt)
            return self.output_parser.parse(response)
        else:
            return AnalysisResult(
                status="no_relevant_vulnerabilities",
                message="No relevant vulnerabilities were detected"
            )
```
