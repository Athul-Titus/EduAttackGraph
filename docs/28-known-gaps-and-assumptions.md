# Known Gaps and Assumptions

This document explicitly records every place where the paper is ambiguous, incomplete, or where implementation decisions had to be made beyond what the paper specifies.

---

## GAP-001: spark-api Role Ambiguity

**Severity**: Medium  
**Paper Reference**: Algorithm 1, line 6, 19; Section III.A

**What the paper says**:
> "ai_model = 'spark-api' — Vulnerability analysis API"
> The algorithm uses `AI_ANALYZE(fingerprint, ai_model)` within the fingerprinting step (Algorithm 1).

**The ambiguity**:
The paper separately defines the full RAG pipeline (Algorithm 2) using BGE + FAISS + DeepSeek. It is not clear whether:
- (a) spark-api performs an intermediate vulnerability analysis within fingerprinting (before RAG), then RAG is a separate second pipeline
- (b) spark-api IS the underlying model for the RAG pipeline  
- (c) spark-api is used only for the per-fingerprint inline analysis, while DeepSeek handles the full prompt-based analysis

**Implementation Decision**:
spark-api is treated as an **optional** per-fingerprint pre-analysis step, isolatable behind a `SparkAPIAdapter` interface. The clean Stage 2 RAG pipeline (fingerprint → BGE → FAISS → threshold → context → DeepSeek) is implemented independently and does NOT depend on spark-api.

**Consequence**:
If spark-api provides important intermediate processing that feeds into the Stage 2 pipeline, this implementation may differ from the paper's exact behavior. This is explicitly documented and the adapter pattern allows future integration if clarified.

---

## GAP-002: port-go.exe / server-go.exe / finger.exe

**Severity**: High  
**Paper Reference**: Algorithm 1, parameters

**What the paper says**:
- `port-go.exe` with `-d ip` flag → returns bracket-content list of open ports
- `server-go.exe` → service version identification
- `finger.exe` with `-u url` flag → returns bracket-content with web fingerprint features

**The ambiguity**:
These are custom research tools, not publicly available. Their internal implementation, output formats, and behavior are not specified in the paper.

**Implementation Decision**:
Python-native implementations:
- `PortScanner` uses `socket`-based TCP connect probing
- `ServiceIdentifier` uses banner grabbing + service signature matching
- `WebFingerprintProvider` uses HTTP header analysis + body pattern matching

Adapter interfaces (`PortScannerAdapter`, `ServiceScannerAdapter`, `WebFingerprintAdapter`) allow plugging in the `.exe` tools if available.

---

## GAP-003: Passive Monitoring Implementation

**Severity**: Low  
**Paper Reference**: Section III.A

**What the paper says**:
> "the fingerprinting process begins with a hybrid collection approach that combines active probing with passive monitoring"

**The ambiguity**:
Passive monitoring is mentioned but not specifically defined. Common interpretations:
- Network traffic capture (pcap)
- HTTP response header analysis (passive — no extra requests)
- Timing analysis of TCP responses

**Implementation Decision**:
HTTP/HTTPS response header analysis is treated as the "passive monitoring" component:
- Server headers (Server, X-Powered-By, X-Generator)
- Cookie names (JSESSIONID → Java, PHPSESSID → PHP)
- HTML meta tags and script includes
- No additional active probing beyond the initial HTTP request

Active probing = TCP port scanning + service banner grabbing.

---

## GAP-004: Similarity Threshold Interpretation

**Severity**: Critical (conceptual)  
**Paper Reference**: Algorithm 2 line 4, Section III.B

**What the paper says**:
> "If the computed similarity score exceeds this threshold, the current user query is determined to involve vulnerability-related content."

**The risk**:
The threshold classifies whether a **query is vulnerability-related** (sufficient for further analysis), NOT whether a vulnerability is **confirmed**. This distinction is critical.

**Implementation Decision**:
The threshold is clearly used only to determine:
> "Is this historical evidence relevant enough to include in the LLM's context?"

It does NOT imply:
> "This vulnerability has been confirmed."

Every finding produced by the LLM is labeled **INFERRED** until a human analyst validates it.

---

## GAP-005: Embedding Model Choice (bge-small-zh vs bge-m3)

**Severity**: Low  
**Paper Reference**: Algorithm 2, Section III.B

**What the paper says**:
> "specifically the pretrained bge-small-zh model from HuggingFace"

**The issue**:
`bge-small-zh` is optimized for Chinese text. Awesome-POC contains substantial English content.

**Implementation Decision**:
Default: `BAAI/bge-m3` (multilingual, supports 100+ languages including Chinese and English)
Alternative: `BAAI/bge-small-zh` (available via `EMBEDDING_MODEL` env var)

**Consequence**:
Results may differ from the paper's 98.89% accuracy, which was obtained with `bge-small-zh` on a Chinese-heavy test set. **Do not claim this implementation reproduces the paper's accuracy metrics.**

---

## GAP-006: Text Chunking Parameters

**Severity**: Low  
**Paper Reference**: Algorithm 2 lines 12-14

**What the paper says**:
> "text chunking technology is employed to disassemble each vulnerability example into independent text units"

Parameters NOT specified: chunk size, overlap, chunking strategy.

**Implementation Decision**:
- Default chunk size: 512 tokens
- Default overlap: 50 tokens
- Strategy: recursive character-based splitting with sentence boundary detection
- All parameters configurable via `CHUNK_SIZE` and `CHUNK_OVERLAP` env vars

---

## GAP-007: Top-K Parameter

**Severity**: Low  
**Paper Reference**: Algorithm 2 (not specified)

**What the paper says**:
Algorithm 2 retrieves only `top_match` (the single highest-similarity vector). The paper does not specify Top-K retrieval for context enrichment.

**Implementation Decision**:
Top-K=5 by default (configurable). The highest-similarity match is used as Ψ(T) in the prompt per Algorithm 2. Additional retrieved results are provided as supplementary context.

---

## GAP-008: CSV vs JSON Fingerprint Format

**Severity**: Low  
**Paper Reference**: Section III.A

**What the paper says**:
> "The results are aggregated into a structured CSV report"

**Implementation Decision**:
JSON format is used internally. The structured fingerprint is:
```json
{
  "target": "...",
  "timestamp": "...",
  "ports": [
    {
      "port": 80,
      "service": "http",
      "version": "Apache/2.4.41",
      "url": "http://target:80",
      "fingerprint": "RuoYi",
      "vulnerability": null
    }
  ]
}
```
CSV export is provided for compatibility with the paper's described format.

---

## GAP-009: Performance Claims

**Severity**: Critical (integrity)  
**Paper Reference**: Section III.C

**What the paper says**:
- 98.89% identification accuracy on 90-sample test set
- 79.04s average processing for vulnerability data
- 9.29s average for non-vulnerability data

**Important warning**:
These results were obtained by the paper's authors on their specific:
- Hardware configuration
- Knowledge base size
- Test dataset (25 Chinese + 25 English vulnerability samples)
- Embedding model (bge-small-zh)
- DeepSeek model version

**This implementation DOES NOT CLAIM to reproduce these metrics** without independent evaluation on comparable conditions.

---

## GAP-010: Logical Vulnerability Detection

**Severity**: Medium  
**Paper Reference**: Section V

**What the paper says**:
> "LLM-EduAttackGraph does not yet support the detection of logical flaws."

**Implementation**:
This limitation is preserved. The system targets the six specified vulnerability categories (O1-O6) and does not claim to detect logical/business-flow vulnerabilities.

---

## Summary Table

| ID | Gap | Severity | Resolution |
|---|---|---|---|
| GAP-001 | spark-api role ambiguity | Medium | Optional adapter, isolated from Stage 2 |
| GAP-002 | .exe tools unavailable | High | Python-native + adapter interfaces |
| GAP-003 | Passive monitoring specifics | Low | HTTP header/response analysis |
| GAP-004 | Threshold = confirmation | Critical | Clear labeling: INFERRED until VALIDATED |
| GAP-005 | bge-small-zh vs multilingual | Low | bge-m3 default, bge-small-zh optional |
| GAP-006 | Chunk size not specified | Low | 512 tokens, configurable |
| GAP-007 | Top-K not specified | Low | K=5 default, configurable |
| GAP-008 | CSV vs JSON | Low | JSON internal, CSV export available |
| GAP-009 | Performance not reproducible | Critical | No claims made without independent evaluation |
| GAP-010 | Logical vulnerabilities | Medium | Not supported (per paper) |
