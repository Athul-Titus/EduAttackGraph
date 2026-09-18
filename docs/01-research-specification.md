# Research Specification: LLM-EduAttackGraph

> **Source**: Liu et al., IEEE Internet of Things Journal, Vol. 13, No. 2, 15 January 2026, DOI: 10.1109/JIOT.2025.3631562

This document extracts and organizes what the paper **actually states**, clearly distinguished from implementation decisions.

---

## 1. Research Objective

**[PAPER FACT]** To address security vulnerabilities in educational websites (schools, universities, education bureaus in mainland China) by developing a tool that combines:
- Website fingerprinting
- Historical vulnerability data retrieval
- LLM-driven penetration path inference
- Human expert review

## 2. Problem Statement

**[PAPER FACT]** Existing approaches are limited by:
1. **Manual expertise dependency** — repetitive, time-consuming fingerprint collection, vulnerability matching, exploitation path analysis
2. **Rigid rule-based engines** — limited adaptability
3. **Generic tools** — lack contextual understanding of educational platforms
4. **No historical integration** — fail to efficiently integrate historical vulnerability data
5. **Fully automated attack tools** (PentestGPT, AutoAttacker, MAPTA) have:
   - High hardware resource requirements (GPU/CPU)
   - Offensive nature → abuse risk
   - Black-box decision making → poor interpretability

## 3. LLM-EduAttackGraph Advantages (from paper)

**[PAPER FACT]**
1. **Web-specific design** — core components (fingerprint scanning, knowledge base retrieval) built around web assets (HTTP/S, open ports, URL structures, software identifiers)
2. **No direct risk to target** — terminates at vulnerability analysis/recommendations; no exploit payloads executed
3. **Low resource consumption** — decoupled offline knowledge base + online lightweight reasoning; no GPU required
4. **High interpretability** — security administrators can trace which fingerprint features triggered which historical vulnerability retrieval
5. **Real-time knowledge updating** — vector database built from continuously updated repositories (Awesome-POC)
6. **Real-world validated** — identified 961 vulnerabilities in Chinese educational websites

## 4. System Architecture (Two Stages)

**[PAPER FACT]** LLM-EduAttackGraph operates in two main stages:

### Stage 1: Website Fingerprinting Module

Described in **Algorithm 1** and **Figure 2**:

**Parameters (from Algorithm 1):**
```
target_ip       — Target IP address or domain
port_scanner    = "port-go.exe"    — TCP/IP stack fingerprinting tool
service_scanner = "server-go.exe"  — Service version identification
fingerprint_tool = "finger.exe"    — Web application fingerprint analyzer
ai_model        = "spark-api"      — Vulnerability analysis API
```

**Procedure SCAN_TARGET(target_ip):**
1. `open_ports ← PORT_SCAN(target_ip, port_scanner)` — Active TCP probing
2. For each `port` in `open_ports`:
   - `service ← SERVICE_IDENTIFY(target_ip:port, service_scanner)`
   - `service_map[port] ← [port, service, "-", "-", ""]`
   - If `service ∈ {"http", "https"}`:
     - `url ← BUILD_URL(service, target_ip, port)`
     - `fingerprint ← WEB_FINGERPRINT(url, fingerprint_tool)` — Passive analysis
     - `service_map[port][2] ← url`
     - `service_map[port][3] ← fingerprint`
     - If `fingerprint ≠ null`:
       - `vulnerability ← AI_ANALYZE(fingerprint, ai_model)`
       - `service_map[port][4] ← vulnerability`
3. `GENERATE_REPORT(target_ip, service_map)`

**Supporting Functions:**
- `PORT_SCAN(ip, scanner)`: executes scanner with `-d ip` flag; extracts bracket-content from raw output
- `WEB_FINGERPRINT(url, tool)`: executes tool with `-u url` flag; extracts features from bracket-content; returns `features[0]` (primary fingerprint) or null

**Report dimensions (from paper):**
- Vulnerability similarity scores
- References to historically most similar vulnerability identifiers and descriptions
- Risk-level assessments
- Remediation suggestions

**Tools described:**
- `port-go.exe` — TCP/IP stack fingerprinting
- `server-go.exe` — Service version identification
- `finger.exe` — Web application fingerprint analyzer
- `spark-api` — AI vulnerability analysis API (used within fingerprinting stage)

**[IMPLEMENTATION DECISION]** These tools are Windows-specific executables not publicly available. The implementation uses Python-native equivalents with an adapter interface allowing `.exe` tools as optional backends.

### Stage 2: LLM-Driven Penetration Path Inference

Described in **Algorithm 2** and **Figure 3**:

**Parameters:**
```
history_repo       = "Dataset"         — Source of historical vulnerability data
embedding_model    = "Trained Model"   — Pre-trained text embedding from HuggingFace
similarity_threshold = 0.6
llm_model          = "DeepSeek"
```

**Knowledge Base Construction (offline):**
```
raw_vulns ← DOWNLOADFILES(history_repo)
For each vuln_file in raw_vulns:
    description ← EXTRACTDESCRIPTION(vuln_file)
    chunk ← CREAT_CHUNK(description)
    text_chunks.append(chunk)
For each chunk in text_chunks:
    vector ← EMBEDTEXT(chunk, embedding_model)
    embeddings.append(vector)
vector_db ← INITFAISSDB()
vector_db.add(embeddings)
```

**Query Processing (online):**
```
query_vector ← EMBEDTEXT(user_query, embedding_model)
max_similarity ← 0.0
For each vector in vector_db:
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
```

## 5. Key Technical Components

### Embedding: BGE-small-zh

**[PAPER FACT]**
> "Each text chunk is then encoded into vector representations using the BGE embedding algorithm, specifically the pretrained bge-small-zh model from HuggingFace"

**[PAPER FACT]** BGE = BERT-based General Embedding. Builds on BERT, maps text to fixed-length dense vectors.

**Mathematical formulation:**
```
T = {t₁, t₂, ..., tₙ}              — text chunks
vᵢ = BGE(tᵢ)                        — vector of each chunk

T₂ = {t₁, t₂, ..., tₘ}             — query tokens
vⱼ = BGE(tⱼ)                        — query vector
```

**[IMPLEMENTATION DECISION]** Uses `BAAI/bge-m3` instead of `bge-small-zh` to support multilingual (English + Chinese) text from Awesome-POC. Configurable via `EMBEDDING_MODEL` env var.

### FAISS Vector Database

**[PAPER FACT]**
> "All embedded vectors of vulnerability descriptions are stored in a vector database (e.g., Faiss), enabling efficient similarity-based retrieval at scale."

**[PAPER FACT]** The paper specifies FAISS for the vector database.

### Cosine Similarity

**[PAPER FACT]** Formula:
```
sim(vᵢ, vⱼ) = (vᵢ · vⱼ) / (‖vᵢ‖ · ‖vⱼ‖) = cos θ ∈ [-1, 1]
```

**[PAPER FACT]** Threshold: **0.6**
> "We set a similarity threshold of 0.6 as the decision criterion."
> "The determination of a similarity threshold of 0.6 is primarily based on practical experience in the field of information retrieval and a preliminary evaluation of the specific semantic space of this project."
> "Reference to the range of 0.5–0.7 commonly adopted in the industry for semantic similarity matching."

**[PAPER FACT]** Relevance classification:
```
BGE_is = Relevant vulnerability, if max sim(vᵢ, vⱼ) ≥ threshold
         Others, otherwise
```

**CRITICAL NOTE**: The threshold determines whether historical evidence is **relevant enough for further analysis**. It does NOT classify a vulnerability as **confirmed**.

### Prompt Construction

**[PAPER FACT]** Formula:
```
Prompt = Φ(T₂) ⊕ Ψ(T) ⊕ Γ
```
Where:
- `Φ(T₂)` = user input content (fingerprint query)
- `Ψ(T)` = historical vulnerability text with highest similarity
- `Γ` = instruction template
- `⊕` = concatenation/combination

### LLM: DeepSeek

**[PAPER FACT]**
> "This prompt is passed to an LLM—specifically, DeepSeek—to generate a comprehensive and informed response."

**[PAPER FACT]** Output includes:
- Direct answer to user's question
- Retrieved vulnerability information summary
- Professional remediation and defense strategies

### Knowledge Base: Awesome-POC

**[PAPER FACT]**
> "https://github.com/Threekiii/Awesome-POC, as an important historical vulnerability information repository, provides abundant vulnerability example data."

## 6. Experimental Results

**[PAPER FACT]**
- Hardware: Intel Core i9-13900HX, 16 GB RAM, 1 TB HDD (no GPU)
- Test dataset: 90 samples
  - 50 vulnerability data (25 Chinese + 25 English)
  - 40 non-vulnerability data (15 Chinese + 25 English)
- Overall identification accuracy: **98.89%**
- 1 piece of vulnerability data misclassified as non-vulnerability
- Non-vulnerability identification accuracy: **100%**
- Average processing time for vulnerability data: **79.04 seconds**
- Average processing time for non-vulnerability data: **9.29 seconds**

## 7. Vulnerability Distribution (from paper, 961 total)

| Category | Count | Percentage |
|----------|-------|------------|
| Weak Password | 535 | 55.61% |
| Unauthorized Access | 271 | 28.20% |
| Sensitive Info Disclosure | 57 | 5.93% |
| SQL Injection | 39 | 4.05% |
| Remote Code Execution | 37 | 3.85% |
| Token Tampering | 7 | 0.73% |

## 8. Limitations (from paper)

**[PAPER FACT]**
1. Cannot detect logical/business-flow vulnerabilities
2. Limited to authorized targets (ethical/legal requirement)
3. Data sample limited to mainland China educational websites
4. Logical vulnerabilities are more prevalent in core digital assets (key websites) — tool detects them indirectly via human review of LLM output, not automatically

## 9. Future Work (from paper)

**[PAPER FACT]**
1. Distributed vector retrieval architecture for exponential vulnerability data growth
2. Microservice-based refactoring (knowledge base, fingerprint collection, reasoning services as independent microservices)
3. Container orchestration and load balancing
4. Model quantization for reduced compute requirements
5. Edge computing node deployment
6. Deep learning tools for automated protection

## 10. Scalability (from paper)

**[PAPER FACT]**
- Decoupled architecture separates computationally intensive vectorization into offline phase
- FAISS supports efficient similarity search in multi-machine environments
- Fingerprint scanning uses concurrent port probing and service identification
- Knowledge base supports incremental updates (new vulnerabilities only need re-vectorization)
- Each system component (knowledge base, fingerprint scanning, LLM reasoning) can be independently deployed and scaled

## Ambiguities

1. **spark-api role**: The paper includes `spark-api` in Algorithm 1 (fingerprinting stage) as a per-fingerprint vulnerability analysis step. However, the primary LLM inference pipeline (Algorithm 2) uses DeepSeek. The relationship between these two is NOT fully disambiguated. **Implementation decision**: spark-api treated as an optional intermediate analysis step within fingerprinting; the clean Stage 2 RAG pipeline uses BGE + FAISS + DeepSeek.

2. **Passive monitoring specifics**: The paper mentions "hybrid collection approach that combines active probing with passive monitoring" but does not fully specify the passive monitoring implementation details.

3. **port-go.exe/server-go.exe/finger.exe**: These are research-specific custom tools not publicly available. The paper describes their command-line interfaces (`-d ip`, `-u url`) but not their internal implementation.

4. **CSV format**: The paper mentions a "structured CSV report" but does not specify the exact column schema (inferred from Algorithm 1's `service_map` structure: port, service, url, fingerprint, vulnerability).

5. **Knowledge base size**: The paper does not specify how many documents from Awesome-POC were ingested.
