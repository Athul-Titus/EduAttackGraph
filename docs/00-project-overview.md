# Project Overview: LLM-EduAttackGraph

## What This Is

LLM-EduAttackGraph is a **human-in-the-loop security vulnerability analysis platform** that implements the research methodology from:

> Liu et al., "LLM-Assisted Security Vulnerability Analysis for Educational Websites: Risk Identification via LLM-EduAttackGraph," *IEEE Internet of Things Journal*, Vol. 13, No. 2, 2026.

## Purpose

To provide a **defensive, advisory** security analysis tool that:
1. Fingerprints an authorized target web application
2. Retrieves relevant historical vulnerability knowledge (Awesome-POC)
3. Uses an LLM to infer potential penetration paths
4. Presents findings to a human security analyst for validation

## What This Is NOT

- Not an autonomous exploitation tool
- Not a vulnerability scanner that auto-confirms findings
- Not a tool for unauthorized use against arbitrary internet targets
- Not a penetration testing tool without human oversight

## Core Philosophy (from paper)

> "LLM-EduAttackGraph does not pursue fully automated attacks; instead, it is positioned as an intelligent auxiliary analysis system, which maintains high targeting while achieving low resource consumption, inherent defense orientation, and a clear, traceable decision-making process."

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Human-in-the-loop | LLM output is INFERRED, not confirmed |
| Offline knowledge base + online reasoning | Reduces online compute cost (paper's core design) |
| Cosine similarity threshold 0.6 | Paper's empirically calibrated default |
| BGE-m3 embeddings | Multilingual; paper uses bge-small-zh |
| FAISS vector database | Paper's choice for efficient similarity search |
| DeepSeek primary LLM | Paper's choice |

## Evidence Classification

Every piece of information in the system is labeled:

| Label | Meaning |
|-------|---------|
| OBSERVED | Directly obtained from TCP/HTTP reconnaissance |
| RETRIEVED | From Awesome-POC knowledge base via RAG |
| INFERRED | LLM-generated analysis (not confirmed) |
| VALIDATED | Reviewed and accepted by human analyst |

## Vulnerability Categories

The paper identifies six categories common to educational websites:

| Code | Name |
|------|------|
| O1 | Remote Code Execution |
| O2 | SQL Injection |
| O3 | Weak Password |
| O4 | Unauthorized Access |
| O5 | Token Tampering |
| O6 | Sensitive Information Disclosure |
