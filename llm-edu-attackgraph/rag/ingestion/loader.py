"""
Knowledge Base Ingestion for LLM-EduAttackGraph

Paper: "https://github.com/Threekiii/Awesome-POC, as an important historical
       vulnerability information repository, provides abundant vulnerability
       example data."

Algorithm 2 (Offline Phase):
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
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

from app.config import settings


# ==============================================================================
# Data Classes
# ==============================================================================

@dataclass
class DocumentMetadata:
    """Metadata extracted from a vulnerability document."""
    source: str
    source_path: str
    title: Optional[str] = None
    category: Optional[str] = None
    technology: Optional[str] = None
    framework: Optional[str] = None
    version_affected: Optional[str] = None
    cve_id: Optional[str] = None
    reference_url: Optional[str] = None


@dataclass
class ParsedDocument:
    """A parsed vulnerability document."""
    metadata: DocumentMetadata
    description: str
    remediation: Optional[str] = None
    content_hash: str = ""

    def __post_init__(self):
        self.content_hash = hashlib.sha256(
            self.description.encode("utf-8")
        ).hexdigest()


@dataclass
class TextChunk:
    """A text chunk ready for embedding."""
    text: str
    chunk_position: int
    document_metadata: DocumentMetadata
    chunk_id: str = ""

    def __post_init__(self):
        self.chunk_id = hashlib.sha256(
            f"{self.document_metadata.source_path}_{self.chunk_position}_{self.text[:50]}".encode()
        ).hexdigest()[:16]


# ==============================================================================
# Document Loader
# ==============================================================================

class AwesomePOCLoader:
    """
    Loads and parses Awesome-POC repository markdown files.

    Awesome-POC structure:
    - Root README.md (index)
    - Subdirectories by vulnerability type
    - Each file is a markdown document describing one vulnerability
    """

    # Map Awesome-POC directory names to paper's categories
    CATEGORY_MAP = {
        "RCE": "O1_RCE",
        "远程代码执行": "O1_RCE",
        "SQL": "O2_SQL_INJECTION",
        "SQL注入": "O2_SQL_INJECTION",
        "弱密码": "O3_WEAK_PASSWORD",
        "未授权访问": "O4_UNAUTHORIZED",
        "Unauthorized": "O4_UNAUTHORIZED",
        "Token": "O5_TOKEN_TAMPERING",
        "信息泄露": "O6_INFO_DISCLOSURE",
        "Information": "O6_INFO_DISCLOSURE",
    }

    def __init__(self, repo_path: str):
        self.repo_path = repo_path

    def load_all(self) -> Iterator[ParsedDocument]:
        """Iterate over all parsed documents in the Awesome-POC repository."""
        if not os.path.exists(self.repo_path):
            raise FileNotFoundError(
                f"Awesome-POC repository not found at '{self.repo_path}'. "
                "Run: git clone https://github.com/Threekiii/Awesome-POC.git "
                f"'{self.repo_path}'"
            )

        for root, dirs, files in os.walk(self.repo_path):
            # Skip hidden directories and git
            dirs[:] = [d for d in dirs if not d.startswith(".")]

            for filename in files:
                if not filename.endswith(".md"):
                    continue
                if filename.lower() in ("readme.md", "contributing.md", "license.md"):
                    continue

                filepath = os.path.join(root, filename)
                relative_path = os.path.relpath(filepath, self.repo_path)

                try:
                    doc = self._parse_file(filepath, relative_path)
                    if doc and len(doc.description) > 50:  # Skip trivially short files
                        yield doc
                except Exception:
                    continue

    def _parse_file(self, filepath: str, relative_path: str) -> Optional[ParsedDocument]:
        """Parse a single Awesome-POC markdown file."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            return None

        if not content.strip():
            return None

        # Extract metadata
        title = self._extract_title(content, filepath)
        category = self._infer_category(relative_path, content)
        technology = self._extract_technology(content, filepath)
        cve_id = self._extract_cve(content)
        version = self._extract_version(content)

        metadata = DocumentMetadata(
            source="awesome-poc",
            source_path=relative_path,
            title=title,
            category=category,
            technology=technology,
            cve_id=cve_id,
            version_affected=version,
        )

        # Extract description (main content)
        description = self._extract_description(content)
        remediation = self._extract_remediation(content)

        return ParsedDocument(
            metadata=metadata,
            description=description,
            remediation=remediation,
        )

    def _extract_title(self, content: str, filepath: str) -> str:
        """Extract document title from markdown h1."""
        match = re.search(r'^#\s+(.+)', content, re.MULTILINE)
        if match:
            return match.group(1).strip()
        # Fall back to filename
        return os.path.splitext(os.path.basename(filepath))[0]

    def _infer_category(self, relative_path: str, content: str) -> Optional[str]:
        """Infer vulnerability category from path and content."""
        # Check path components
        parts = relative_path.replace("\\", "/").split("/")
        for part in parts:
            for keyword, category in self.CATEGORY_MAP.items():
                if keyword.lower() in part.lower():
                    return category

        # Check content
        content_lower = content.lower()
        if any(k in content_lower for k in ["remote code execution", "rce", "命令执行", "代码执行"]):
            return "O1_RCE"
        if any(k in content_lower for k in ["sql injection", "sql注入", "sqli"]):
            return "O2_SQL_INJECTION"
        if any(k in content_lower for k in ["weak password", "default password", "弱密码"]):
            return "O3_WEAK_PASSWORD"
        if any(k in content_lower for k in ["unauthorized", "未授权", "unauthenticated"]):
            return "O4_UNAUTHORIZED"
        if any(k in content_lower for k in ["token", "jwt", "session"]):
            return "O5_TOKEN_TAMPERING"
        if any(k in content_lower for k in ["information disclosure", "信息泄露", "sensitive"]):
            return "O6_INFO_DISCLOSURE"

        return "UNKNOWN"

    def _extract_technology(self, content: str, filepath: str) -> Optional[str]:
        """Extract technology name from content or filename."""
        filename = os.path.basename(filepath)
        # Common technology patterns in Awesome-POC filenames
        tech_patterns = [
            r"(Apache\s+\w+)", r"(Log4[jJ]\w*)", r"(Spring\s*Boot)", r"(Spring\s*Cloud)",
            r"(Shiro\w*)", r"(Struts\s*2)", r"(Nacos)", r"(Druid)", r"(FastJSON)",
            r"(ThinkPHP)", r"(Laravel)", r"(WordPress)", r"(Joomla)", r"(Drupal)",
            r"(Django)", r"(RuoYi)", r"(MinIO)", r"(Elasticsearch)", r"(Redis)",
            r"(MySQL)", r"(PostgreSQL)", r"(MongoDB)", r"(Kibana)", r"(Jenkins)",
        ]
        for pattern in tech_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
            match = re.search(pattern, filename, re.IGNORECASE)
            if match:
                return match.group(1)

        # Try to get from first heading
        title_match = re.search(r'^#\s+(.+)', content, re.MULTILINE)
        if title_match:
            title = title_match.group(1)
            # Take first 2 words as tech identifier
            words = title.split()
            if words:
                return " ".join(words[:2])
        return None

    def _extract_cve(self, content: str) -> Optional[str]:
        """Extract CVE ID from content."""
        match = re.search(r'CVE-\d{4}-\d+', content, re.IGNORECASE)
        return match.group(0).upper() if match else None

    def _extract_version(self, content: str) -> Optional[str]:
        """Extract version information from content."""
        patterns = [
            r'版本[：:]\s*([\d.x, ]+)',
            r'version[s]?[：:]\s*([\d.x, ]+)',
            r'affected versions?[：:]\s*([\d.x, ]+)',
        ]
        for p in patterns:
            match = re.search(p, content, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None

    def _extract_description(self, content: str) -> str:
        """
        Extract the description/body from markdown content.
        Paper: EXTRACTDESCRIPTION(vuln_file)
        """
        # Remove YAML frontmatter if present
        content = re.sub(r'^---\n.*?\n---\n', '', content, flags=re.DOTALL)

        # Remove title
        content = re.sub(r'^#\s+.+\n', '', content, count=1, flags=re.MULTILINE)

        # Remove HTML tags
        content = re.sub(r'<[^>]+>', '', content)

        # Normalize whitespace
        content = re.sub(r'\n{3,}', '\n\n', content)
        content = content.strip()

        return content

    def _extract_remediation(self, content: str) -> Optional[str]:
        """Extract remediation section from markdown."""
        patterns = [
            r'##\s*(?:修复|修复建议|remediation|fix|solution|缓解)[^\n]*\n(.*?)(?=\n##|\Z)',
        ]
        for p in patterns:
            match = re.search(p, content, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1).strip()
        return None


# ==============================================================================
# Text Chunker
# ==============================================================================

class TextChunker:
    """
    Splits documents into text chunks for embedding.
    Paper: "text chunking technology to disassemble each vulnerability example
           into independent text units"

    Parameters:
        chunk_size: Maximum tokens per chunk (paper doesn't specify; we use 512)
        chunk_overlap: Token overlap between chunks (we use 50)
    """

    def __init__(
        self,
        chunk_size: int = None,
        chunk_overlap: int = None,
    ):
        self.chunk_size = chunk_size or settings.CHUNK_SIZE
        self.chunk_overlap = chunk_overlap or settings.CHUNK_OVERLAP

    def chunk_document(self, doc: ParsedDocument) -> List[TextChunk]:
        """Split a parsed document into text chunks."""
        text = doc.description
        if not text:
            return []

        chunks = self._split_text(text)
        result = []
        for i, chunk_text in enumerate(chunks):
            result.append(TextChunk(
                text=chunk_text,
                chunk_position=i,
                document_metadata=doc.metadata,
            ))

        return result

    def _split_text(self, text: str) -> List[str]:
        """
        Split text into chunks with overlap.
        Uses sentence-aware splitting to avoid cutting mid-sentence.
        """
        # Estimate 4 chars per token (rough approximation)
        char_limit = self.chunk_size * 4
        overlap_chars = self.chunk_overlap * 4

        if len(text) <= char_limit:
            return [text]

        chunks = []
        start = 0

        while start < len(text):
            end = start + char_limit

            if end >= len(text):
                chunks.append(text[start:].strip())
                break

            # Try to split at sentence boundary
            split_point = self._find_split_point(text, end)
            chunks.append(text[start:split_point].strip())
            start = max(start + 1, split_point - overlap_chars)

        return [c for c in chunks if len(c) > 20]  # Filter trivially small chunks

    def _find_split_point(self, text: str, desired_end: int) -> int:
        """Find a good split point near desired_end (sentence boundary)."""
        # Look back for sentence end
        search_start = max(0, desired_end - 200)
        search_text = text[search_start:desired_end]

        # Sentence endings: period, ?, !, newline
        for pattern in [r'\.\s', r'\n\n', r'\?\s', r'!\s', r'\n']:
            matches = list(re.finditer(pattern, search_text))
            if matches:
                last_match = matches[-1]
                return search_start + last_match.end()

        return desired_end


# ==============================================================================
# Knowledge Base Manager
# ==============================================================================

class KnowledgeBaseManager:
    """
    Manages the complete knowledge base ingestion pipeline.

    Offline phase from Algorithm 2:
    1. Load documents from Awesome-POC
    2. Extract descriptions
    3. Chunk text
    4. (Embedding done separately in build_faiss_index.py)
    """

    def __init__(
        self,
        source: str = "awesome-poc",
        repo_path: Optional[str] = None,
    ):
        self.source = source
        self.repo_path = repo_path or settings.AWESOME_POC_LOCAL_PATH

    def load_and_chunk(self) -> Tuple[List[ParsedDocument], List[TextChunk]]:
        """
        Load all documents and produce text chunks.
        Returns (documents, chunks) pair.
        """
        loader = AwesomePOCLoader(self.repo_path)
        chunker = TextChunker()

        all_docs = []
        all_chunks = []

        for doc in loader.load_all():
            all_docs.append(doc)
            chunks = chunker.chunk_document(doc)
            all_chunks.extend(chunks)

        return all_docs, all_chunks

    def clone_awesome_poc(self) -> None:
        """
        Clone the Awesome-POC repository if not present.
        """
        import subprocess

        if os.path.exists(self.repo_path):
            return

        os.makedirs(os.path.dirname(self.repo_path) or ".", exist_ok=True)
        subprocess.run(
            ["git", "clone", settings.AWESOME_POC_REPO, self.repo_path],
            check=True,
        )
