"""Small dependency-light RAG store for authorized security testing.

It accepts PDF, Markdown, text and HTML sources, persists chunks as JSON, and
uses a deterministic TF-IDF-style lexical retriever.  An embedding provider is
intentionally not required, so scans remain usable offline and reproducible.
Retrieved text is advisory context only; it never authorizes a request.
"""
from __future__ import annotations

import html
import json
import math
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

TOKEN_RE = re.compile(r"[a-zA-Z0-9_./:-]{2,}")
TEXT_EXTENSIONS = {".txt", ".md", ".markdown", ".html", ".htm", ".rst", ".log"}


@dataclass
class KnowledgeChunk:
    id: str
    source: str
    text: str
    section: str = ""


@dataclass
class KnowledgeHit:
    chunk: KnowledgeChunk
    score: float


class KnowledgeBase:
    def __init__(self, path: str | Path = "data/knowledge/index.json", chunk_size: int = 1200, overlap: int = 180):
        self.path = Path(path)
        self.chunk_size = max(300, int(chunk_size))
        self.overlap = max(0, min(int(overlap), self.chunk_size // 2))
        self.chunks: list[KnowledgeChunk] = []
        self._df: Counter[str] = Counter()
        self._loaded = False

    def load(self) -> int:
        if not self.path.exists():
            self._loaded = True
            return 0
        try:
            rows = json.loads(self.path.read_text(encoding="utf-8"))
            self.chunks = [KnowledgeChunk(**row) for row in rows if isinstance(row, dict) and row.get("text")]
            self._reindex()
        except (OSError, ValueError, TypeError):
            self.chunks = []
        self._loaded = True
        return len(self.chunks)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps([asdict(c) for c in self.chunks], ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.path)

    def ingest(self, paths: str | Path | Iterable[str | Path]) -> int:
        if isinstance(paths, (str, Path)):
            paths = [paths]
        added: list[KnowledgeChunk] = []
        for raw in paths:
            path = Path(raw)
            files = [path] if path.is_file() else [p for p in path.rglob("*") if p.is_file()] if path.is_dir() else []
            for file in files:
                text = self._extract(file)
                if not text.strip():
                    continue
                # Replace chunks from the same source to make re-ingestion idempotent.
                self.chunks = [c for c in self.chunks if c.source != str(file)]
                for i, chunk in enumerate(self._chunk(text)):
                    added.append(KnowledgeChunk(f"{file}:{i}", str(file), chunk))
        self.chunks.extend(added)
        self._reindex()
        self.save()
        self._loaded = True
        return len(added)

    def search(self, query: str, top_k: int = 5, min_score: float = 0.03) -> list[KnowledgeHit]:
        if not self._loaded:
            self.load()
        q = self._tokens(query)
        if not q or not self.chunks:
            return []
        scores: list[KnowledgeHit] = []
        n = len(self.chunks)
        for chunk in self.chunks:
            tokens = self._tokens(chunk.text)
            if not tokens:
                continue
            tf = Counter(tokens)
            dot = norm_a = norm_b = 0.0
            for token in set(q) | set(tokens):
                weight = math.log((n + 1) / (self._df.get(token, 0) + 1)) + 1
                a, b = q.count(token) * weight, tf[token] * weight
                dot += a * b; norm_a += a * a; norm_b += b * b
            score = dot / math.sqrt(norm_a * norm_b) if norm_a and norm_b else 0.0
            if score >= min_score:
                scores.append(KnowledgeHit(chunk, round(score, 4)))
        scores.sort(key=lambda h: h.score, reverse=True)
        return scores[:max(1, int(top_k))]

    def context(self, query: str, top_k: int = 4, max_chars: int = 5000) -> list[dict]:
        out, used = [], 0
        for hit in self.search(query, top_k):
            text = hit.chunk.text[: max(0, max_chars - used)]
            if not text:
                break
            out.append({"source": hit.chunk.source, "score": hit.score, "text": text})
            used += len(text)
        return out

    def _reindex(self) -> None:
        self._df = Counter()
        for chunk in self.chunks:
            self._df.update(set(self._tokens(chunk.text)))

    @staticmethod
    def _tokens(text: str) -> list[str]:
        return [t.lower() for t in TOKEN_RE.findall(text or "")]

    def _chunk(self, text: str) -> list[str]:
        text = re.sub(r"\n{3,}", "\n\n", text).strip()
        step = self.chunk_size - self.overlap
        return [text[i:i + self.chunk_size] for i in range(0, len(text), step)]

    @staticmethod
    def _extract(path: Path) -> str:
        try:
            if path.suffix.lower() == ".pdf":
                try:
                    from pypdf import PdfReader
                    return "\n".join(page.extract_text() or "" for page in PdfReader(str(path)).pages)
                except (ImportError, OSError, ValueError):
                    return ""
            raw = path.read_text(encoding="utf-8", errors="ignore") if path.suffix.lower() in TEXT_EXTENSIONS else ""
            if path.suffix.lower() in {".html", ".htm"}:
                raw = re.sub(r"<script[\s\S]*?</script>|<style[\s\S]*?</style>|<[^>]+>", " ", raw, flags=re.I)
                raw = html.unescape(raw)
            return raw
        except OSError:
            return ""
