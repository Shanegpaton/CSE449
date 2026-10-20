"""
FastAPI entrypoint for the AI Code Security Analyzer.
Run: py -3.12 -m uvicorn main:app --reload
"""
import io
import zipfile
from typing import Any, Dict, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator

import joern_engine
from analyzer import analyze, analyze_project

app = FastAPI(title="AI Code Security Analyzer")

# Lets the React dev server (localhost:5173) call this API (localhost:8000).
# TODO: tighten origins/methods before any deployment.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

SUPPORTED_LANGUAGES = {"python", "javascript"}
MAX_CODE_CHARS = 50_000
MAX_ZIP_BYTES = 2_000_000
MAX_PROJECT_FILES = 200


class AnalyzeRequest(BaseModel):
    """What the frontend sends. Bad input is rejected before analysis runs."""
    prompt: str = ""      # the prompt originally given to the AI tool
    code: str             # the AI-generated code to analyze
    language: str

    @validator("language")
    def check_language(cls, v):
        v = v.lower().strip()
        if v not in SUPPORTED_LANGUAGES:
            raise ValueError(f"language must be one of {sorted(SUPPORTED_LANGUAGES)}")
        return v

    @validator("code")
    def check_code(cls, v):
        if not v.strip():
            raise ValueError("code is empty")
        if len(v) > MAX_CODE_CHARS:
            raise ValueError(f"code exceeds {MAX_CODE_CHARS} characters")
        return v


class AnalyzeResponse(BaseModel):
    """What the backend returns. The frontend renders these sections."""
    language: str
    engine: str                       # joern | ast_fallback | pattern_scan | none
    engine_note: Optional[str] = None  # why Joern was not used, if it was not
    correctness: Dict[str, Any]
    security: Dict[str, Any]
    context_gaps: Dict[str, Any]
    hallucinations: Dict[str, Any]
    recommendation: Dict[str, Any]    # verdict, reason, action, steps, counts


@app.get("/health")
def health():
    return {"status": "ok", "joern": joern_engine.status()}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_code(req: AnalyzeRequest):
    try:
        return analyze(req.prompt, req.code, req.language)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {e}")


@app.post("/analyze-project", response_model=AnalyzeResponse)
def analyze_zip(file: UploadFile = File(...)):
    """Upload a .zip of a Python project. All .py files are analyzed together (cross-file taint needs Joern)."""
    raw = file.file.read(MAX_ZIP_BYTES + 1)
    if len(raw) > MAX_ZIP_BYTES:
        raise HTTPException(status_code=413, detail=f"zip exceeds {MAX_ZIP_BYTES} bytes")
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile:
        raise HTTPException(status_code=422, detail="file is not a valid zip")

    files, total = {}, 0
    for info in archive.infolist():
        name = info.filename.replace("\\", "/")
        parts = [p for p in name.split("/") if p]
        if info.is_dir() or not name.endswith(".py"):
            continue
        # never trust paths inside an archive
        if name.startswith("/") or ".." in parts or ":" in name or parts[0] in ("__MACOSX",):
            continue
        total += info.file_size
        if total > MAX_ZIP_BYTES * 5 or len(files) >= MAX_PROJECT_FILES:
            raise HTTPException(status_code=413, detail="project is too large")
        files["/".join(parts)] = archive.read(info).decode("utf-8", errors="replace")
    if not files:
        raise HTTPException(status_code=422, detail="zip contains no .py files")

    # drop a single wrapping folder (sample_app/routes.py -> routes.py)
    roots = {p.split("/")[0] for p in files}
    if len(roots) == 1 and all("/" in p for p in files):
        files = {p.split("/", 1)[1]: c for p, c in files.items()}
    try:
        return analyze_project(files)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {e}")
