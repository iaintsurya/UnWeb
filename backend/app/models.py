from typing import Literal
from pydantic import BaseModel, Field

class ScanRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    max_pages: int = Field(default=8, ge=1, le=30)

class Finding(BaseModel):
    id: str
    title: str
    severity: Literal["info", "low", "medium", "high"]
    confidence: Literal["high", "medium", "low"]
    evidence: str
    recommendation: str

class PageSummary(BaseModel):
    url: str
    status_code: int | None = None
    title: str | None = None
    links: list[str] = []
    scripts: list[str] = []
    stylesheets: list[str] = []
    images: list[str] = []
    metadata: dict[str, str] = {}

class ScanResult(BaseModel):
    id: str
    requested_url: str
    final_url: str
    status_code: int
    scanned_at: str
    title: str | None = None
    description: str | None = None
    headers: dict[str, str]
    technologies: list[dict[str, str]]
    assets: list[dict[str, str]]
    page: PageSummary
    pages: list[PageSummary] = []
    findings: list[Finding] = []
    js_analysis: list[dict[str, object]] = []
    notes: list[str] = []
    reconstruction: dict[str, str] | None = None
