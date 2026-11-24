from typing import Literal
from pydantic import BaseModel, Field, field_validator


class ScanRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    max_pages: int = Field(default=8, ge=1, le=30)
    authorised: bool = False
    scope_paths: list[str] = Field(default_factory=lambda: ["/"], min_length=1, max_length=20)

    target_id: str | None = Field(default=None, max_length=64)


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
    links: list[str] = Field(default_factory=list)
    scripts: list[str] = Field(default_factory=list)
    stylesheets: list[str] = Field(default_factory=list)
    images: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)


class PageEdge(BaseModel):
    source: str
    target: str


class ScanResult(BaseModel):
    id: str
    requested_url: str
    final_url: str
    scope_paths: list[str] = Field(default_factory=lambda: ["/"])
    status_code: int
    scanned_at: str
    title: str | None = None
    description: str | None = None
    headers: dict[str, str]
    technologies: list[dict[str, str]]
    assets: list[dict[str, str]]
    page: PageSummary
    pages: list[PageSummary] = Field(default_factory=list)
    edges: list[PageEdge] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    security_findings: list[dict[str, object]] = Field(default_factory=list)
    js_analysis: list[dict[str, object]] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    reconstruction: dict[str, str] | None = None



class GitHubRepositoryScanRequest(BaseModel):
    repository_url: str = Field(min_length=15, max_length=2048)
    ref: str | None = Field(default=None, max_length=255)
    authorised: bool = False


class DependencyAdvisoryRequest(BaseModel):
    authorised: bool = False
    packages: list[dict[str, str]] = Field(min_length=1, max_length=100)


class TargetAuthorizationChallengeRequest(BaseModel):
    hostname: str = Field(min_length=3, max_length=253)
    ports: list[int] = Field(default_factory=lambda: [443, 80], min_length=1, max_length=10)
    scope_paths: list[str] = Field(default_factory=lambda: ["/"], min_length=1, max_length=20)

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, ports: list[int]) -> list[int]:
        if any(port < 1 or port > 65535 for port in ports):
            raise ValueError("Ports must be between 1 and 65535.")
        return list(dict.fromkeys(ports))