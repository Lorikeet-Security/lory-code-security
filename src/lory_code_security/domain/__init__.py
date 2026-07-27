"""The problem domain: findings, Lory's block format, code mapping, remediation."""

from lory_code_security.domain.blocks import Block, parse_blocks, validate_reply
from lory_code_security.domain.codebase import CodeMatch, build_plan, locate
from lory_code_security.domain.findings import (
    Finding,
    FindingStore,
    TriageLog,
    filter_findings,
    severity_counts,
    sort_findings,
)
from lory_code_security.domain.remediate import RemediationRequest, build_prompt

__all__ = [
    "Block",
    "CodeMatch",
    "Finding",
    "FindingStore",
    "RemediationRequest",
    "TriageLog",
    "build_plan",
    "build_prompt",
    "filter_findings",
    "locate",
    "parse_blocks",
    "severity_counts",
    "sort_findings",
    "validate_reply",
]
