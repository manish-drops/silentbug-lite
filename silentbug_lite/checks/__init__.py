"""The checks. Each one takes a parsed file and yields Findings; none of them reads other
files, runs code or touches the network."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from silentbug_lite.models import Finding, ParsedModule


class Detector(Protocol):
    id: str
    languages: frozenset[str]

    def run(self, module: ParsedModule) -> Iterable[Finding]: ...


def detectors() -> list[Detector]:
    from silentbug_lite.checks.auth import DestructiveNoAuth, UnprotectedRoute
    from silentbug_lite.checks.errors import SuccessOnException
    from silentbug_lite.checks.llm_loop import LLMCallInLoop
    from silentbug_lite.checks.secrets import HardcodedSecret
    from silentbug_lite.checks.sql import SqlInjection

    return [
        SuccessOnException(),
        SqlInjection(),
        HardcodedSecret(),
        LLMCallInLoop(),
        UnprotectedRoute(),
        DestructiveNoAuth(),
    ]
