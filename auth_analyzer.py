#!/usr/bin/env python3
"""Analyze authentication logs for explainable suspicious activity."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable, TextIO


SSH_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}(?:\s+\d{4})?\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+"
    r"(?P<event>Failed password|Accepted password|Invalid user)"
    r"(?: for (?:invalid user )?(?P<user>\S+))? from (?P<source>\S+)"
)
GENERIC_PATTERN = re.compile(
    r"^(?P<timestamp>\S+T\S+)\s+(?P<event>LOGIN_FAILED|LOGIN_SUCCESS|AUTH_FAILURE)\s+"
    r"user=(?P<user>\S+)\s+ip=(?P<source>\S+)"
)


@dataclass(frozen=True)
class AuthEvent:
    """Represents a single parsed authentication event.

    Attributes:
        timestamp: When the event occurred.
        event: Event category, either ``"success"`` or ``"failure"``.
        user: The username associated with the login attempt.
        source: The remote IP or hostname from which the event originated.
        raw: The original log line used to generate the event.
    """

    timestamp: datetime
    event: str
    user: str
    source: str
    raw: str


@dataclass(frozen=True)
class Alert:
    """A security finding generated from a sequence of auth events.

    Attributes:
        rule: The detection rule name that produced the alert.
        severity: Severity label such as ``"high"`` or ``"medium"``.
        timestamp: ISO-formatted time when the alert was raised.
        user: Account associated with the alert.
        source: Source IP or host involved in the activity.
        message: Human-readable summary of the suspicious behavior.
        evidence: Raw log lines used as supporting evidence.
    """

    rule: str
    severity: str
    timestamp: str
    user: str
    source: str
    message: str
    evidence: list[str]


def parse_timestamp(value: str, reference_year: int) -> datetime:
    """Parse a syslog or ISO timestamp into a ``datetime``.

    SSH log timestamps may be written in either ISO-8601 format or syslog format
    without a year. For syslog entries, the provided ``reference_year`` is used as
    a fallback so the timestamp can be normalized consistently.

    Args:
        value: The timestamp string from the log line.
        reference_year: Year to use when parsing syslog timestamps without a year.

    Returns:
        A timezone-aware or naive ``datetime`` object representing the event.

    Raises:
        ValueError: If the timestamp format is unsupported.
    """

    if value.count(" ") >= 2 and len(value.split()) == 3:
        month, day, time_str = value.split()
        value = f"{month} {day} {reference_year} {time_str}"
    formats = ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%b %d %Y %H:%M:%S")
    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise ValueError(f"unsupported timestamp: {value}")


def parse_line(line: str, reference_year: int) -> AuthEvent | None:
    """Parse a single authentication log line into an :class:`AuthEvent`.

    Supported formats include standard SSHd auth lines and a simplified generic
    format used for testing or log normalization.

    Args:
        line: A single line from an authentication log.
        reference_year: Year used when the timestamp does not include one.

    Returns:
        An ``AuthEvent`` if the line matches a supported format; otherwise ``None``.
    """

    line = line.strip()
    if not line:
        return None
    match = SSH_PATTERN.match(line) or GENERIC_PATTERN.match(line)
    if not match:
        return None
    data = match.groupdict()
    raw_event = data["event"]
    event = "success" if raw_event in {"Accepted password", "LOGIN_SUCCESS"} else "failure"
    return AuthEvent(
        timestamp=parse_timestamp(data["timestamp"], reference_year),
        event=event,
        user=data.get("user") or "unknown",
        source=data["source"],
        raw=line,
    )


def analyze(events: Iterable[AuthEvent], threshold: int = 5, window_minutes: int = 10) -> list[Alert]:
    """Analyze a sequence of authentication events and return suspicious activity alerts.

    The detector looks for bursts of failures from the same source or against the
    same account, as well as suspicious successful logins following recent failures
    or source changes.

    Args:
        events: Authentication events to inspect, in any order.
        threshold: Minimum failure count needed to trigger a stronger alert.
        window_minutes: Time window used to evaluate repeated login activity.

    Returns:
        A list of :class:`Alert` objects describing suspicious activity.
    """

    ordered = sorted(events, key=lambda item: item.timestamp)
    failures_by_source: dict[str, deque[AuthEvent]] = defaultdict(deque)
    failures_by_user: dict[str, deque[AuthEvent]] = defaultdict(deque)
    last_success_source: dict[str, str] = {}
    alerts: list[Alert] = []
    window = timedelta(minutes=window_minutes)
    alerted_sources: set[tuple[str, datetime]] = set()
    brute_force_sources: set[tuple[str, datetime]] = set()
    alerted_users: set[tuple[str, datetime]] = set()
    targeted_users: set[tuple[str, datetime]] = set()
    failure_floor = max(2, min(threshold, 3))

    for event in ordered:
        if event.event == "failure":
            source_failures = failures_by_source[event.source]
            user_failures = failures_by_user[event.user]
            source_failures.append(event)
            user_failures.append(event)
            cutoff = event.timestamp - window
            while source_failures and source_failures[0].timestamp < cutoff:
                source_failures.popleft()
            while user_failures and user_failures[0].timestamp < cutoff:
                user_failures.popleft()

            if len(source_failures) >= failure_floor:
                key = (event.source, source_failures[0].timestamp)
                if key not in alerted_sources:
                    alerted_sources.add(key)
                    alerts.append(Alert(
                        rule="multiple_failed_login_attempts",
                        severity="medium",
                        timestamp=event.timestamp.isoformat(),
                        user=event.user,
                        source=event.source,
                        message=f"{len(source_failures)} failed logins from {event.source} within {window_minutes} minutes",
                        evidence=[item.raw for item in source_failures],
                    ))

            if len(source_failures) >= threshold:
                key = (event.source, source_failures[0].timestamp)
                if key not in brute_force_sources:
                    brute_force_sources.add(key)
                    alerts.append(Alert(
                        rule="brute_force_source",
                        severity="high",
                        timestamp=event.timestamp.isoformat(),
                        user=event.user,
                        source=event.source,
                        message=f"{len(source_failures)} failed logins from {event.source} within {window_minutes} minutes",
                        evidence=[item.raw for item in source_failures],
                    ))
            if len(user_failures) >= failure_floor:
                key = (event.user, user_failures[0].timestamp)
                if key not in alerted_users:
                    alerted_users.add(key)
                    alerts.append(Alert(
                        rule="multiple_failed_login_attempts",
                        severity="medium",
                        timestamp=event.timestamp.isoformat(),
                        user=event.user,
                        source=event.source,
                        message=f"{len(user_failures)} failed login attempts targeting {event.user} within {window_minutes} minutes",
                        evidence=[item.raw for item in user_failures],
                    ))
            if len(user_failures) >= threshold:
                key = (event.user, user_failures[0].timestamp)
                if key not in targeted_users:
                    targeted_users.add(key)
                    alerts.append(Alert(
                        rule="targeted_account_attack",
                        severity="medium",
                        timestamp=event.timestamp.isoformat(),
                        user=event.user,
                        source=event.source,
                        message=f"{len(user_failures)} failed logins targeting account {event.user} within {window_minutes} minutes",
                        evidence=[item.raw for item in user_failures],
                    ))
        else:
            previous_source = last_success_source.get(event.user)
            if previous_source and previous_source != event.source:
                alerts.append(Alert(
                    rule="successful_login_from_new_source",
                    severity="medium",
                    timestamp=event.timestamp.isoformat(),
                    user=event.user,
                    source=event.source,
                    message=f"Successful login for {event.user} changed source from {previous_source} to {event.source}",
                    evidence=[f"previous source: {previous_source}", event.raw],
                ))
            last_success_source[event.user] = event.source
            recent_failures = failures_by_user[event.user]
            cutoff = event.timestamp - window
            recent_failures = deque(item for item in recent_failures if item.timestamp >= cutoff)
            if recent_failures:
                alerts.append(Alert(
                    rule="success_after_failures",
                    severity="high",
                    timestamp=event.timestamp.isoformat(),
                    user=event.user,
                    source=event.source,
                    message=f"Successful login followed {len(recent_failures)} recent failures for {event.user}",
                    evidence=[item.raw for item in recent_failures] + [event.raw],
                ))
                failures_by_user[event.user] = recent_failures
    return alerts


def read_events(stream: TextIO, reference_year: int) -> tuple[list[AuthEvent], int]:
    """Read and parse authentication events from a text stream.

    Args:
        stream: Open file-like object containing log lines.
        reference_year: Year used to normalize syslog timestamps without a year.

    Returns:
        A tuple of ``(events, ignored_lines)`` where ``events`` contains all parsed
        authentication events and ``ignored_lines`` counts unsupported lines.
    """

    events: list[AuthEvent] = []
    ignored = 0
    for line in stream:
        try:
            event = parse_line(line, reference_year)
        except ValueError:
            event = None
        if event:
            events.append(event)
        elif line.strip():
            ignored += 1
    return events, ignored


def main() -> int:
    """Entry point for the CLI.

    Parses command-line arguments, reads the log file, runs the security checks,
    and prints either a human-readable summary or JSON output.

    Returns:
        Always 0 for successful execution.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logfile", type=Path, help="Authentication log file, or '-' for stdin")
    parser.add_argument("--threshold", type=int, default=5, help="Failures needed to trigger an alert (default: 5)")
    parser.add_argument("--window", type=int, default=10, help="Detection window in minutes (default: 10)")
    parser.add_argument("--year", type=int, default=datetime.now().year, help="Year for syslog timestamps")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Emit machine-readable JSON")
    args = parser.parse_args()
    if args.threshold < 2 or args.window < 1:
        parser.error("--threshold must be at least 2 and --window must be positive")

    if str(args.logfile) == "-":
        events, ignored = read_events(sys.stdin, args.year)
    else:
        try:
            with args.logfile.open(encoding="utf-8") as stream:
                events, ignored = read_events(stream, args.year)
        except OSError as exc:
            parser.error(str(exc))

    alerts = analyze(events, args.threshold, args.window)
    if args.as_json:
        print(json.dumps({"events": len(events), "ignored_lines": ignored, "alerts": [asdict(alert) for alert in alerts]}, indent=2))
    else:
        print(f"Parsed {len(events)} authentication events; ignored {ignored} lines.")
        if not alerts:
            print("No suspicious activity detected.")
        for alert in alerts:
            print(f"[{alert.severity.upper()}] {alert.rule}: {alert.message}")
            print(f"  user={alert.user} source={alert.source} at={alert.timestamp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
