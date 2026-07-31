"""Tespit motoru: olaylari kurallarla eslestirir ve alarm uretir."""
from __future__ import annotations

import datetime as dt
import re
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .rules import Rule

Event = Dict[str, Any]

_TS_FIELDS = (
    "_ts", "timestamp", "TimeCreated", "UtcTime", "@timestamp", "EventTime",
    "SystemTime", "time", "Event.System.TimeCreated.@SystemTime", "date",
)

_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
    "%b %d %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p",
)


def parse_timestamp(event: Event, default_year: Optional[int] = None) -> Optional[dt.datetime]:
    """Olaydan bir zaman damgasi cikarmaya calisir."""
    for field_name in _TS_FIELDS:
        raw = event.get(field_name)
        if not raw:
            continue
        text = str(raw).strip().replace("Z", "+0000")
        text = re.sub(r"([+-]\d{2}):(\d{2})$", r"\1\2", text)
        for fmt in _TS_FORMATS:
            try:
                parsed = dt.datetime.strptime(text, fmt)
            except ValueError:
                continue
            if parsed.year == 1900:
                parsed = parsed.replace(year=default_year or dt.datetime.now().year)
            return parsed.replace(tzinfo=None)
    return None


@dataclass
class Alert:
    rule_id: str
    rule_title: str
    level: str
    score: int
    timestamp: Optional[dt.datetime]
    source_file: str
    line: Optional[int]
    tags: List[str] = field(default_factory=list)
    fields: Dict[str, Any] = field(default_factory=dict)
    raw: str = ""
    count: int = 1
    kind: str = "match"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "level": self.level,
            "score": self.score,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_file": self.source_file,
            "line": self.line,
            "tags": self.tags,
            "mitre": [t for t in self.tags if t.lower().startswith("attack.")],
            "count": self.count,
            "kind": self.kind,
            "fields": self.fields,
            "raw": self.raw,
        }


# --------------------------------------------------------------------------- #
_INTERESTING = (
    "EventID", "Image", "CommandLine", "ParentImage", "ParentCommandLine",
    "TargetUserName", "SubjectUserName", "user", "src_ip", "IpAddress",
    "DestinationIp", "DestinationPort", "QueryName", "Computer", "host",
    "process", "event_type", "outcome", "TargetFilename", "ServiceName",
)


def _summary_fields(event: Event, limit: int = 8) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for name in _INTERESTING:
        value = event.get(name)
        if value not in (None, ""):
            out[name] = value
        if len(out) >= limit:
            break
    if not out:
        for key, value in event.items():
            if key.startswith("_") or value in (None, ""):
                continue
            out[key] = value
            if len(out) >= limit:
                break
    return out


class ThresholdTracker:
    """'N olay / M dakika' seklindeki korelasyon kurallarini takip eder."""

    def __init__(self, rule: Rule):
        cfg = rule.detection.get("timeframe_config") or {}
        self.rule = rule
        self.count = int(cfg.get("count") or 0)
        self.window = int(cfg.get("window_minutes") or 5)
        self.group_by = cfg.get("group_by") or "src_ip"
        if isinstance(self.group_by, str):
            self.group_by = [self.group_by]
        self.buckets: Dict[Tuple[Any, ...], deque] = defaultdict(deque)
        self.fired: set = set()

    @property
    def enabled(self) -> bool:
        return self.count > 1

    def push(self, event: Event, when: Optional[dt.datetime]) -> Optional[Alert]:
        if not self.enabled:
            return None
        key = tuple(str(event.get(g, "?")) for g in self.group_by)
        when = when or dt.datetime.now()
        bucket = self.buckets[key]
        bucket.append(when)
        cutoff = when - dt.timedelta(minutes=self.window)
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) < self.count:
            return None
        signature = (key, bucket[0])
        if signature in self.fired:
            return None
        self.fired.add(signature)
        return Alert(
            rule_id=self.rule.id,
            rule_title=f"{self.rule.title} ({len(bucket)}x / {self.window}dk)",
            level=self.rule.level,
            score=min(100, self.rule.score + 10),
            timestamp=when,
            source_file=str(event.get("_source_file", "")),
            line=event.get("_line"),
            tags=self.rule.tags,
            fields={**dict(zip(self.group_by, key)), "hit_count": len(bucket)},
            raw=str(event.get("_raw", ""))[:500],
            count=len(bucket),
            kind="threshold",
        )


@dataclass
class Result:
    alerts: List[Alert] = field(default_factory=list)
    events_scanned: int = 0
    files_scanned: int = 0
    rules_loaded: int = 0
    errors: List[str] = field(default_factory=list)

    @property
    def by_level(self) -> Counter:
        return Counter(a.level.lower() for a in self.alerts)

    @property
    def by_rule(self) -> Counter:
        return Counter(a.rule_title for a in self.alerts)

    @property
    def risk_score(self) -> int:
        """0-100 arasi genel risk skoru."""
        if not self.alerts:
            return 0
        top = sorted((a.score for a in self.alerts), reverse=True)[:10]
        base = max(top)
        volume_bonus = min(15, len(self.alerts) // 5)
        return min(100, int(base + volume_bonus))


class Engine:
    def __init__(self, rules: Iterable[Rule], dedup: bool = True):
        self.rules = list(rules)
        self.dedup = dedup
        self.trackers = {r.id: ThresholdTracker(r) for r in self.rules}

    def run(self, events: Iterable[Event]) -> Result:
        result = Result(rules_loaded=len(self.rules))
        seen: set = set()
        for event in events:
            result.events_scanned += 1
            when = parse_timestamp(event)
            for rule in self.rules:
                try:
                    hit = rule.matches(event)
                except Exception as exc:  # kural hatasi taramayi durdurmasin
                    result.errors.append(f"{rule.id}: {exc}")
                    continue
                if not hit:
                    continue

                tracker = self.trackers[rule.id]
                if tracker.enabled:
                    alert = tracker.push(event, when)
                    if alert:
                        result.alerts.append(alert)
                    continue

                fields = _summary_fields(event)
                if self.dedup:
                    signature = (rule.id, tuple(sorted(fields.items(), key=lambda kv: kv[0])))
                    signature = (signature[0], str(signature[1]))
                    if signature in seen:
                        continue
                    seen.add(signature)

                result.alerts.append(Alert(
                    rule_id=rule.id,
                    rule_title=rule.title,
                    level=rule.level,
                    score=rule.score,
                    timestamp=when,
                    source_file=str(event.get("_source_file", "")),
                    line=event.get("_line"),
                    tags=rule.tags,
                    fields=fields,
                    raw=str(event.get("_raw", ""))[:500],
                ))
        result.alerts.sort(key=lambda a: (-a.score, a.timestamp or dt.datetime.min))
        return result
