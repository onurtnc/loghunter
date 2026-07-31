"""Farkli log formatlarini ortak bir olay sozlugune ceviren parser'lar."""
from __future__ import annotations

import csv
import json
import os
import re
from typing import Any, Dict, Iterator, List, Optional

Event = Dict[str, Any]

_SYSLOG_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>[\w\-/.]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)

_AUTH_PATTERNS = [
    (re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)"),
     {"event_type": "ssh_failed_login", "outcome": "failure"}),
    (re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)"),
     {"event_type": "ssh_successful_login", "outcome": "success"}),
    (re.compile(r"Invalid user (?P<user>\S+) from (?P<src_ip>\S+)"),
     {"event_type": "ssh_invalid_user", "outcome": "failure"}),
    (re.compile(r"session opened for user (?P<user>\S+)"),
     {"event_type": "session_opened", "outcome": "success"}),
    (re.compile(r"sudo:\s+(?P<user>\S+).*COMMAND=(?P<command>.+)$"),
     {"event_type": "sudo_command", "outcome": "success"}),
    (re.compile(r"authentication failure.*ruser=.*rhost=(?P<src_ip>\S*)\s+user=(?P<user>\S+)"),
     {"event_type": "pam_auth_failure", "outcome": "failure"}),
]


# --------------------------------------------------------------------------- #
def _flatten(obj: Any, prefix: str = "", out: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Ic ice JSON'u 'a.b.c' anahtarlarina duzler, yapraklari da kisa adla ekler."""
    if out is None:
        out = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            new_prefix = f"{prefix}.{key}" if prefix else str(key)
            _flatten(value, new_prefix, out)
    elif isinstance(obj, list):
        if all(not isinstance(i, (dict, list)) for i in obj):
            out[prefix] = obj
        else:
            for idx, item in enumerate(obj):
                _flatten(item, f"{prefix}.{idx}", out)
    else:
        out[prefix] = obj
        short = prefix.split(".")[-1]
        out.setdefault(short, obj)
    return out


def _normalize_windows(event: Event) -> Event:
    """Sysmon / Windows Security JSON ciktilarini standart alanlara tasir."""
    data = event.get("EventData")
    if isinstance(data, dict):
        for key, value in data.items():
            event.setdefault(key, value)
    # evtx_dump / winlogbeat tarzi 'Event.EventData.Data' listesi
    raw_data = event.get("Event.EventData.Data")
    if isinstance(raw_data, list):
        for item in raw_data:
            if isinstance(item, dict) and "@Name" in item:
                event.setdefault(item["@Name"], item.get("#text"))

    channel = str(event.get("Channel") or event.get("Event.System.Channel") or "")
    if "Sysmon" in channel:
        event.setdefault("_product", "windows")
        event.setdefault("_service", "sysmon")
    elif "Security" in channel:
        event.setdefault("_product", "windows")
        event.setdefault("_service", "security")
    elif "PowerShell" in channel:
        event.setdefault("_product", "windows")
        event.setdefault("_service", "powershell")
    elif channel:
        event.setdefault("_product", "windows")
        event.setdefault("_service", channel.lower())
    return event


# --------------------------------------------------------------------------- #
def parse_json(path: str) -> Iterator[Event]:
    """JSON array veya JSON Lines (ndjson) dosyasi."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        head = fh.read(2048)
        fh.seek(0)
        stripped = head.lstrip()
        if stripped.startswith("["):
            try:
                records = json.load(fh)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}: gecersiz JSON ({exc})") from exc
            for record in records:
                yield _post(record, path)
            return
        for line_no, line in enumerate(fh, 1):
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            record.setdefault("_line", line_no)
            yield _post(record, path)


def _post(record: Any, path: str) -> Event:
    if not isinstance(record, dict):
        record = {"message": record}
    event = _flatten(record)
    event["_raw"] = json.dumps(record, ensure_ascii=False)[:4000]
    event["_source_file"] = os.path.basename(path)
    return _normalize_windows(event)


def parse_syslog(path: str) -> Iterator[Event]:
    """Linux auth.log / syslog satirlari."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line_no, raw in enumerate(fh, 1):
            raw = raw.rstrip("\n")
            if not raw.strip():
                continue
            event: Event = {
                "_raw": raw, "_line": line_no,
                "_source_file": os.path.basename(path),
                "_product": "linux", "_service": "auth",
            }
            match = _SYSLOG_RE.match(raw)
            if match:
                event.update({k: v for k, v in match.groupdict().items() if v is not None})
            else:
                event["message"] = raw
            message = event.get("message", raw)
            for pattern, extra in _AUTH_PATTERNS:
                found = pattern.search(message)
                if found:
                    event.update({k: v for k, v in found.groupdict().items() if v is not None})
                    event.update(extra)
                    break
            yield event


def parse_csv(path: str) -> Iterator[Event]:
    with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        sample = fh.read(4096)
        fh.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        for line_no, row in enumerate(csv.DictReader(fh, dialect=dialect), 1):
            event = {k: v for k, v in row.items() if k}
            event["_line"] = line_no
            event["_source_file"] = os.path.basename(path)
            event["_raw"] = json.dumps(event, ensure_ascii=False)[:4000]
            yield _normalize_windows(event)


def parse_plain(path: str) -> Iterator[Event]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line_no, raw in enumerate(fh, 1):
            if raw.strip():
                yield {
                    "message": raw.rstrip("\n"), "_raw": raw.rstrip("\n"),
                    "_line": line_no, "_source_file": os.path.basename(path),
                }


PARSERS = {
    "json": parse_json, "ndjson": parse_json, "jsonl": parse_json,
    "syslog": parse_syslog, "auth": parse_syslog, "log": parse_syslog,
    "csv": parse_csv, "tsv": parse_csv,
    "plain": parse_plain, "txt": parse_plain,
}


def detect_format(path: str) -> str:
    ext = os.path.splitext(path)[1].lower().lstrip(".")
    if ext in ("json", "ndjson", "jsonl"):
        return "json"
    if ext in ("csv", "tsv"):
        return "csv"
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        head = fh.read(1024).lstrip()
    if head.startswith(("{", "[")):
        return "json"
    if _SYSLOG_RE.match(head.splitlines()[0] if head.splitlines() else ""):
        return "syslog"
    return "plain"


def parse_file(path: str, fmt: str = "auto") -> Iterator[Event]:
    fmt = (fmt or "auto").lower()
    if fmt == "auto":
        fmt = detect_format(path)
    parser = PARSERS.get(fmt)
    if parser is None:
        raise ValueError(f"bilinmeyen format: {fmt} (secenekler: {', '.join(sorted(set(PARSERS)))})")
    return parser(path)


def collect_inputs(paths: List[str], recursive: bool = True) -> List[str]:
    """Dosya/dizin karisimi girdiden okunacak dosya listesi cikarir."""
    files: List[str] = []
    for path in paths:
        if os.path.isdir(path):
            if recursive:
                for root, _dirs, names in os.walk(path):
                    files.extend(os.path.join(root, n) for n in sorted(names))
            else:
                files.extend(
                    os.path.join(path, n) for n in sorted(os.listdir(path))
                    if os.path.isfile(os.path.join(path, n))
                )
        elif os.path.isfile(path):
            files.append(path)
        else:
            raise FileNotFoundError(path)
    return files
