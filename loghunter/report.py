"""Alarm ciktilarini konsol / JSON / CSV / HTML olarak sunar."""
from __future__ import annotations

import csv
import html
import json
from typing import List

from .engine import Alert, Result

LEVEL_COLOR = {
    "critical": "\033[97;41m", "high": "\033[91m", "medium": "\033[93m",
    "low": "\033[96m", "informational": "\033[90m",
}
RESET = "\033[0m"
BOLD = "\033[1m"

LEVEL_HEX = {
    "critical": "#b3001b", "high": "#e8590c", "medium": "#f08c00",
    "low": "#1c7ed6", "informational": "#868e96",
}


def _c(text: str, color: str, use_color: bool) -> str:
    return f"{color}{text}{RESET}" if use_color else text


def to_console(result: Result, use_color: bool = True, limit: int = 50) -> str:
    lines: List[str] = []
    lines.append(_c("=" * 78, BOLD, use_color))
    lines.append(_c("  LogHunter - Tespit Raporu", BOLD, use_color))
    lines.append(_c("=" * 78, BOLD, use_color))
    lines.append(
        f"  Dosya: {result.files_scanned}   Olay: {result.events_scanned}   "
        f"Kural: {result.rules_loaded}   Alarm: {len(result.alerts)}"
    )
    risk = result.risk_score
    bar = "#" * (risk // 5) + "." * (20 - risk // 5)
    risk_color = LEVEL_COLOR["critical"] if risk >= 80 else (
        LEVEL_COLOR["high"] if risk >= 60 else LEVEL_COLOR["medium"])
    lines.append(f"  Risk skoru: {_c(f'[{bar}] {risk}/100', risk_color, use_color)}")

    counts = result.by_level
    if counts:
        parts = [
            _c(f"{lvl}:{cnt}", LEVEL_COLOR.get(lvl, ""), use_color)
            for lvl, cnt in sorted(counts.items(), key=lambda kv: -kv[1])
        ]
        lines.append("  Seviyeler: " + "  ".join(parts))
    lines.append("-" * 78)

    if not result.alerts:
        lines.append("  Alarm yok. Temiz gorunuyor.")
        return "\n".join(lines)

    for alert in result.alerts[:limit]:
        level = alert.level.lower()
        head = f"[{alert.level.upper()}] {alert.rule_title}"
        lines.append(_c(head, LEVEL_COLOR.get(level, ""), use_color))
        stamp = alert.timestamp.isoformat(sep=" ") if alert.timestamp else "zaman yok"
        loc = f"{alert.source_file}:{alert.line}" if alert.line else alert.source_file
        lines.append(f"    zaman : {stamp}    kaynak: {loc}")
        if alert.tags:
            lines.append(f"    etiket: {', '.join(alert.tags)}")
        for key, value in alert.fields.items():
            text = str(value)
            if len(text) > 110:
                text = text[:107] + "..."
            lines.append(f"    {key:<18}: {text}")
        lines.append("")

    if len(result.alerts) > limit:
        lines.append(f"  ... {len(result.alerts) - limit} alarm daha (--limit ile artir)")
    if result.errors:
        lines.append(_c(f"  Uyari: {len(result.errors)} kural hatasi", LEVEL_COLOR["medium"], use_color))
        for err in result.errors[:5]:
            lines.append(f"    - {err}")
    return "\n".join(lines)


def to_json(result: Result) -> str:
    return json.dumps({
        "summary": {
            "files_scanned": result.files_scanned,
            "events_scanned": result.events_scanned,
            "rules_loaded": result.rules_loaded,
            "alert_count": len(result.alerts),
            "risk_score": result.risk_score,
            "by_level": dict(result.by_level),
            "by_rule": dict(result.by_rule),
        },
        "alerts": [a.to_dict() for a in result.alerts],
        "errors": result.errors,
    }, indent=2, ensure_ascii=False)


def to_csv(result: Result, path: str) -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["timestamp", "level", "score", "rule_id", "rule_title",
                         "source_file", "line", "tags", "fields"])
        for a in result.alerts:
            writer.writerow([
                a.timestamp.isoformat() if a.timestamp else "", a.level, a.score,
                a.rule_id, a.rule_title, a.source_file, a.line or "",
                ";".join(a.tags),
                json.dumps(a.fields, ensure_ascii=False),
            ])


def to_html(result: Result) -> str:
    rows = []
    for a in result.alerts:
        color = LEVEL_HEX.get(a.level.lower(), "#868e96")
        fields = "".join(
            f"<div><span class='k'>{html.escape(str(k))}</span>"
            f"<span class='v'>{html.escape(str(v))[:300]}</span></div>"
            for k, v in a.fields.items()
        )
        rows.append(f"""
        <tr>
          <td class="lvl"><span style="background:{color}">{html.escape(a.level.upper())}</span></td>
          <td>
            <div class="title">{html.escape(a.rule_title)}</div>
            <div class="meta">{html.escape(a.timestamp.isoformat(sep=' ') if a.timestamp else '-')}
              &middot; {html.escape(a.source_file)}{f':{a.line}' if a.line else ''}</div>
            <div class="tags">{html.escape(', '.join(a.tags))}</div>
            <div class="fields">{fields}</div>
          </td>
          <td class="score">{a.score}</td>
        </tr>""")

    level_rows = "".join(
        f"<li><b>{html.escape(lvl)}</b>: {cnt}</li>"
        for lvl, cnt in sorted(result.by_level.items(), key=lambda kv: -kv[1])
    )
    return f"""<!doctype html>
<html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LogHunter Raporu</title>
<style>
 :root {{ color-scheme: light dark; }}
 body {{ font-family: -apple-system,Segoe UI,Roboto,sans-serif; margin:0; padding:24px;
        background:#0f1115; color:#e6e6e6; }}
 h1 {{ margin:0 0 4px; font-size:22px; }}
 .sub {{ color:#9aa0a6; margin-bottom:20px; font-size:13px; }}
 .cards {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:20px; }}
 .card {{ background:#171a21; border:1px solid #262b36; border-radius:10px;
          padding:14px 18px; min-width:120px; }}
 .card b {{ display:block; font-size:26px; }}
 .card span {{ color:#9aa0a6; font-size:12px; }}
 ul {{ margin:0; padding-left:18px; color:#c9ced6; font-size:13px; }}
 table {{ width:100%; border-collapse:collapse; background:#171a21;
          border:1px solid #262b36; border-radius:10px; overflow:hidden; }}
 th,td {{ padding:10px 12px; border-bottom:1px solid #262b36; vertical-align:top;
          text-align:left; font-size:13px; }}
 th {{ background:#1d222b; color:#9aa0a6; font-size:12px; text-transform:uppercase; }}
 .lvl span {{ display:inline-block; padding:3px 9px; border-radius:20px; color:#fff;
              font-size:11px; font-weight:700; }}
 .title {{ font-weight:600; font-size:14px; }}
 .meta {{ color:#9aa0a6; font-size:12px; margin:2px 0; }}
 .tags {{ color:#5c9ded; font-size:12px; }}
 .fields {{ margin-top:6px; }}
 .fields .k {{ display:inline-block; min-width:150px; color:#9aa0a6; }}
 .fields .v {{ font-family:ui-monospace,Menlo,Consolas,monospace; }}
 .score {{ font-weight:700; text-align:right; }}
</style></head><body>
<h1>LogHunter - Tespit Raporu</h1>
<div class="sub">Sigma benzeri kural motoru &middot; risk skoru {result.risk_score}/100</div>
<div class="cards">
  <div class="card"><b>{result.files_scanned}</b><span>dosya</span></div>
  <div class="card"><b>{result.events_scanned}</b><span>olay</span></div>
  <div class="card"><b>{result.rules_loaded}</b><span>kural</span></div>
  <div class="card"><b>{len(result.alerts)}</b><span>alarm</span></div>
  <div class="card"><ul>{level_rows or '<li>alarm yok</li>'}</ul></div>
</div>
<table><thead><tr><th>Seviye</th><th>Bulgu</th><th>Skor</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan=3>Alarm bulunamadi.</td></tr>'}</tbody></table>
</body></html>"""
