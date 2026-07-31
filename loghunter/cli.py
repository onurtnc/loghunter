"""LogHunter komut satiri arayuzu."""
from __future__ import annotations

import argparse
import os
import sys
from typing import Iterator, List

from . import __version__
from .engine import Engine, Result
from .parsers import collect_inputs, parse_file
from .report import to_console, to_csv, to_html, to_json
from .rules import filter_rules, load_rules

DEFAULT_RULES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="loghunter",
        description="Sigma benzeri kurallarla log dosyalarinda tehdit avi yapar.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""ornekler:
  loghunter samples/                       # tum ornek loglari tara
  loghunter samples/sysmon.json -f json
  loghunter /var/log/auth.log --min-level high
  loghunter samples/ --html rapor.html --json bulgular.json
  loghunter samples/ --tag attack.t1059 --no-color
""")
    parser.add_argument("inputs", nargs="+", help="log dosyasi veya dizin")
    parser.add_argument("-r", "--rules", default=DEFAULT_RULES,
                        help="kural dosyasi/dizini (varsayilan: paketle gelen rules/)")
    parser.add_argument("-f", "--format", default="auto",
                        choices=["auto", "json", "ndjson", "csv", "syslog", "plain"],
                        help="girdi formati (varsayilan: auto)")
    parser.add_argument("--min-level", default="informational",
                        choices=["informational", "low", "medium", "high", "critical"],
                        help="bu seviyenin altindaki kurallari calistirma")
    parser.add_argument("--tag", help="sadece bu etiketi iceren kurallari calistir")
    parser.add_argument("--limit", type=int, default=50, help="konsolda gosterilecek alarm sayisi")
    parser.add_argument("--json", metavar="PATH", help="JSON raporu yaz")
    parser.add_argument("--csv", metavar="PATH", help="CSV raporu yaz")
    parser.add_argument("--html", metavar="PATH", help="HTML raporu yaz")
    parser.add_argument("--no-dedup", action="store_true", help="ayni bulgulari tekrarla")
    parser.add_argument("--no-color", action="store_true", help="ANSI renklerini kapat")
    parser.add_argument("--quiet", action="store_true", help="sadece dosya ciktisi uret")
    parser.add_argument("--list-rules", action="store_true", help="yuklu kurallari listele ve cik")
    parser.add_argument("--fail-on", default="none",
                        choices=["none", "low", "medium", "high", "critical"],
                        help="bu seviyede alarm varsa exit code 1 dondur (CI icin)")
    parser.add_argument("-V", "--version", action="version", version=f"loghunter {__version__}")
    return parser


def _iter_events(files: List[str], fmt: str, result: Result) -> Iterator[dict]:
    for path in files:
        try:
            count_before = result.events_scanned
            for event in parse_file(path, fmt):
                yield event
            if result.events_scanned > count_before or True:
                result.files_scanned += 1
        except Exception as exc:
            result.errors.append(f"{path}: {exc}")


def main(argv: List[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        rules = load_rules(args.rules)
    except Exception as exc:
        print(f"Kural yukleme hatasi: {exc}", file=sys.stderr)
        return 2
    rules = filter_rules(rules, args.min_level, args.tag)

    if args.list_rules:
        for rule in sorted(rules, key=lambda r: (-r.score, r.title)):
            print(f"{rule.level.upper():<14} {rule.id:<28} {rule.title}")
        print(f"\nToplam {len(rules)} kural.")
        return 0

    if not rules:
        print("Uygun kural bulunamadi.", file=sys.stderr)
        return 2

    try:
        files = collect_inputs(args.inputs)
    except FileNotFoundError as exc:
        print(f"Bulunamadi: {exc}", file=sys.stderr)
        return 2
    if not files:
        print("Taranacak dosya yok.", file=sys.stderr)
        return 2

    engine = Engine(rules, dedup=not args.no_dedup)
    result = Result(rules_loaded=len(rules))
    partial = engine.run(_iter_events(files, args.format, result))
    partial.files_scanned = result.files_scanned or len(files)
    partial.errors.extend(result.errors)
    result = partial

    if not args.quiet:
        print(to_console(result, use_color=not args.no_color, limit=args.limit))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(to_json(result))
        print(f"JSON raporu -> {args.json}")
    if args.csv:
        to_csv(result, args.csv)
        print(f"CSV raporu  -> {args.csv}")
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(to_html(result))
        print(f"HTML raporu -> {args.html}")

    if args.fail_on != "none":
        from .rules import LEVEL_SCORE
        floor = LEVEL_SCORE[args.fail_on]
        if any(a.score >= floor for a in result.alerts):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
