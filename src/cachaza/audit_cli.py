"""Offline commands kept separate from network execution options."""
from __future__ import annotations

import json
from pathlib import Path

from .audit import REVIEW_STATES, compare_reports, load_report, review_queue, update_review


def add_commands(commands, common) -> None:
    diff = commands.add_parser("diff", parents=[common], add_help=False, help="compare two JSON reports offline")
    diff.add_argument("before", type=Path)
    diff.add_argument("after", type=Path)
    diff.add_argument("-o", dest="output", type=Path)
    diff.add_argument("-json", action="store_true")
    review = commands.add_parser("review", parents=[common], add_help=False, help="list or annotate workspace findings offline")
    review.add_argument("workspace", type=Path)
    review.add_argument("-id")
    review.add_argument("-state", choices=REVIEW_STATES)
    review.add_argument("-owner")
    review.add_argument("-notes")
    review.add_argument("-closure-test")
    review.add_argument("-json", action="store_true")
    report = commands.add_parser("report", parents=[common], add_help=False, help="regenerate deterministic reports from workspace evidence offline")
    report.add_argument("workspace", type=Path)
    report.add_argument("-format", action="append", choices=("json", "txt", "html", "pdf", "csv"), dest="formats")
    report.add_argument("-professional-report", action="store_true")


def execute(args) -> int:
    if args.command == "diff":
        result = compare_reports(load_report(args.before), load_report(args.after))
        if args.output:
            # Avoid overwriting either input, including a report inside a workspace.
            inputs = [(p / "report.json" if p.is_dir() else p).resolve() for p in (args.before, args.after)]
            if args.output.resolve() in inputs:
                raise ValueError("diff output must not overwrite an input report")
            with args.output.open("x", encoding="utf-8") as handle:
                handle.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print(result["notice"])
            for category in ("added", "not_observed", "changed"):
                print(f"{category}: {len(result[category])}")
                for row in result[category]:
                    item = row.get("after", row)
                    print(f"  {item['kind']}: {item['value']}")
            print(f"unchanged: {result['unchanged']}")
            for label in ("before", "after"):
                cov = result[f"coverage_{label}"]
                print(f"{label} coverage: stages={cov['stage_counts']}; providers={cov['provider_counts']}; issues={len(result[f'issues_{label}'])}")
        return 0
    root = args.workspace.expanduser().resolve()
    if not (root / "rest" / "scope.json").is_file():
        raise ValueError("expected an existing workspace with rest/scope.json")
    if args.command == "review":
        if args.id:
            update_review(root, args.id, state=args.state, owner=args.owner, notes=args.notes, closure_test=args.closure_test)
        elif any(value is not None for value in (args.state, args.owner, args.notes, args.closure_test)):
            raise ValueError("annotation options require -id")
        findings = [json.loads(line) for line in (root / "rest" / "findings.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
        path = root / "rest" / "review.json"
        rows = review_queue(findings, json.loads(path.read_text(encoding="utf-8")) if path.exists() else {})
        if args.json:
            print(json.dumps(rows, ensure_ascii=False, indent=2))
        else:
            for row in rows:
                print(f"{row['id']}  {row['state']:<10} {row['kind']}: {row['value']}  owner={row['owner']}")
            print("Review states are operator annotations. Run 'cachaza report WORKSPACE' to include them in reports.")
        return 0
    from . import __version__
    from .models import StageStatus, TargetSpec
    from .workspace import RunWorkspace
    from .reports import export_reports
    workspace = RunWorkspace(root, resume=True)
    target = TargetSpec(**json.loads((root / "rest" / "scope.json").read_text(encoding="utf-8")))
    manifest_path = root / "rest" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    workspace.stages = [StageStatus(**{k: v for k, v in row.items() if k in StageStatus.__dataclass_fields__}) for row in manifest.get("stages", [])]
    failures = [s.details for s in workspace.stages if s.status in {"failed", "interrupted"}]
    for path in export_reports(workspace, target, args.formats or ["json", "txt", "html"], version=__version__, failures=failures, txt_color=False, professional_report=args.professional_report):
        print(path)
    return 0
