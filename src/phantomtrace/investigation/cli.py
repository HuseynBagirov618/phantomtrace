"""Command line entry points for the demo and evaluation."""
import argparse
import json
from pathlib import Path
from tempfile import TemporaryDirectory

import uvicorn

from phantomtrace.investigation.evaluate import evaluate, markdown
from phantomtrace.investigation.sample import DEMO_CONFIG, seed
from phantomtrace.investigation.store import AnalysisStore


def main():
    parser = argparse.ArgumentParser(prog="phantomtrace")
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("demo")
    demo.add_argument("--port", type=int, default=8000)
    evaluation = commands.add_parser("eval")
    evaluation.add_argument("manifest", type=Path)
    evaluation.add_argument("--split", choices=["development", "validation", "held_out"], default="development")
    evaluation.add_argument("--json", dest="json_path", type=Path, default=Path("data/eval.json"))
    evaluation.add_argument("--markdown", dest="markdown_path", type=Path, default=Path("data/eval.md"))
    args = parser.parse_args()

    if args.command == "demo":
        from apps.api import main as application
        from phantomtrace.database.db import PhantomTraceDB
        from phantomtrace.evidence.storage import EvidenceStorage

        with TemporaryDirectory() as temp:
            directory = Path(temp)
            application.db = PhantomTraceDB(directory / "demo.db")
            application.storage = EvidenceStorage(directory / "cases")
            for scenario in ("benign", "concurrent", "indicator"):
                case_id = "DEMO-" + scenario.upper()
                seed(application.db, application.storage, directory / "samples", case_id, scenario)
                AnalysisStore(application.db).run(case_id, DEMO_CONFIG)
            print(f"Synthetic demo at http://127.0.0.1:{args.port}", flush=True)
            uvicorn.run(application.app, host="127.0.0.1", port=args.port)
        return

    try:
        results = evaluate(args.manifest, split=args.split)
    except (KeyError, OSError, ValueError) as error:
        parser.exit(2, f"Evaluation failed: {error}\n")
    for path, content in ((args.json_path, json.dumps(results, indent=2) + "\n"),
                          (args.markdown_path, markdown(results))):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    print(markdown(results), end="")


if __name__ == "__main__":
    main()
