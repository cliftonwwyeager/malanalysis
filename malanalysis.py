#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from mgnn_features import (
    ANALYSIS_SCHEMA,
    AnalysisParseError,
    build_analysis_prompt,
    extract_executable_features,
    heuristic_analysis,
    parse_model_response,
)


DEFAULT_MODEL = os.getenv("MGNN_OLLAMA_MODEL", "mgnn:8b")


def iter_targets(paths, recursive=False):
    for raw_path in paths:
        path = Path(raw_path)
        if path.is_file():
            yield path
        elif path.is_dir() and recursive:
            for child in path.rglob("*"):
                if child.is_file():
                    yield child
        elif path.is_dir():
            for child in path.iterdir():
                if child.is_file():
                    yield child
        else:
            raise FileNotFoundError(f"No such file or directory: {path}")


def emit_json(payload, jsonl=False):
    if jsonl:
        print(json.dumps(payload, separators=(",", ":")))
    else:
        print(json.dumps(payload, indent=2))


def run_ollama(model, prompt, timeout):
    if shutil.which("ollama") is None:
        raise RuntimeError("ollama command not found. Install Ollama and run `ollama serve`.")
    completed = subprocess.run(
        ["ollama", "run", model],
        input=prompt,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip()[-2000:]
        raise RuntimeError(f"ollama run failed with exit code {completed.returncode}: {stderr}")
    return completed.stdout.strip()


def command_features(args):
    for target in iter_targets(args.paths, recursive=args.recursive):
        emit_json(extract_executable_features(target), jsonl=args.jsonl)
    return 0


def command_prompt(args):
    features = extract_executable_features(args.path)
    print(build_analysis_prompt(features), end="")
    return 0


def command_baseline(args):
    for target in iter_targets(args.paths, recursive=args.recursive):
        features = extract_executable_features(target)
        emit_json(heuristic_analysis(features), jsonl=args.jsonl)
    return 0


def command_analyze(args):
    exit_code = 0
    for target in iter_targets(args.paths, recursive=args.recursive):
        features = extract_executable_features(target)
        prompt = build_analysis_prompt(features)
        try:
            response = run_ollama(args.model, prompt, timeout=args.timeout)
            if args.raw:
                print(response)
                continue
            analysis = parse_model_response(response, features, model_name=args.model)
        except (AnalysisParseError, RuntimeError, subprocess.TimeoutExpired) as exc:
            if not args.fallback:
                exit_code = 2
                print(json.dumps({"file": str(target), "error": str(exc)}), file=sys.stderr)
                continue
            analysis = heuristic_analysis(features, reason=f"Ollama analysis failed: {exc}")
        emit_json(analysis, jsonl=args.jsonl)
    return exit_code


def command_schema(args):
    emit_json(ANALYSIS_SCHEMA)
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        description="MGNN Ollama local-model helper for executable metadata analysis."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    features = subparsers.add_parser("features", help="Extract static executable metadata")
    features.add_argument("paths", nargs="+", help="Files or directories to inspect")
    features.add_argument("--recursive", action="store_true", help="Recurse into directories")
    features.add_argument("--jsonl", action="store_true", help="Emit compact JSONL")
    features.set_defaults(func=command_features)

    prompt = subparsers.add_parser("prompt", help="Build an Ollama prompt for one file")
    prompt.add_argument("path", help="File to inspect")
    prompt.set_defaults(func=command_prompt)

    baseline = subparsers.add_parser("baseline", help="Run metadata-only heuristic analysis")
    baseline.add_argument("paths", nargs="+", help="Files or directories to inspect")
    baseline.add_argument("--recursive", action="store_true", help="Recurse into directories")
    baseline.add_argument("--jsonl", action="store_true", help="Emit compact JSONL")
    baseline.set_defaults(func=command_baseline)

    analyze = subparsers.add_parser("analyze", help="Analyze files with an imported Ollama model")
    analyze.add_argument("paths", nargs="+", help="Files or directories to inspect")
    analyze.add_argument("--model", default=DEFAULT_MODEL, help="Ollama model name")
    analyze.add_argument("--timeout", type=int, default=180, help="Per-file timeout in seconds")
    analyze.add_argument("--recursive", action="store_true", help="Recurse into directories")
    analyze.add_argument("--jsonl", action="store_true", help="Emit compact JSONL")
    analyze.add_argument("--raw", action="store_true", help="Print raw Ollama output")
    analyze.add_argument(
        "--fallback",
        action="store_true",
        help="Return metadata-only heuristic output if Ollama fails",
    )
    analyze.set_defaults(func=command_analyze)

    schema = subparsers.add_parser("schema", help="Print the expected analysis JSON schema")
    schema.set_defaults(func=command_schema)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except OSError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
