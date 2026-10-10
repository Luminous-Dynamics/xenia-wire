#!/usr/bin/env python3
"""Compile Python heredocs embedded in active GitHub Actions workflow files.

GitHub Actions does not parse Python heredoc bodies when validating workflow YAML.
This check catches syntax and indentation failures in workflow_run trust consumers
before they are merged and become the default-branch execution source.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

HEREDOC = re.compile(
    r"""^(?P<indent> *)python(?:3)?[ \t]+-[ \t]+(?:.*?[ \t]+)?<<(?:(?P<single>'[A-Za-z_][A-Za-z0-9_]*')|(?P<double>"[A-Za-z_][A-Za-z0-9_]*")|(?P<bare>[A-Za-z_][A-Za-z0-9_]*))[ \t]*$"""
)


def compile_embedded_python(path: Path) -> tuple[int, list[str]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    errors: list[str] = []
    checked = 0
    index = 0

    while index < len(lines):
        match = HEREDOC.match(lines[index])
        if match is None:
            index += 1
            continue

        command_indent = match.group("indent")
        marker_text = next(
            match.group(group)
            for group in ("single", "double", "bare")
            if match.group(group) is not None
        )
        marker = marker_text[1:-1] if marker_text.startswith(("'", '"')) else marker_text
        start_line = index + 1
        body_start = index + 1
        index += 1
        terminator_index = None
        terminator_indent = ""

        while index < len(lines):
            candidate = lines[index]
            candidate_indent = candidate[:len(candidate) - len(candidate.lstrip(" "))]
            if candidate == candidate_indent + marker:
                terminator_index = index
                terminator_indent = candidate_indent
                break
            index += 1

        if terminator_index is None:
            errors.append(
                f"{path}:{start_line}: Python heredoc marker {marker!r} has no terminator"
            )
            break

        # In a nested shell block, the command line may be deeper than the
        # heredoc body/terminator because YAML strips the run-block base indent.
        # The terminator's indent is the only correct extraction baseline.
        if not command_indent.startswith(terminator_indent):
            errors.append(
                f"{path}:{terminator_index + 1}: heredoc terminator indentation "
                f"is not a prefix of its command indentation"
            )

        body: list[str] = []
        for body_index in range(body_start, terminator_index):
            line = lines[body_index]
            if line.strip() and not line.startswith(terminator_indent):
                errors.append(
                    f"{path}:{body_index + 1}: heredoc body is less-indented than "
                    f"its terminator; refusing ambiguous extraction"
                )
                body.append(line)
            else:
                body.append(line[len(terminator_indent):] if line.strip() else "")
        index = terminator_index + 1  # consume the terminator
        source = "\n".join(body) + "\n"
        checked += 1
        try:
            compile(source, f"{path}:{start_line}", "exec")
        except (SyntaxError, IndentationError, ValueError) as exc:
            line = getattr(exc, "lineno", None)
            detail = getattr(exc, "msg", str(exc))
            where = f"{path}:{start_line + line}" if line else f"{path}:{start_line}"
            errors.append(f"{where}: embedded Python syntax error: {detail}")

    return checked, errors


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.is_dir():
        print(f"FAIL: workflow directory not found: {workflow_dir}", file=sys.stderr)
        return 2

    workflows = sorted(
        path for path in workflow_dir.iterdir()
        if path.is_file() and path.suffix in {".yml", ".yaml"}
    )
    if not workflows:
        print(f"FAIL: no active workflow YAML files found in {workflow_dir}", file=sys.stderr)
        return 2

    total = 0
    failures: list[str] = []
    for path in workflows:
        count, errors = compile_embedded_python(path)
        total += count
        failures.extend(errors)

    if failures:
        for error in failures:
            print(f"FAIL: {error}", file=sys.stderr)
        print(
            f"RESULT: FAIL ({len(failures)} issue(s); checked {total} Python heredoc(s) "
            f"across {len(workflows)} active workflow file(s))",
            file=sys.stderr,
        )
        return 1

    print(
        f"RESULT: PASS (compiled {total} Python heredoc(s) across "
        f"{len(workflows)} active workflow file(s))"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
