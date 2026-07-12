#!/usr/bin/env python3
"""Check tracked production files for repository-hygiene violations.

The content checks intentionally scan only configured production/runtime roots.
Generated-artifact checks scan every tracked file present in the worktree. The
rules are structural and do not contain benchmark labels, actors, indicators,
or expected answers.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Sequence


DEFAULT_PRODUCTION_PREFIXES = (
    "Linux_LLM/config",
    "Linux_LLM/app",
    "Linux_LLM/static",
    "Linux_LLM/templates",
    "Linux_LLM/.env.example",
    ".env.example",
    "pyproject.toml",
    "requirements.txt",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
)
TEXT_SUFFIXES = {
    ".cfg",
    ".conf",
    ".env",
    ".html",
    ".ini",
    ".j2",
    ".js",
    ".json",
    ".py",
    ".toml",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
TEXT_FILENAMES = {
    ".env.example",
    "Dockerfile",
    "docker-compose.yaml",
    "docker-compose.yml",
    "pyproject.toml",
    "requirements.txt",
}

FORBIDDEN_IMPORT_COMPONENTS = {"tests", "test", "evaluation", "evaluation_generalization"}
FORBIDDEN_PATH_PATTERNS = (
    (
        "evaluation_path",
        re.compile(
            r"(?i)(?:^|[/\\])(?:evaluation|evaluation_generalization|evaluation-results|benchmarks?)(?:[/\\]|$)"
        ),
    ),
    ("test_path", re.compile(r"(?i)(?:^|[/\\])tests?(?:[/\\]|$)")),
    ("gold_manifest_path", re.compile(r"(?i)\bgold[-_]manifest(?:\.json)?\b")),
    (
        "frozen_suite_path",
        re.compile(r"(?i)(?:^|[/\\])(?:holdout|development)[-_]suite(?:[/\\]|$)"),
    ),
)

PERSONAL_PATH_PATTERNS = (
    re.compile(r"(?<![A-Za-z0-9])/(?:home|Users)/(?P<user>[A-Za-z0-9._-]+)(?:[/\\]|$)"),
    re.compile(r"(?i)(?<![A-Za-z0-9])(?:[A-Z]:)?\\Users\\(?P<user>[A-Za-z0-9._-]+)(?:\\|$)"),
)
PLACEHOLDER_USERS = {
    "<user>",
    "${user}",
    "$user",
    "example",
    "username",
    "your-user",
    "your_user",
    "yourname",
}

SENSITIVE_KEY_PATTERN = re.compile(
    r"(?i)(?:^|_)(?:password|passwd|pwd|secret|api_key|access_token|auth_token|bearer_token|private_key|client_secret)(?:$|_)"
)
PLACEHOLDER_SECRET_VALUES = {
    "<secret>",
    "${secret}",
    "$secret",
    "change-me",
    "changeme",
    "example",
    "not-set",
    "none",
    "null",
    "placeholder",
    "redacted",
    "replace-me",
    "unset",
    "your-secret-here",
}
PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
TOKEN_PATTERNS = (
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("API token", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
)

GENERATED_DIRECTORY_NAMES = {
    "__pycache__",
    ".mypy_cache",
    ".nox",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    "all_pdfs",
    "build",
    "dist",
    "evaluation-results",
    "htmlcov",
    "node_modules",
    "reports",
    "uploads",
}
GENERATED_FILE_NAMES = {".coverage", ".DS_Store"}
GENERATED_SUFFIXES = {
    ".bak",
    ".backup",
    ".ckpt",
    ".db",
    ".dump",
    ".gguf",
    ".log",
    ".onnx",
    ".pt",
    ".pth",
    ".prof",
    ".pstats",
    ".pyc",
    ".pyo",
    ".safetensors",
    ".sqlite",
    ".sqlite3",
    ".swp",
    ".swo",
    ".tmp",
}


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    line: int | None
    message: str


def _normalize_relative_path(value: str | Path) -> str:
    text = str(value).replace("\\", "/").strip()
    while text.startswith("./"):
        text = text[2:]
    return str(PurePosixPath(text))


def tracked_files(repo_root: Path) -> list[str]:
    """Return tracked paths that are present in the current worktree."""
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=repo_root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    paths = [item for item in result.stdout.decode("utf-8", errors="surrogateescape").split("\0") if item]
    return sorted(
        _normalize_relative_path(path)
        for path in paths
        if (repo_root / path).is_file()
    )


def _is_in_scope(path: str, prefixes: Sequence[str]) -> bool:
    normalized = _normalize_relative_path(path)
    for prefix in prefixes:
        clean_prefix = _normalize_relative_path(prefix).rstrip("/")
        if normalized == clean_prefix or normalized.startswith(clean_prefix + "/"):
            return True
    return False


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _import_is_forbidden(module_name: str) -> bool:
    components = {part.lower() for part in str(module_name or "").split(".") if part}
    return bool(components & FORBIDDEN_IMPORT_COMPONENTS)


def _python_import_findings(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        tree = ast.parse(text, filename=path)
    except SyntaxError as error:
        return [
            Finding(
                "python_parse_error",
                path,
                error.lineno,
                "Python source could not be parsed, so import hygiene could not be verified.",
            )
        ]

    for node in ast.walk(tree):
        imported: list[str] = []
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.append(node.module)
            imported.extend(alias.name for alias in node.names if node.level and not node.module)
        elif isinstance(node, ast.Call):
            is_dynamic_import = (
                isinstance(node.func, ast.Name)
                and node.func.id == "__import__"
            ) or (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "importlib"
                and node.func.attr == "import_module"
            )
            if is_dynamic_import and node.args and isinstance(node.args[0], ast.Constant):
                if isinstance(node.args[0].value, str):
                    imported.append(node.args[0].value)

        for module_name in imported:
            if _import_is_forbidden(module_name):
                findings.append(
                    Finding(
                        "production_imports_nonproduction",
                        path,
                        getattr(node, "lineno", None),
                        f"Production source imports non-production module '{module_name}'.",
                    )
                )
    return findings


def _javascript_import_findings(path: str, text: str) -> list[Finding]:
    pattern = re.compile(
        r"(?im)(?:\bfrom\s+|\brequire\s*\(\s*|\bimport\s*\(\s*)"
        r"[\"'](?P<module>[^\"']+)[\"']"
    )
    findings = []
    for match in pattern.finditer(text):
        module_name = match.group("module").replace("\\", "/")
        components = {part.lower() for part in module_name.split("/") if part not in {".", "..", ""}}
        if components & FORBIDDEN_IMPORT_COMPONENTS:
            findings.append(
                Finding(
                    "production_imports_nonproduction",
                    path,
                    _line_number(text, match.start()),
                    f"Production asset imports non-production module '{module_name}'.",
                )
            )
    return findings


def _literal_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _sensitive_key(name: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", str(name or "").lower()).strip("_")
    return bool(normalized and SENSITIVE_KEY_PATTERN.search(normalized))


def _looks_like_placeholder_secret(value: str) -> bool:
    normalized = str(value or "").strip().lower()
    if not normalized:
        return True
    if normalized in PLACEHOLDER_SECRET_VALUES:
        return True
    if normalized.startswith(("${", "$", "env:", "vault:", "secret://")):
        return True
    if (normalized.startswith("<") and normalized.endswith(">")) or "replace" in normalized:
        return True
    if len(set(normalized)) == 1 and normalized[0] in {"x", "*", "-"}:
        return True
    return False


def _python_secret_findings(path: str, text: str) -> list[Finding]:
    try:
        tree = ast.parse(text, filename=path)
    except SyntaxError:
        return []

    candidates: list[tuple[str, str, int | None]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value_node = node.value
            value = _literal_string(value_node)
            if value is None:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    candidates.append((target.id, value, getattr(node, "lineno", None)))
                elif isinstance(target, ast.Attribute):
                    candidates.append((target.attr, value, getattr(node, "lineno", None)))
        elif isinstance(node, ast.Dict):
            for key_node, value_node in zip(node.keys, node.values):
                key = _literal_string(key_node)
                value = _literal_string(value_node)
                if key is not None and value is not None:
                    candidates.append((key, value, getattr(value_node, "lineno", getattr(node, "lineno", None))))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            positional = list(node.args.posonlyargs) + list(node.args.args)
            if node.args.defaults:
                positional = positional[-len(node.args.defaults):]
                for argument, default in zip(positional, node.args.defaults):
                    value = _literal_string(default)
                    if value is not None:
                        candidates.append((argument.arg, value, getattr(default, "lineno", node.lineno)))
            for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
                value = _literal_string(default)
                if default is not None and value is not None:
                    candidates.append((argument.arg, value, getattr(default, "lineno", node.lineno)))

    findings = []
    seen = set()
    for key, value, line in candidates:
        identity = (key, line)
        if identity in seen or not _sensitive_key(key) or _looks_like_placeholder_secret(value):
            continue
        seen.add(identity)
        findings.append(
            Finding(
                "credential_literal",
                path,
                line,
                f"Likely credential literal assigned to sensitive key '{key}'.",
            )
        )
    return findings


def _text_secret_findings(path: str, text: str) -> list[Finding]:
    assignment_pattern = re.compile(
        r"(?im)^[ \t]*[\"']?(?P<key>[A-Za-z][A-Za-z0-9_.-]*)[\"']?[ \t]*[:=][ \t]*"
        r"(?:(?P<quote>[\"'])(?P<quoted_value>.*?)(?P=quote)|(?P<bare_value>[^\s,#]*))"
        r"[ \t]*,?[ \t]*(?:#.*)?$"
    )
    findings = []
    for match in assignment_pattern.finditer(text):
        key = match.group("key")
        value = match.group("quoted_value")
        if value is None:
            value = match.group("bare_value") or ""
        if _sensitive_key(key) and not _looks_like_placeholder_secret(value):
            findings.append(
                Finding(
                    "credential_literal",
                    path,
                    _line_number(text, match.start()),
                    f"Likely credential literal assigned to sensitive key '{key}'.",
                )
            )
    return findings


def _content_findings(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    suffix = PurePosixPath(path).suffix.lower()

    if suffix == ".py":
        findings.extend(_python_import_findings(path, text))
        findings.extend(_python_secret_findings(path, text))
    elif suffix == ".js":
        findings.extend(_javascript_import_findings(path, text))
        findings.extend(_text_secret_findings(path, text))
    else:
        findings.extend(_text_secret_findings(path, text))

    for rule, pattern in FORBIDDEN_PATH_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(
                Finding(
                    rule,
                    path,
                    _line_number(text, match.start()),
                    "Production content references an evaluation or benchmark artifact path/token.",
                )
            )

    for pattern in PERSONAL_PATH_PATTERNS:
        for match in pattern.finditer(text):
            user = match.group("user").lower()
            if user in PLACEHOLDER_USERS or user.startswith(("${", "<")):
                continue
            findings.append(
                Finding(
                    "personal_absolute_path",
                    path,
                    _line_number(text, match.start()),
                    "Production content contains a user-specific absolute path.",
                )
            )

    for match in PRIVATE_KEY_PATTERN.finditer(text):
        findings.append(
            Finding(
                "private_key_material",
                path,
                _line_number(text, match.start()),
                "Production content appears to contain private key material.",
            )
        )

    for token_name, pattern in TOKEN_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(
                Finding(
                    "credential_literal",
                    path,
                    _line_number(text, match.start()),
                    f"Production content appears to contain a {token_name} literal.",
                )
            )
    return findings


def _generated_artifact_finding(path: str) -> Finding | None:
    pure_path = PurePosixPath(_normalize_relative_path(path))
    components = {component.lower() for component in pure_path.parts}
    suffixes = {suffix.lower() for suffix in pure_path.suffixes}

    if components & GENERATED_DIRECTORY_NAMES:
        return Finding(
            "tracked_generated_artifact",
            str(pure_path),
            None,
            "Generated/runtime directory is tracked by git.",
        )
    if pure_path.name in GENERATED_FILE_NAMES:
        return Finding(
            "tracked_generated_artifact",
            str(pure_path),
            None,
            "Generated metadata file is tracked by git.",
        )
    if (
        suffixes & GENERATED_SUFFIXES
        or any(component.endswith((".dist-info", ".egg-info")) for component in components)
        or pure_path.name.startswith(".coverage.")
    ):
        return Finding(
            "tracked_generated_artifact",
            str(pure_path),
            None,
            "Generated artifact, model, cache, log, or database dump is tracked by git.",
        )
    lower_name = pure_path.name.lower()
    if (
        lower_name.endswith((".sql", ".sql.gz", ".tar", ".tar.gz", ".tgz"))
        and any(token in lower_name for token in ("backup", "database", "dump", "snapshot"))
    ):
        return Finding(
            "tracked_generated_artifact",
            str(pure_path),
            None,
            "Likely database/archive dump is tracked by git.",
        )
    return None


def scan_repository(
    repo_root: Path,
    *,
    tracked_paths: Iterable[str] | None = None,
    production_prefixes: Sequence[str] = DEFAULT_PRODUCTION_PREFIXES,
) -> dict:
    """Scan a repository and return a stable, JSON-serializable result."""
    repo_root = Path(repo_root).resolve()
    normalized_prefixes = tuple(_normalize_relative_path(item) for item in production_prefixes)
    selected_paths = tracked_files(repo_root) if tracked_paths is None else tracked_paths
    paths = sorted({_normalize_relative_path(item) for item in selected_paths})
    production_paths = [path for path in paths if _is_in_scope(path, normalized_prefixes)]

    findings: list[Finding] = []
    for path in paths:
        generated_finding = _generated_artifact_finding(path)
        if generated_finding:
            findings.append(generated_finding)

    for path in production_paths:
        absolute_path = repo_root / path
        if not absolute_path.is_file():
            continue
        if absolute_path.suffix.lower() not in TEXT_SUFFIXES and absolute_path.name not in TEXT_FILENAMES:
            continue
        try:
            text = absolute_path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError as error:
            findings.append(
                Finding(
                    "file_read_error",
                    path,
                    None,
                    f"Tracked production file could not be read: {error}",
                )
            )
            continue
        findings.extend(_content_findings(path, text))

    unique_findings = sorted(
        set(findings),
        key=lambda item: (item.path, item.line or 0, item.rule, item.message),
    )
    return {
        "ok": not unique_findings,
        "repository": str(repo_root),
        "scope": {
            "production_prefixes": list(normalized_prefixes),
            "production_content_files_scanned": len(production_paths),
            "generated_artifact_scope": "all tracked files present in the worktree",
            "tracked_files_scanned": len(paths),
        },
        "finding_count": len(unique_findings),
        "findings": [asdict(finding) for finding in unique_findings],
    }


def _human_output(result: dict) -> str:
    status = "PASS" if result["ok"] else "FAIL"
    scope = result["scope"]
    lines = [
        f"Repository hygiene: {status} ({result['finding_count']} finding(s))",
        "Production content scope: " + ", ".join(scope["production_prefixes"]),
        f"Production content files scanned: {scope['production_content_files_scanned']}",
        (
            "Generated-artifact scope: "
            f"{scope['generated_artifact_scope']} ({scope['tracked_files_scanned']} files)"
        ),
    ]
    for finding in result["findings"]:
        location = finding["path"]
        if finding["line"] is not None:
            location += f":{finding['line']}"
        lines.append(f"- [{finding['rule']}] {location}: {finding['message']}")
    return "\n".join(lines)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="Repository root (defaults to the root containing Linux_LLM).",
    )
    parser.add_argument(
        "--production-root",
        action="append",
        dest="production_roots",
        help=(
            "Repository-relative production/runtime root or file to scan. Repeatable; "
            "defaults cover the application, runtime assets, and deployment configuration."
        ),
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    production_roots = tuple(args.production_roots or DEFAULT_PRODUCTION_PREFIXES)
    try:
        result = scan_repository(
            args.repo_root,
            production_prefixes=production_roots,
        )
    except (OSError, subprocess.SubprocessError) as error:
        if args.json:
            print(json.dumps({"ok": False, "error": str(error)}, indent=2, sort_keys=True))
        else:
            print(f"Repository hygiene check could not run: {error}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(_human_output(result))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
