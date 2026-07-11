"""已有 OpenAI Agents 项目的只读 AST 检查与迁移报告。"""

from __future__ import annotations

import ast
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal, cast


@dataclass(slots=True, frozen=True)
class OpenAIMigrationFinding:
    path: str
    line: int
    kind: Literal["agent", "function_tool", "agent_as_tool", "handoff", "runner", "fastapi_endpoint"]
    confidence: Literal["high", "medium"]
    recommendation: str


def inspect_openai_project(project_root: str | Path) -> list[OpenAIMigrationFinding]:
    root = Path(project_root).resolve()
    findings: list[OpenAIMigrationFinding] = []
    for path in sorted(root.rglob("*.py")):
        if _ignored(path, root):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        relative = path.relative_to(root).as_posix()
        for node in ast.walk(tree):
            finding = _finding(node, relative)
            if finding is not None:
                findings.append(finding)
    return sorted(findings, key=lambda item: (item.path, item.line, item.kind))


def migration_report(project_root: str | Path) -> dict[str, object]:
    findings = inspect_openai_project(project_root)
    return {
        "version": 1,
        "project_root": str(Path(project_root).resolve()),
        "findings": [asdict(item) for item in findings],
        "summary": {
            "total": len(findings),
            "automatic_source_changes": 0,
            "reason": (
                "Agent identity and authorization policy cannot be inferred safely from Python syntax; "
                "the generated report is an explicit migration checklist."
            ),
        },
    }


def write_migration_report(project_root: str | Path) -> Path:
    """幂等写入迁移清单；绝不改写业务 Python 源码。"""

    root = Path(project_root).resolve()
    payload = migration_report(root)
    output_dir = root / ".agent-auth"
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "openai-migration.json"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    markdown_path = output_dir / "OPENAI_MIGRATION.md"
    lines = [
        "# OpenAI Agents 身份认证迁移清单",
        "",
        "此文件由 `agent-auth openai migrate . --write` 生成。命令不会猜测身份或修改业务源码。",
        "",
    ]
    for finding in cast(list[dict[str, Any]], payload["findings"]):
        lines.append(f"- [ ] `{finding['path']}:{finding['line']}` `{finding['kind']}` — {finding['recommendation']}")
    if not payload["findings"]:
        lines.append("未识别到 OpenAI Agents 静态边界。请检查动态构造或工厂函数。")
    lines.extend(["", "机器可读结果见 `openai-migration.json`。", ""])
    markdown_path.write_text("\n".join(lines), encoding="utf-8")
    return markdown_path


def _finding(node: ast.AST, path: str) -> OpenAIMigrationFinding | None:
    if isinstance(node, ast.Call):
        name = _call_name(node.func)
        if name == "Agent":
            return OpenAIMigrationFinding(path, node.lineno, "agent", "high", "为此 Agent 绑定配置中的 identity role。")
        if name == "function_tool":
            return OpenAIMigrationFinding(
                path,
                node.lineno,
                "function_tool",
                "high",
                "若它跨越 Agent 信任边界，使用 auth.protect_tool(existing_tool, target=...)。",
            )
        if name.endswith(".as_tool"):
            return OpenAIMigrationFinding(
                path,
                node.lineno,
                "agent_as_tool",
                "high",
                "替换为 auth.agent_as_tool(agent, identity=...) 并保留 tool 名称和描述。",
            )
        if name == "handoff":
            return OpenAIMigrationFinding(
                path,
                node.lineno,
                "handoff",
                "high",
                "同进程审计使用 auth.authenticated_handoff；安全隔离使用 remote_agent_tool。",
            )
        if name in {"Runner.run", "Runner.run_sync", "Runner.run_streamed"}:
            return OpenAIMigrationFinding(
                path,
                node.lineno,
                "runner",
                "medium",
                "确认该调用是否为跨 Agent 边界；优先改为 agent_as_tool 或 remote_agent_tool。",
            )
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for decorator in node.decorator_list:
            name = _call_name(decorator.func if isinstance(decorator, ast.Call) else decorator)
            if name in {"function_tool", "app.post", "router.post", "app.api_route", "router.api_route"}:
                kind: Literal["function_tool", "fastapi_endpoint"] = (
                    "function_tool" if name == "function_tool" else "fastapi_endpoint"
                )
                recommendation = (
                    "跨 Agent tool 使用 auth.protect_tool。"
                    if kind == "function_tool"
                    else "Agent HTTP 边界使用 AgentAuthRouter.agent_endpoint。"
                )
                return OpenAIMigrationFinding(path, node.lineno, kind, "high", recommendation)
    return None


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _ignored(path: Path, root: Path) -> bool:
    ignored = {".git", ".venv", "venv", "site-packages", "dist", "build", "__pycache__"}
    return any(part in ignored for part in path.relative_to(root).parts)
