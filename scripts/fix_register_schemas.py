#!/usr/bin/env python3
"""
fix_register_schemas.py — God-Tier v2.0 (Consejo Absoluto)

Añade automáticamente `_register_schema(...)` a los agentes que definen
schemas Pydantic pero no los registran en el registry global.

v2.0 (corrige el bug de v1.0):
- Elimina registros mal colocados antes de reinsertar.
- Usa AST para encontrar la definición real de cada schema.
- Inserta el bloque DESPUÉS de la última clase de schema (Input y Output).
- Es idempotente: si ya está bien colocado, no lo toca.

Uso:
    uv run python scripts/fix_register_schemas.py
"""
from __future__ import annotations

import ast
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (ruta, [schemas de input, schemas de output])
AGENTS = [
    (ROOT / "src/god_tier_agency/agents/recon_agent.py",        ["ReconInput", "ReconOutput"]),
    (ROOT / "src/god_tier_agency/agents/scanner_agent.py",      ["ScannerInput", "ScannerOutput"]),
    (ROOT / "src/god_tier_agency/agents/evasion_agent.py",      ["EvasionInput", "EvasionOutput"]),
    (ROOT / "src/god_tier_agency/agents/post_exploit_agent.py", ["PostExploitInput", "PostExploitOutput"]),
    (ROOT / "src/god_tier_agency/agents/reporter_agent.py",     ["ReportInput", "ReportOutput"]),
]

# Regex para detectar el bloque actual (v1.0 lo puso en cualquier sitio)
BLOCK_IMPORT_RE = re.compile(
    r'^from\s+god_tier_agency\.agents\.contract\s+import\s+_register_schema\s*$',
    re.MULTILINE,
)
BLOCK_CALL_RE = re.compile(
    r'^_register_schema\([^)]*\)\s*$',
    re.MULTILINE,
)
BLOCK_COMMENT_RE = re.compile(
    r'^#\s*Registrar schemas en el registry global[^\n]*$',
    re.MULTILINE,
)


def find_class_end_line(lines: list[str], class_name: str) -> int | None:
    """Devuelve el índice (0-based) de la última línea de la clase `class_name`.

    Estrategia: usa ast para localizar la clase, luego busca la línea
    `lineno`/`end_lineno` que Python 3.8+ provee.
    """
    src = "\n".join(lines)
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        print(f"    ⚠️  SyntaxError al parsear: {e}")
        return None

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            # end_lineno es 1-based; convertir a 0-based index
            return node.end_lineno - 1 if node.end_lineno else None
    return None


def remove_existing_block(content: str) -> str:
    """Elimina bloques de registro v1.0 mal colocados."""
    lines = content.splitlines(keepends=True)
    out: list[str] = []
    skip_next = False

    for i, line in enumerate(lines):
        if skip_next:
            skip_next = False
            continue

        # Comentario del bloque
        if BLOCK_COMMENT_RE.match(line.rstrip("\n")):
            # Verificar si la siguiente línea es el import
            if i + 1 < len(lines) and BLOCK_IMPORT_RE.match(lines[i + 1].rstrip("\n")):
                # Saltar comentario + import + posibles _register_schema(...) siguientes
                skip_next = True
                j = i + 2
                while j < len(lines) and (
                    BLOCK_CALL_RE.match(lines[j].rstrip("\n"))
                    or not lines[j].strip()
                ):
                    j += 1
                # Saltamos hasta j
                # Reconstruimos desde i pero saltando
                # Truco: ya avanzamos out con todo lo anterior.
                # Aquí simplemente no añadimos nada hasta j.
                # Necesitamos saltar manualmente:
                # Como estamos en un for, convertimos a while
                pass
        out.append(line)

    # Re-hacer con while para control preciso
    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if BLOCK_COMMENT_RE.match(line.rstrip("\n")):
            # Saltar bloque completo
            j = i + 1
            if j < len(lines) and BLOCK_IMPORT_RE.match(lines[j].rstrip("\n")):
                j += 1
                while j < len(lines) and BLOCK_CALL_RE.match(lines[j].rstrip("\n")):
                    j += 1
                i = j
                continue
        out.append(line)
        i += 1
    return "".join(out)


def build_register_block(schemas: list[str]) -> str:
    lines = [
        "",
        "# Registrar schemas en el registry global (necesario para AgentContract)",
        "from god_tier_agency.agents.contract import _register_schema",
    ]
    for s in schemas:
        lines.append(f'_register_schema("{s}", {s})')
    lines.append("")
    return "\n".join(lines)


def fix_agent(path: Path, schemas: list[str]) -> str:
    """Repara un agente. Devuelve 'fixed' | 'already_ok' | 'missing' | 'error'."""
    if not path.exists():
        return "missing"

    content = path.read_text(encoding="utf-8")

    # 1. Eliminar bloques mal colocados de v1.0
    cleaned = remove_existing_block(content)

    # 2. Encontrar la última clase de schema (el Output, por convención)
    lines = cleaned.splitlines(keepends=True)
    last_schema = schemas[-1]
    end_idx = find_class_end_line(lines, last_schema)

    if end_idx is None:
        return "error"

    # 3. Verificar si el bloque correcto ya está justo después
    block = build_register_block(schemas)
    next_chunk = "".join(lines[end_idx + 1 : end_idx + len(block.splitlines()) + 2])
    already_correct = (
        '_register_schema' in next_chunk
        and schemas[0] in next_chunk
        and schemas[-1] in next_chunk
    )

    if already_correct and cleaned == content:
        return "already_ok"

    # 4. Insertar el bloque después del final de la clase
    before = "".join(lines[: end_idx + 1])
    after = "".join(lines[end_idx + 1 :])
    if not before.endswith("\n"):
        before += "\n"
    new_content = before + block + after

    # 5. Backup + escribir
    backup = path.with_suffix(path.suffix + ".bak")
    if not backup.exists():
        shutil.copy2(path, backup)

    path.write_text(new_content, encoding="utf-8")
    return "fixed"


def main() -> int:
    print("=" * 70)
    print("  fix_register_schemas.py — God-Tier v2.0")
    print("=" * 70)
    print()

    counts = {"fixed": 0, "already_ok": 0, "missing": 0, "error": 0}
    for path, schemas in AGENTS:
        rel = path.relative_to(ROOT)
        status = fix_agent(path, schemas)
        counts[status] += 1

        icon = {
            "fixed": "✅ REPARADO",
            "already_ok": "⏭️  YA OK",
            "missing": "❌ NO EXISTE",
            "error": "⚠️  ERROR",
        }[status]
        print(f"  {icon:14s} {rel}")

    print()
    print("=" * 70)
    print(f"  Reparados: {counts['fixed']} | Ya OK: {counts['already_ok']} | "
          f"Missing: {counts['missing']} | Error: {counts['error']}")
    print("=" * 70)

    return 0 if counts["error"] == 0 and counts["missing"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
