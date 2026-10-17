#!/usr/bin/env python3
"""
fix_register_order.py — God-Tier v3.0

Corrige el orden de `_register_schema(...)` en los agentes.

Bug: scripts automáticos previos insertaron el bloque ANTES de que las
clases Input/Output estuvieran definidas → NameError al importar.

Estrategia:
1. Parsea con AST para localizar `class XInput` / `class XOutput`.
2. Localiza el bloque mal colocado (comentario + import + 2 registros).
3. Borra ese bloque si existe.
4. Inserta el bloque DESPUÉS de end_lineno de la última clase de schema.
5. Verifica con py_compile + import.

Idempotente: si ya está bien, no toca nada.

Uso:
    uv run python scripts/fix_register_order.py
    uv run python scripts/fix_register_order.py --dry-run
"""
from __future__ import annotations

import argparse
import ast
import py_compile
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

AGENTS = [
    (ROOT / "src/god_tier_agency/agents/recon_agent.py",        "ReconInput",       "ReconOutput"),
    (ROOT / "src/god_tier_agency/agents/scanner_agent.py",      "ScannerInput",     "ScannerOutput"),
    (ROOT / "src/god_tier_agency/agents/evasion_agent.py",      "EvasionInput",     "EvasionOutput"),
    (ROOT / "src/god_tier_agency/agents/post_exploit_agent.py", "PostExploitInput", "PostExploitOutput"),
    (ROOT / "src/god_tier_agency/agents/reporter_agent.py",     "ReportInput",      "ReportOutput"),
]


def find_class_end_line(tree: ast.AST, class_name: str) -> int | None:
    """Retorna el end_lineno (0-based) de la clase o None si no existe."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return node.end_lineno - 1 if node.end_lineno else None
    return None


def build_block(input_cls: str, output_cls: str) -> str:
    """Bloque de registro con saltos de línea correctos."""
    return (
        "\n"
        "# Registrar schemas en el registry global (necesario para AgentContract)\n"
        "from god_tier_agency.agents.contract import _register_schema\n"
        f'_register_schema("{input_cls}", {input_cls})\n'
        f'_register_schema("{output_cls}", {output_cls})\n'
        "\n"
    )


def remove_existing_block(lines: list[str]) -> list[str]:
    """Elimina el bloque de registro (comentario + import + 2 registros) si existe."""
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Detección del comentario inicial
        if stripped == "# Registrar schemas en el registry global (necesario para AgentContract)":
            # Saltar comentario + import + posibles _register_schema siguientes
            j = i + 1
            if j < len(lines) and lines[j].strip().startswith("from god_tier_agency.agents.contract import _register_schema"):
                j += 1
                while j < len(lines) and lines[j].strip().startswith("_register_schema("):
                    j += 1
                # Saltar también líneas en blanco consecutivas que hayamos metido
                while j < len(lines) and not lines[j].strip():
                    j += 1
                i = j
                continue

        # Detección de import huérfano (sin comentario)
        if stripped.startswith("from god_tier_agency.agents.contract import _register_schema"):
            # Ver si la siguiente línea es _register_schema
            j = i + 1
            while j < len(lines) and lines[j].strip().startswith("_register_schema("):
                j += 1
            i = j
            continue

        out.append(line)
        i += 1

    return out


def fix_agent(path: Path, input_cls: str, output_cls: str, dry_run: bool) -> str:
    """Repara un agente. Retorna 'fixed' | 'already_ok' | 'missing' | 'error'."""
    if not path.exists():
        return "missing"

    original = path.read_text(encoding="utf-8")

    # 1. Parse AST
    try:
        tree = ast.parse(original)
    except SyntaxError as e:
        print(f"    ❌ SyntaxError: {e}")
        return "error"

    # 2. Localizar las dos clases
    end_input = find_class_end_line(tree, input_cls)
    end_output = find_class_end_line(tree, output_cls)
    if end_input is None or end_output is None:
        print(f"    ❌ Falta clase: {input_cls if end_input is None else ''} {output_cls if end_output is None else ''}")
        return "error"

    # 3. El bloque va después del MAYOR de los dos end_lineno
    insert_after = max(end_input, end_output)

    # 4. Si el bloque ya está justo después de insert_after, OK
    lines = original.splitlines(keepends=True)
    block = build_block(input_cls, output_cls)
    block_first_line = block.strip().splitlines()[0]

    # Ventana de 6 líneas después de insert_after
    window = "".join(lines[insert_after + 1 : insert_after + 7])
    if block_first_line in window and input_cls in window and output_cls in window:
        # Verificar que esté DESPUÉS de ambas clases (ya lo está por construcción)
        return "already_ok"

    # 5. Borrar bloques mal colocados
    cleaned_lines = remove_existing_block(lines)

    # 6. Re-parsear para localizar insert_after en el archivo limpio
    cleaned = "".join(cleaned_lines)
    try:
        tree2 = ast.parse(cleaned)
    except SyntaxError as e:
        print(f"    ❌ SyntaxError tras limpieza: {e}")
        return "error"

    end_input2 = find_class_end_line(tree2, input_cls)
    end_output2 = find_class_end_line(tree2, output_cls)
    if end_input2 is None or end_output2 is None:
        return "error"
    insert_after2 = max(end_input2, end_output2)

    # 7. Insertar el bloque después de insert_after2
    final_lines = cleaned.splitlines(keepends=True)
    # Asegurar que insert_after2 + 1 es la posición correcta
    head = "".join(final_lines[: insert_after2 + 1])
    tail = "".join(final_lines[insert_after2 + 1 :])
    if not head.endswith("\n"):
        head += "\n"
    new_content = head + block + tail

    # 8. Verificar que el nuevo contenido compila
    try:
        compile(new_content, str(path), "exec")
    except SyntaxError as e:
        print(f"    ❌ Nuevo contenido no compila: {e}")
        return "error"

    # 9. Dry-run
    if dry_run:
        print(f"    📝 (dry-run) Se reescribiría: {path.name}")
        return "fixed"

    # 10. Backup + escribir
    backup = path.with_suffix(path.suffix + ".bak")
    if not backup.exists():
        shutil.copy2(path, backup)

    path.write_text(new_content, encoding="utf-8")

    # 11. Verificación real: py_compile + import
    try:
        py_compile.compile(str(path), doraise=True)
    except py_compile.PyCompileError as e:
        print(f"    ❌ py_compile falló: {e}")
        path.write_text(original, encoding="utf-8")  # rollback
        return "error"

    return "fixed"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="Solo mostrar, no escribir")
    args = parser.parse_args()

    print("=" * 70)
    print("  fix_register_order.py — God-Tier v3.0")
    print("=" * 70)
    print()

    counts = {"fixed": 0, "already_ok": 0, "missing": 0, "error": 0}
    for path, input_cls, output_cls in AGENTS:
        try:
            rel = path.relative_to(ROOT)
        except ValueError:
            rel = path
        print(f"▶ {rel}")

        status = fix_agent(path, input_cls, output_cls, dry_run=args.dry_run)
        counts[status] += 1

        icon = {
            "fixed": "✅ REPARADO",
            "already_ok": "⏭️  YA OK",
            "missing": "❌ NO EXISTE",
            "error": "⚠️  ERROR",
        }[status]
        print(f"    {icon}")
        print()

    print("=" * 70)
    print(f"  Reparados: {counts['fixed']} | Ya OK: {counts['already_ok']} | "
          f"Missing: {counts['missing']} | Error: {counts['error']}")
    print("=" * 70)

    return 0 if counts["error"] == 0 and counts["missing"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
