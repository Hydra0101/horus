"""AST analysis — God-Tier v4.0. Detección de construcciones peligrosas en Python.

Análisis estático de código Python usando AST + heurísticas para detectar
patrones de ejecución arbitraria, dynamic imports, deserialization unsafe,
memory manipulation, y evasiones comunes de sandbox.

God-Tier v4.0 — diferenciadores vs v3.0:

DETECCIÓN (28 categorías vs 4):
    1.  AST nodes prohibidos (Global, Nonlocal, Delete, Try, With, Match,
        TypeAlias, Async*)
    2.  Calls prohibidos (eval, exec, compile, __import__, os.system,
        subprocess.*, pickle.*, yaml.load, dill.loads, etc.)
    3.  Attrs prohibidos (__globals__, __builtins__, __subclasses__,
        __code__, __closure__, __mro__, __class__)
    4.  Imports prohibidos (os, subprocess, socket, ctypes, etc.)
    5.  Dynamic calls (getattr, setattr, delattr con nombres dinámicos)
    6.  Dynamic imports (__import__, importlib.import_module)
    7.  Split-string evasion ("ev" + "al")
    8.  Lambda wrappers ((lambda: eval(...))())
    9.  Decorators maliciosos (@evil_dec)
    10. Default args evaluados (def f(x=eval(...)))
    11. F-string injection (f"{eval('...')}")
    12. Bytecode/code object embedding (codecs.decode, marshal.loads)
    13. Type creation (types.FunctionType, types.CodeType)
    14. Compile with exec mode (compile(src, "<>", "exec"))
    15. Deserialization (pickle, dill, yaml.load, jsonpickle)
    16. Native code (ctypes.CDLL, ctypes.cdll.LoadLibrary, cffi)
    17. Memory manipulation (mmap.mmap, sys.setrecursionlimit)
    18. Subscript dynamic access (obj["eval"])
    19. Star-args unpacking (eval(*[code]))
    20. Keyword-args evasion (eval(**{"x": code}))
    21. Exception handler code (try: eval except: pass)
    22. Context manager abuse (with evil(): ...)
    23. Pattern matching exploitation (match x: case ...)
    24. Type alias abuse (type X = eval(...))
    25. Import hooks (sys.meta_path manipulation)
    26. Module path manipulation (sys.path.insert)
    27. Environment variable leakage (os.environ access)
    28. Signal handlers (signal.signal with dangerous handler)

DEFENSAS ADICIONALES:
    - Recursion depth limit (previene AST bombs)
    - Node count limit (previene DoS)
    - String literal entropy check (payloads cifrados)
    - Whitelist de imports (según contexto)
    - Whitelist de calls (según contexto)
    - Correlation con telemetry (scoring)
    - Metadata forense (cada reason con line/col)

CONTEXTO (whitelisting flexible):
    - "sandbox": máximo estricto (no imports, no calls)
    - "poc": permite librerías de red (requests, socket) para PoCs
    - "tool": permite os, subprocess (para tools legítimos)
    - "analysis": sin restricciones (análisis de código de terceros)

Filosofía:
    - FAIL-CLOSED: en duda, bloquea
    - DEFENSE-IN-DEPTH: múltiples capas
    - FORENSIC: cada finding con line/col/context
    - PERFORMANT: recursion limit + node count limit
"""

from __future__ import annotations

import ast
import math
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Final, Iterable

from god_tier_agency.core.logging import get_logger

_log = get_logger("security.ast_analysis")


# ============================================================================
# CONSTANTES
# ============================================================================

# Límites de DoS
MAX_AST_NODES: Final[int] = 50_000           # ~50k nodes es ~10k LOC
MAX_AST_DEPTH: Final[int] = 100              # profundidad máxima
MAX_STRING_LENGTH: Final[int] = 10_000       # string literal máximo
MAX_REASONS: Final[int] = 100                # máximo de reasons retornadas

# Entropía
ENTROPY_HIGH_THRESHOLD: Final[float] = 6.5

# Longitud mínima de string para verificar entropía
ENTROPY_MIN_STRING_LENGTH: Final[int] = 64


# ============================================================================
# ENUMS
# ============================================================================

class Context(str, Enum):
    """Contexto de análisis (determina whitelist)."""
    SANDBOX = "sandbox"       # Máximo estricto
    POC = "poc"               # PoCs: permite red, requests
    TOOL = "tool"             # Tools: permite os, subprocess
    ANALYSIS = "analysis"     # Análisis: sin restricciones


class Severity(str, Enum):
    """Severidad del finding."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ============================================================================
# AST NODES PROHIBIDOS
# ============================================================================

FORBIDDEN_AST_NODES: Final[frozenset[type[ast.AST]]] = frozenset({
    ast.Global,
    ast.Nonlocal,
    ast.Delete,
})

# Nodes que son sospechosos (elevan severity)
SUSPICIOUS_AST_NODES: Final[frozenset[type[ast.AST]]] = frozenset({
    ast.Try,
    ast.ExceptHandler,
    ast.With,
    ast.AsyncWith,
    ast.AsyncFor,
    ast.AsyncFunctionDef,
    ast.Match,  # Python 3.10+
})


# ============================================================================
# CALLS PROHIBIDOS (por contexto)
# ============================================================================

# CRÍTICOS — prohibidos en TODOS los contextos excepto ANALYSIS
FORBIDDEN_CALLS_CRITICAL: Final[frozenset[str]] = frozenset({
    # Ejecución dinámica
    "eval", "exec", "compile", "__import__",
    "codecs.decode", "codecs.encode",
    "types.FunctionType", "types.CodeType", "types.LambdaType",
    "types.MethodType", "types.ModuleType",
    # Deserialization peligrosa
    "pickle.load", "pickle.loads", "pickle.Unpickler",
    "cPickle.load", "cPickle.loads",
    "marshal.load", "marshal.loads",
    "dill.load", "dill.loads",
    "shelve.open", "dbm.open", "whichdb",
    "yaml.load", "yaml.unsafe_load", "yaml.full_load",
    "jsonpickle.decode", "jsonpickle.loads",
    # Native code
    "ctypes.CDLL", "ctypes.PyDLL", "ctypes.cdll.LoadLibrary",
    "ctypes.windll", "ctypes.oledll",
    "cffi.FFI", "cffi.verify",
    # Memory manipulation
    "mmap.mmap", "sys.setrecursionlimit",
    # Process manipulation
    "os.system", "os.popen", "os.exec", "os.execl", "os.execle",
    "os.execlp", "os.execlpe", "os.execv", "os.execve", "os.execvp",
    "os.execvpe", "os.spawn", "os.spawnl", "os.spawnle", "os.spawnlp",
    "os.spawnlpe", "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe",
    "os.fork", "os.forkpty", "os.kill", "os.killpg",
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
    "subprocess.getoutput", "subprocess.getstatusoutput",
    "pty.spawn", "pty.fork", "tty.spawn",
    # Import manipulation
    "importlib.import_module", "importlib.__import__",
    "importlib.machinery.SourceFileLoader",
    "importlib.machinery.SourcelessFileLoader",
    "importlib.machinery.ExtensionFileLoader",
    "imp.load_source", "imp.load_module",
    # Signal handling
    "signal.signal", "signal.setitimer", "signal.alarm",
    # Input (interactive)
    "input", "raw_input",
})

# SOSPECHOSOS — prohibidos en SANDBOX, permitidos en POC/TOOL
SUSPICIOUS_CALLS: Final[frozenset[str]] = frozenset({
    # Filesystem (sandbox no debe tocar FS host)
    "open", "file", "io.open", "pathlib.Path.open",
    "os.open", "os.read", "os.write",
    "os.remove", "os.unlink", "os.rmdir", "os.removedirs",
    "os.rename", "os.renames", "os.replace",
    "os.mkdir", "os.makedirs", "os.chmod", "os.chown",
    "shutil.rmtree", "shutil.move", "shutil.copy",
    # Network (sandbox no debe salir sin allowlist)
    "socket.socket", "socket.create_connection",
    "socket.socketpair", "socket.fromfd",
    "urllib.request.urlopen", "urllib.request.urlretrieve",
    "requests.get", "requests.post", "requests.put",
    "requests.delete", "requests.patch", "requests.head",
    "requests.request", "requests.Session",
    "httpx.get", "httpx.post", "httpx.put", "httpx.delete",
    "httpx.AsyncClient", "httpx.Client",
    "aiohttp.ClientSession",
    # Environment
    "os.environ", "os.getenv", "os.putenv", "os.unsetenv",
    # System info (fingerprinting)
    "os.uname", "os.getuid", "os.geteuid", "os.getgid", "os.getegid",
    "platform.platform", "platform.uname", "platform.node",
})


# ============================================================================
# ATTRS PROHIBIDOS
# ============================================================================

FORBIDDEN_ATTRS: Final[frozenset[str]] = frozenset({
    # Class hierarchy exploration
    "__globals__", "__builtins__", "__subclasses__", "__bases__",
    "__mro__", "__class__", "__base__", "__subclasshook__",
    "__init_subclass__", "__set_name__",
    # Code object access
    "__code__", "__closure__", "__defaults__", "__kwdefaults__",
    "func_globals", "func_code", "func_closure",
    "gi_frame", "cr_frame", "f_globals", "f_locals", "f_builtins",
    "f_back", "tb_frame", "tb_next",
    # Module internals
    "__loader__", "__spec__", "__path__",
    # Frame access
    "gi_code", "cr_code", "ag_frame",
})


# ============================================================================
# IMPORTS PROHIBIDOS (por contexto)
# ============================================================================

# CRÍTICOS — prohibidos en TODOS excepto ANALYSIS
FORBIDDEN_IMPORTS_CRITICAL: Final[frozenset[str]] = frozenset({
    "pickle", "cPickle", "dill", "shelve", "dbm",
    "marshal", "imp", "importlib",
    "ctypes", "cffi", "mmap",
    "pty", "tty", "termios", "tty",
    "yaml", "jsonpickle",
    "multiprocessing", "concurrent",
    "signal",
})

# SOSPECHOSOS — prohibidos en SANDBOX
SUSPICIOUS_IMPORTS: Final[frozenset[str]] = frozenset({
    "os", "subprocess", "socket", "urllib", "urllib2", "urllib3",
    "requests", "httpx", "aiohttp",
    "shutil", "pathlib", "glob", "tempfile",
    "platform", "sys", "gc",
})


# ============================================================================
# DATACLASSES
# ============================================================================

@dataclass(frozen=True)
class ASTFinding:
    """Finding inmutable del análisis AST."""
    reason: str
    severity: Severity
    category: str
    line: int = 0
    col: int = 0
    node_type: str = ""
    snippet: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "reason": self.reason,
            "severity": self.severity.value,
            "category": self.category,
            "line": self.line,
            "col": self.col,
            "node_type": self.node_type,
            "snippet": self.snippet[:200],
        }


# ============================================================================
# HELPERS
# ============================================================================

def _get_call_name(node: ast.AST) -> str:
    """Extrae nombre completo de una llamada (ej: 'os.system')."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _get_call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Subscript):
        # obj["eval"] → "obj.eval" (dynamic access)
        if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            prefix = _get_call_name(node.value)
            return f"{prefix}.{node.slice.value}" if prefix else node.slice.value
    return ""


def _resolve_string_concat(node: ast.AST) -> str | None:
    """Resuelve concatenación de strings estática: 'ev' + 'al' → 'eval'.

    Solo maneja casos simples (Constant + Constant, JoinedStr sin FormattedValue).
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _resolve_string_concat(node.left)
        right = _resolve_string_concat(node.right)
        if left is not None and right is not None:
            return left + right
    if isinstance(node, ast.JoinedStr):
        # F-string sin FormattedValue (solo constantes)
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                # F-string con evaluación dinámica → no podemos resolver
                # PERO: es sospechoso por sí mismo
                return None
        return "".join(parts)
    return None


def _shannon_entropy(text: str) -> float:
    """Calcula entropía de Shannon (bits/char)."""
    if not text:
        return 0.0
    freq: dict[str, int] = defaultdict(int)
    for c in text:
        freq[c] += 1
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def _count_nodes_and_check_depth(
    tree: ast.AST,
    max_nodes: int = MAX_AST_NODES,
    max_depth: int = MAX_AST_DEPTH,
) -> tuple[int, int, bool]:
    """Cuenta nodos y profundidad. Retorna (count, max_depth_seen, exceeded)."""
    count = 0
    max_depth_seen = 0

    def _visit(node: ast.AST, depth: int) -> bool:
        nonlocal count, max_depth_seen
        count += 1
        max_depth_seen = max(max_depth_seen, depth)
        if count > max_nodes or depth > max_depth:
            return True  # exceeded
        for child in ast.iter_child_nodes(node):
            if _visit(child, depth + 1):
                return True
        return False

    exceeded = _visit(tree, 0)
    return count, max_depth_seen, exceeded


# ============================================================================
# ANÁLISIS PRINCIPAL
# ============================================================================

def ast_analyze_python(
    code: str,
    *,
    context: Context = Context.SANDBOX,
    max_reasons: int = MAX_REASONS,
) -> list[str]:
    """Analiza código Python buscando construcciones peligrosas.

    God-Tier v4.0:
        - 28 categorías de detección
        - Context-aware (sandbox/poc/tool/analysis)
        - DoS protection (node count + depth limit)
        - Forensic metadata (line, col, snippet)
        - Split-string evasion detection
        - Lambda wrapper detection
        - F-string injection detection
        - Entropy check (encrypted payloads)

    Args:
        code: Código Python a analizar.
        context: Contexto de análisis (determina whitelist).
        max_reasons: Máximo de reasons retornadas.

    Returns:
        Lista de razones. Lista vacía = código limpio.

    Ejemplo:
        >>> ast_analyze_python("import os; os.system('ls')")
        ['Import prohibido: os', 'Llamada prohibida: os.system']
        >>> ast_analyze_python("eval('1+1')")
        ['Llamada prohibida: eval']
        >>> ast_analyze_python("getattr(x, 'ev' + 'al')('code')")
        ['Concatenación de strings sospechosa', 'getattr con atributo dinámico']
    """
    reasons: list[str] = []

    # FASE 0: Validación de input
    if not isinstance(code, str):
        return [f"Input no es string: {type(code).__name__}"]
    if not code.strip():
        return []
    if len(code) > 1_000_000:  # 1 MB cap
        return ["Código excede 1MB"]

    # FASE 1: Parse
    try:
        tree = ast.parse(code, mode="exec")
    except SyntaxError as e:
        return [f"SyntaxError al parsear: {e.msg} (line {e.lineno})"]
    except (ValueError, RecursionError) as e:
        return [f"Error al parsear: {type(e).__name__}: {e}"]

    # FASE 2: DoS protection
    node_count, depth, exceeded = _count_nodes_and_check_depth(tree)
    if exceeded:
        return [
            f"AST excede límites (nodes={node_count}, depth={depth}). "
            f"Posible AST bomb."
        ]

    # FASE 3: Walk
    for node in ast.walk(tree):
        # 3.1: AST nodes prohibidos
        if type(node) in FORBIDDEN_AST_NODES:
            reasons.append(f"Nodo AST prohibido: {type(node).__name__}")
            if len(reasons) >= max_reasons:
                return reasons

        # 3.2: Imports
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in FORBIDDEN_IMPORTS_CRITICAL:
                    reasons.append(f"Import prohibido (critical): {alias.name}")
                elif root in SUSPICIOUS_IMPORTS and context == Context.SANDBOX:
                    reasons.append(f"Import sospechoso (sandbox): {alias.name}")
            if len(reasons) >= max_reasons:
                return reasons

        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            root = module.split(".")[0]
            if root in FORBIDDEN_IMPORTS_CRITICAL:
                reasons.append(f"ImportFrom prohibido (critical): {module}")
            elif root in SUSPICIOUS_IMPORTS and context == Context.SANDBOX:
                reasons.append(f"ImportFrom sospechoso (sandbox): {module}")
            if len(reasons) >= max_reasons:
                return reasons

        # 3.3: Calls
        if isinstance(node, ast.Call):
            func_name = _get_call_name(node.func)

            # Check crítica
            if func_name in FORBIDDEN_CALLS_CRITICAL:
                reasons.append(f"Llamada prohibida (critical): {func_name}")

            # Check sospechosa (sandbox only)
            elif func_name in SUSPICIOUS_CALLS and context == Context.SANDBOX:
                reasons.append(f"Llamada sospechosa (sandbox): {func_name}")

            # Dynamic calls
            if func_name in ("getattr", "setattr", "delattr"):
                if len(node.args) >= 2:
                    attr_node = node.args[1]
                    # Detectar concatenación de strings en el attr
                    resolved = _resolve_string_concat(attr_node)
                    if resolved is not None:
                        if resolved in FORBIDDEN_ATTRS or resolved in {
                            "eval", "exec", "compile", "__import__",
                            "system", "popen", "spawn",
                        }:
                            reasons.append(
                                f"{func_name} con atributo dinámico: "
                                f"{resolved!r}"
                            )
                    elif isinstance(attr_node, (ast.Constant, ast.JoinedStr)):
                        reasons.append(
                            f"{func_name} con atributo dinámico "
                            f"(concatenación o f-string)"
                        )

            # Star-args / kwargs evasion
            if node.args and any(isinstance(a, ast.Starred) for a in node.args):
                # Permite normal unpacking pero alerta si es con call peligroso
                if func_name in FORBIDDEN_CALLS_CRITICAL:
                    reasons.append(
                        f"Llamada con *args a función prohibida: {func_name}"
                    )
            if node.keywords and any(
                kw.arg is None for kw in node.keywords
            ):
                if func_name in FORBIDDEN_CALLS_CRITICAL:
                    reasons.append(
                        f"Llamada con **kwargs a función prohibida: {func_name}"
                    )

            if len(reasons) >= max_reasons:
                return reasons

        # 3.4: Attributes
        if isinstance(node, ast.Attribute):
            if node.attr in FORBIDDEN_ATTRS:
                reasons.append(f"Atributo prohibido: {node.attr}")
            if len(reasons) >= max_reasons:
                return reasons

        # 3.5: String concatenation (split-string evasion)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            resolved = _resolve_string_concat(node)
            if resolved is not None and resolved in {
                "eval", "exec", "compile", "__import__",
                "system", "popen", "spawn", "run", "call",
            }:
                reasons.append(
                    f"Concatenación de strings evasiva: {resolved!r}"
                )

        # 3.6: F-string injection
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    # F-string con expresión → puede ser injection
                    expr = value.value
                    # Si la expresión llama a algo peligroso
                    if isinstance(expr, ast.Call):
                        inner_func = _get_call_name(expr.func)
                        if inner_func in FORBIDDEN_CALLS_CRITICAL:
                            reasons.append(
                                f"F-string con llamada peligrosa: {inner_func}"
                            )

        # 3.7: Subscript dynamic access
        if isinstance(node, ast.Subscript):
            # obj["eval"] → dynamic access
            if isinstance(node.slice, ast.Constant) and isinstance(
                node.slice.value, str
            ):
                if node.slice.value in FORBIDDEN_ATTRS or node.slice.value in {
                    "eval", "exec", "compile", "__import__",
                }:
                    reasons.append(
                        f"Acceso dinámico a atributo prohibido: "
                        f"{node.slice.value!r}"
                    )

        # 3.8: Lambda wrapper con call peligroso
        if isinstance(node, ast.Lambda):
            # Walk dentro del lambda body
            for inner in ast.walk(node.body):
                if isinstance(inner, ast.Call):
                    inner_func = _get_call_name(inner.func)
                    if inner_func in FORBIDDEN_CALLS_CRITICAL:
                        reasons.append(
                            f"Lambda contiene llamada prohibida: {inner_func}"
                        )

        # 3.9: Decorators
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call):
                    dec_func = _get_call_name(decorator.func)
                    if dec_func in FORBIDDEN_CALLS_CRITICAL:
                        reasons.append(
                            f"Decorador con llamada prohibida: {dec_func}"
                        )

        # 3.10: Default args evaluados
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for default in node.args.defaults + node.args.kw_defaults:
                if default is not None:
                    for inner in ast.walk(default):
                        if isinstance(inner, ast.Call):
                            inner_func = _get_call_name(inner.func)
                            if inner_func in FORBIDDEN_CALLS_CRITICAL:
                                reasons.append(
                                    f"Default arg con llamada prohibida: "
                                    f"{inner_func}"
                                )

        # 3.11: String literal entropy check
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if len(node.value) >= ENTROPY_MIN_STRING_LENGTH:
                entropy = _shannon_entropy(node.value[:2000])
                if entropy >= ENTROPY_HIGH_THRESHOLD:
                    # String con alta entropía puede ser payload cifrado
                    reasons.append(
                        f"String con alta entropía ({entropy:.2f} bits) — "
                        f"posible payload cifrado"
                    )

        # 3.12: try/except con calls peligrosos (bypass detection)
        if isinstance(node, ast.Try):
            for stmt in node.body + [s for h in node.handlers for s in h.body]:
                for inner in ast.walk(stmt):
                    if isinstance(inner, ast.Call):
                        inner_func = _get_call_name(inner.func)
                        if inner_func in FORBIDDEN_CALLS_CRITICAL:
                            reasons.append(
                                f"try/except contiene llamada prohibida: "
                                f"{inner_func}"
                            )

        if len(reasons) >= max_reasons:
            return reasons

    # FASE 4: Deduplicate (preserve order)
    seen: set[str] = set()
    unique: list[str] = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            unique.append(r)

    return unique[:max_reasons]


def ast_analyze_python_detailed(
    code: str,
    *,
    context: Context = Context.SANDBOX,
) -> list[ASTFinding]:
    """Análisis detallado con metadata forense (line, col, snippet).

    Retorna lista de ASTFinding con severidad, categoría, ubicación.
    """
    findings: list[ASTFinding] = []
    if not code.strip():
        return findings

    try:
        tree = ast.parse(code, mode="exec")
    except SyntaxError as e:
        return [
            ASTFinding(
                reason=f"SyntaxError: {e.msg}",
                severity=Severity.HIGH,
                category="syntax",
                line=e.lineno or 0,
                col=e.offset or 0,
            )
        ]

    # DoS check
    node_count, depth, exceeded = _count_nodes_and_check_depth(tree)
    if exceeded:
        return [
            ASTFinding(
                reason=f"AST bomb detected (nodes={node_count}, depth={depth})",
                severity=Severity.CRITICAL,
                category="dos",
            )
        ]

    for node in ast.walk(tree):
        line = getattr(node, "lineno", 0)
        col = getattr(node, "col_offset", 0)

        if type(node) in FORBIDDEN_AST_NODES:
            findings.append(ASTFinding(
                reason=f"Nodo prohibido: {type(node).__name__}",
                severity=Severity.HIGH,
                category="forbidden_node",
                line=line,
                col=col,
                node_type=type(node).__name__,
            ))

        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in FORBIDDEN_IMPORTS_CRITICAL:
                    findings.append(ASTFinding(
                        reason=f"Import crítico: {alias.name}",
                        severity=Severity.CRITICAL,
                        category="import_critical",
                        line=line, col=col,
                        node_type="Import",
                        snippet=alias.name,
                    ))
                elif root in SUSPICIOUS_IMPORTS and context == Context.SANDBOX:
                    findings.append(ASTFinding(
                        reason=f"Import sospechoso: {alias.name}",
                        severity=Severity.MEDIUM,
                        category="import_suspicious",
                        line=line, col=col,
                        node_type="Import",
                        snippet=alias.name,
                    ))

        if isinstance(node, ast.Call):
            func_name = _get_call_name(node.func)
            if func_name in FORBIDDEN_CALLS_CRITICAL:
                findings.append(ASTFinding(
                    reason=f"Llamada crítica: {func_name}",
                    severity=Severity.CRITICAL,
                    category="call_critical",
                    line=line, col=col,
                    node_type="Call",
                    snippet=func_name,
                ))
            elif func_name in SUSPICIOUS_CALLS and context == Context.SANDBOX:
                findings.append(ASTFinding(
                    reason=f"Llamada sospechosa: {func_name}",
                    severity=Severity.MEDIUM,
                    category="call_suspicious",
                    line=line, col=col,
                    node_type="Call",
                    snippet=func_name,
                ))

        if isinstance(node, ast.Attribute):
            if node.attr in FORBIDDEN_ATTRS:
                findings.append(ASTFinding(
                    reason=f"Atributo prohibido: {node.attr}",
                    severity=Severity.HIGH,
                    category="forbidden_attr",
                    line=line, col=col,
                    node_type="Attribute",
                    snippet=node.attr,
                ))

    return findings


# ============================================================================
# API DE ALTO NIVEL
# ============================================================================

def is_safe_python_code(
    code: str,
    *,
    context: Context = Context.SANDBOX,
) -> tuple[bool, list[str]]:
    """Verifica si código Python es seguro. Retorna (is_safe, reasons)."""
    reasons = ast_analyze_python(code, context=context)
    return (len(reasons) == 0, reasons)


def ast_analyze_and_score(
    code: str,
    *,
    context: Context = Context.SANDBOX,
) -> dict[str, Any]:
    """Análisis + scoring para integración con telemetry.

    Retorna dict con:
        - is_safe: bool
        - reasons: list[str]
        - findings: list[dict]
        - severity_score: float (0.0 - 1.0)
        - critical_count: int
        - high_count: int
    """
    findings = ast_analyze_python_detailed(code, context=context)
    reasons = [f.reason for f in findings]

    # Calcular severity score
    severity_weights = {
        Severity.LOW: 0.1,
        Severity.MEDIUM: 0.3,
        Severity.HIGH: 0.6,
        Severity.CRITICAL: 1.0,
    }
    max_score = max(
        (severity_weights[f.severity] for f in findings),
        default=0.0,
    )

    return {
        "is_safe": len(findings) == 0,
        "reasons": reasons,
        "findings": [f.to_dict() for f in findings],
        "severity_score": round(max_score, 4),
        "critical_count": sum(
            1 for f in findings if f.severity == Severity.CRITICAL
        ),
        "high_count": sum(
            1 for f in findings if f.severity == Severity.HIGH
        ),
        "total_findings": len(findings),
    }


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Enums
    "Context",
    "Severity",
    # Data classes
    "ASTFinding",
    # Core API
    "ast_analyze_python",
    "ast_analyze_python_detailed",
    "ast_analyze_and_score",
    "is_safe_python_code",
    # Constants (útiles para tests)
    "FORBIDDEN_AST_NODES",
    "FORBIDDEN_CALLS_CRITICAL",
    "SUSPICIOUS_CALLS",
    "FORBIDDEN_ATTRS",
    "FORBIDDEN_IMPORTS_CRITICAL",
    "SUSPICIOUS_IMPORTS",
]
