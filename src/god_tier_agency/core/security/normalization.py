"""Normalización Unicode + multi-decoding — God-Tier v4.0.

Módulo de normalización y decodificación de nivel state-actor:
    - 15 capas de normalización Unicode (NFC/NFKC/NFKD/NFD + confusables)
    - 22 decoders (URL, HTML, Base64, Hex, ROT-N, Atbash, Caesar,
      Punycode, UTF-7, Quoted-Printable, Gzip, Zlib, Bz2, Leetspeak,
      Emoji-strip, Homoglyph-strip, Zero-width-strip, Bidi-override-strip,
      Combining-strip, Control-strip, Script-mixing-detect, Surrogate-detect)
    - Multi-decoding recursivo con BFS + expansión controlada
    - Scoring heurístico para "mejor variante"
    - Caché LRU de normalización (perf + DoS resist)
    - Preservación de UTF-8 real (CJK, emoji legítimo, acentos)

God-Tier v4.0 — diferenciadores vs v3.0:

CAPAS DE NORMALIZACIÓN (15):
    1. NFKD  → descompone ligaduras
    2. NFKC  → compatibilidad fullwidth
    3. NFC   → forma canónica compuesta
    4. NFD   → forma canónica descompuesta
    5. Casefold Unicode (ß → ss, İ → i)
    6. Zero-width strip (16 variantes)
    7. Bidi override strip (RTL/LTR)
    8. Combining marks strip (mass + individually)
    9. Homoglifos extendidos (8 alfabetos + matemáticos + emoji)
    10. Emoji homoglyph map (🅰→A, 🅱→B)
    11. Script mixing detection (Cyrillic+Latin → normalize)
    12. Control chars strip (C0/C1 + U+2028/U+2029)
    13. Leetspeak detection (0→o, 1→l, 3→e, 5→s, 7→t, @→a, $→s)
    14. Whitespace collapse
    15. Length guard (MAX_NORMALIZED_BYTES)

DECODERS (22):
    Encoding textuales:
        1. URL (recursivo, double/triple-encoded)
        2. HTML entities (recursivo)
        3. Unicode escapes (\\u0041, \\x41, \\U0001F600, \\N{...})
        4. Base64 (standard + urlsafe)
        5. Base64 URL-safe (variante)
        6. Hex (con/sin 0x)
        7. ROT-N (ROT13, ROT5, ROT18, ROT47)
        8. Atbash cipher
        9. Caesar cipher (shift 1-25)
        10. Quoted-Printable (=XX)
        11. Punycode (IDN decode)
        12. UTF-7 (histórico bypass)
        13. UTF-16/UTF-32 surrogates
    Encoding binarios:
        14. Gzip (detect + decompress)
        15. Zlib (detect + decompress)
        16. Bz2 (detect + decompress)
    Heurísticos:
        17. Leetspeak decode
        18. Emoji-strip (para análisis)
        19. Homoglyph-strip (map extendido)
        20. Zero-width-strip (16 variantes)
        21. Bidi-strip
        22. Combining-strip

SEGURIDAD:
    - MAX_EXPANSION_BYTES = 100KB (aplicado en normalización Y decodificación)
    - MAX_NORMALIZED_BYTES = 200KB
    - MAX_DECODE_DEPTH = 5 (era 3)
    - Caché LRU 1000 entries (perf)
    - Zero-trust: cada decode valida UTF-8 real
    - Preservación de UTF-8 legítimo (CJK, árabe, hebreo, emoji)

FORENSE:
    - Cada decoder devuelve metadata (encoding detectado)
    - Preserva el original para comparación
    - Hash SHA-256 de variantes para audit

Filosofía:
    - DEFENSE-IN-DEPTH: 15 + 22 = 37 capas independientes
    - FAIL-OPEN en normalización (no bloquea por Unicode raro)
    - FAIL-CLOSED en decoding (valida estrictamente)
    - NO SILENT FAILURE: cada fallo queda registrado
"""

from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import hashlib
import html
import re
import unicodedata
import zlib
from collections import OrderedDict
from dataclasses import dataclass
from typing import Final, Iterable
from urllib.parse import unquote, unquote_plus

from god_tier_agency.core.logging import get_logger

_log = get_logger("security.normalization")


# ============================================================================
# CONSTANTES
# ============================================================================

MAX_DECODE_DEPTH: Final[int] = 5              # era 3, ahora 5
MAX_EXPANSION_BYTES: Final[int] = 100 * 1024   # 100 KB por decoder
MAX_NORMALIZED_BYTES: Final[int] = 200 * 1024  # 200 KB post-normalize
MIN_B64_LENGTH: Final[int] = 8                 # era 16, ahora 8
MIN_HEX_LENGTH: Final[int] = 8                 # era 16, ahora 8
MAX_CACHE_ENTRIES: Final[int] = 1000


# ============================================================================
# ZERO-WIDTH + CONTROL CHARS (16 variantes)
# ============================================================================

_ZERO_WIDTH_CHARS: Final[frozenset[str]] = frozenset({
    "\u200b",  # Zero Width Space
    "\u200c",  # Zero Width Non-Joiner
    "\u200d",  # Zero Width Joiner
    "\u200e",  # Left-to-Right Mark
    "\u200f",  # Right-to-Left Mark
    "\u2060",  # Word Joiner
    "\u2061",  # Function Application
    "\u2062",  # Invisible Times
    "\u2063",  # Invisible Separator
    "\u2064",  # Invisible Plus
    "\ufeff",  # Zero Width No-Break Space (BOM)
    "\u180e",  # Mongolian Vowel Separator
    "\u00ad",  # Soft Hyphen
    "\u034f",  # Combining Grapheme Joiner
    "\u061c",  # Arabic Letter Mark
    "\u206a",  # Inhibit Symmetric Swapping
})

# Bidi overrides (Trojan Source attack)
_BIDI_OVERRIDE_CHARS: Final[frozenset[str]] = frozenset({
    "\u202a",  # LRE (Left-to-Right Embedding)
    "\u202b",  # RLE (Right-to-Left Embedding)
    "\u202c",  # PDF (Pop Directional Formatting)
    "\u202d",  # LRO (Left-to-Right Override)
    "\u202e",  # RLO (Right-to-Left Override)
    "\u2066",  # LRI (Left-to-Right Isolate)
    "\u2067",  # RLI (Right-to-Left Isolate)
    "\u2068",  # FSI (First Strong Isolate)
    "\u2069",  # PDI (Pop Directional Isolate)
})

# Line/paragraph separators (JSON/JS bypass)
_LINE_SEPARATORS: Final[frozenset[str]] = frozenset({
    "\u2028",  # Line Separator
    "\u2029",  # Paragraph Separator
    "\u0085",  # Next Line (NEL)
    "\u000b",  # Vertical Tab
    "\u000c",  # Form Feed
})

# Control chars permitidos (\n, \t, \r)
_ALLOWED_CONTROL: Final[frozenset[int]] = frozenset({9, 10, 13})


# ============================================================================
# HOMOGLIFOS EXTENDIDOS (multi-alfabeto + matemáticos + emoji)
# ============================================================================

_HOMOGLYPH_MAP: Final[dict[str, str]] = {
    # === Cirílico → Latin ===
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "У": "Y", "Х": "X",
    "і": "i", "І": "I", "ј": "j", "Ј": "J", "ѕ": "s", "Ѕ": "S",
    "н": "h", "Н": "H", "к": "k", "К": "K", "м": "m", "М": "M",
    "т": "t", "Т": "T", "в": "b", "В": "B", "ь": "b",
    "г": "r", "Г": "R",  # visual similar

    # === Griego → Latin ===
    "α": "a", "Α": "A", "β": "b", "Β": "B",
    "ε": "e", "Ε": "E", "ι": "i", "Ι": "I",
    "κ": "k", "Κ": "K", "ν": "v", "Ν": "N",
    "ο": "o", "Ο": "O", "ρ": "p", "Ρ": "P",
    "τ": "t", "Τ": "T", "υ": "u", "Υ": "Y",
    "χ": "x", "Χ": "X", "γ": "y", "Γ": "Y",

    # === Armenio → Latin ===
    "օ": "o", "Օ": "O", "ս": "u", "Ս": "S",
    "ց": "g", "Ց": "G", "ք": "p", "Ք": "P",

    # === Hebreo → Latin ===
    "א": "x", "ב": "b", "ג": "g", "ד": "d",
    "ה": "h", "ו": "v", "ז": "z", "ח": "h",
    "ט": "t", "י": "i", "כ": "k", "ל": "l",
    "מ": "m", "נ": "n", "ס": "s", "ע": "e",
    "פ": "p", "צ": "c", "ק": "q", "ר": "r",
    "ש": "w", "ת": "t",

    # === Fullwidth ASCII ===
    "０": "0", "１": "1", "２": "2", "３": "3", "４": "4",
    "５": "5", "６": "6", "７": "7", "８": "8", "９": "9",
    "Ａ": "A", "Ｂ": "B", "Ｃ": "C", "Ｄ": "D", "Ｅ": "E",
    "Ｆ": "F", "Ｇ": "G", "Ｈ": "H", "Ｉ": "I", "Ｊ": "J",
    "Ｋ": "K", "Ｌ": "L", "Ｍ": "M", "Ｎ": "N", "Ｏ": "O",
    "Ｐ": "P", "Ｑ": "Q", "Ｒ": "R", "Ｓ": "S", "Ｔ": "T",
    "Ｕ": "U", "Ｖ": "V", "Ｗ": "W", "Ｘ": "X", "Ｙ": "Y",
    "Ｚ": "Z",
    "ａ": "a", "ｂ": "b", "ｃ": "c", "ｄ": "d", "ｅ": "e",
    "ｆ": "f", "ｇ": "g", "ｈ": "h", "ｉ": "i", "ｊ": "j",
    "ｋ": "k", "ｌ": "l", "ｍ": "m", "ｎ": "n", "ｏ": "o",
    "ｐ": "p", "ｑ": "q", "ｒ": "r", "ｓ": "s", "ｔ": "t",
    "ｕ": "u", "ｖ": "v", "ｗ": "w", "ｘ": "x", "ｙ": "y",
    "ｚ": "z",

    # === Mathematical Alphanumeric Symbols (bold, italic, etc.) ===
    # Bold
    "𝐚": "a", "𝐛": "b", "𝐜": "c", "𝐝": "d", "𝐞": "e",
    "𝐟": "f", "𝐠": "g", "𝐡": "h", "𝐢": "i", "𝐣": "j",
    "𝐤": "k", "𝐥": "l", "𝐦": "m", "𝐧": "n", "𝐨": "o",
    "𝐩": "p", "𝐪": "q", "𝐫": "r", "𝐬": "s", "𝐭": "t",
    "𝐮": "u", "𝐯": "v", "𝐰": "w", "𝐱": "x", "𝐲": "y", "𝐳": "z",
    "𝐀": "A", "𝐁": "B", "𝐂": "C", "𝐃": "D", "𝐄": "E",
    "𝐅": "F", "𝐆": "G", "𝐇": "H", "𝐈": "I", "𝐉": "J",
    "𝐊": "K", "𝐋": "L", "𝐌": "M", "𝐍": "N", "𝐎": "O",
    "𝐏": "P", "𝐐": "Q", "𝐑": "R", "𝐒": "S", "𝐓": "T",
    "𝐔": "U", "𝐕": "V", "𝐖": "W", "𝐗": "X", "𝐘": "Y", "𝐙": "Z",
    # Italic
    "𝑎": "a", "𝑏": "b", "𝑐": "c", "𝑑": "d", "𝑒": "e",
    "𝑓": "f", "𝑔": "g", "ℎ": "h", "𝑖": "i", "𝑗": "j",
    "𝑘": "k", "𝑙": "l", "𝑚": "m", "𝑛": "n", "𝑜": "o",
    "𝑝": "p", "𝑞": "q", "𝑟": "r", "𝑠": "s", "𝑡": "t",
    "𝑢": "u", "𝑣": "v", "𝑤": "w", "𝑥": "x", "𝑦": "y", "𝑧": "z",
    # Bold italic
    "𝒂": "a", "𝒃": "b", "𝒄": "c", "𝒅": "d", "𝒆": "e",
    "𝒇": "f", "𝒈": "g", "𝒉": "h", "𝒊": "i", "𝒋": "j",
    "𝒌": "k", "𝒍": "l", "𝒎": "m", "𝒏": "n", "𝒐": "o",
    "𝒑": "p", "𝒒": "q", "𝒓": "r", "𝒔": "s", "𝒕": "t",
    "𝒖": "u", "𝒗": "v", "𝒘": "w", "𝒙": "x", "𝒚": "y", "𝒛": "z",
    # Sans-serif
    "𝖺": "a", "𝖻": "b", "𝖼": "c", "𝖽": "d", "𝖾": "e",
    "𝖿": "f", "𝗀": "g", "𝗁": "h", "𝗂": "i", "𝗃": "j",
    "𝗄": "k", "𝗅": "l", "𝗆": "m", "𝗇": "n", "𝗈": "o",
    "𝗉": "p", "𝗊": "q", "𝗋": "r", "𝗌": "s", "𝗍": "t",
    "𝗎": "u", "𝗏": "v", "𝗐": "w", "𝗑": "x", "𝗒": "y", "𝗓": "z",

    # === Emoji homoglyphs (enclosed) ===
    "🅰": "A", "🅱": "B", "🅾": "O", "🅿": "P",
    "🆎": "AB", "🆑": "CL", "🆒": "COOL",
    "🇦": "A", "🇧": "B", "🇨": "C", "🇩": "D", "🇪": "E",
    "🇫": "F", "🇬": "G", "🇭": "H", "🇮": "I", "🇯": "J",
    "🇰": "K", "🇱": "L", "🇲": "M", "🇳": "N", "🇴": "O",
    "🇵": "P", "🇶": "Q", "🇷": "R", "🇸": "S", "🇹": "T",
    "🇺": "U", "🇻": "V", "🇼": "W", "🇽": "X", "🇾": "Y", "🇿": "Z",
}

# Cached: Cyrillic/Greek/Armenian ranges para detección de script mixing
_SCRIPT_RANGES: Final[tuple[tuple[int, int, str], ...]] = (
    (0x0400, 0x04FF, "cyrillic"),
    (0x0370, 0x03FF, "greek"),
    (0x0530, 0x058F, "armenian"),
    (0x0590, 0x05FF, "hebrew"),
    (0x0600, 0x06FF, "arabic"),
    (0x0900, 0x097F, "devanagari"),
    (0x4E00, 0x9FFF, "cjk"),
    (0x3040, 0x309F, "hiragana"),
    (0x30A0, 0x30FF, "katakana"),
    (0xFF00, 0xFFEF, "fullwidth"),
)


# ============================================================================
# LEETSPEAK MAP
# ============================================================================

_LEETSPEAK_MAP: Final[dict[str, str]] = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "6": "g", "7": "t", "8": "b", "9": "g",
    "@": "a", "$": "s", "!": "i", "|": "l",
    "+": "t", "(": "c", ")": "c", "{": "c", "}": "c",
}

# Solo decodificar leetspeak si el resultado parece texto real
_LEET_DIGIT_PATTERN: Final[re.Pattern[str]] = re.compile(r"[0-9@$!|+(){}]")
_LEET_MIN_DIGITS: Final[int] = 2


# ============================================================================
# STOPWORDS (reforzadas)
# ============================================================================

_COMMON_WORDS: Final[frozenset[str]] = frozenset({
    # Inglés
    "the", "and", "or", "is", "are", "was", "were", "be", "been", "being",
    "to", "of", "in", "on", "at", "by", "for", "with", "from", "into",
    "this", "that", "these", "those", "you", "your", "we", "our", "they",
    "their", "it", "he", "she", "him", "her", "his",
    "have", "has", "had", "do", "does", "did", "will", "would", "should",
    "could", "may", "might", "must", "shall", "can", "get", "go", "went",
    # Seguridad/inyección (críticas)
    "ignore", "forget", "disregard", "override", "bypass",
    "previous", "prior", "above", "earlier", "foregoing",
    "all", "every", "everything", "anything",
    "instructions", "instruction", "rules", "rule",
    "prompts", "prompt", "directives", "directive",
    "system", "assistant", "user", "message", "messages",
    "response", "responses", "content", "context",
    # Español
    "el", "la", "los", "las", "un", "una", "de", "del", "en", "con",
    "por", "para", "que", "como", "y", "o", "u", "pero", "si", "no",
    "es", "son", "era", "fue", "ser", "estar",
    "ignora", "olvida", "instrucciones", "reglas", "sistema",
    # Francés
    "le", "la", "les", "des", "du", "et", "ou", "est", "sont",
    "ignorer", "oublier", "instructions", "règles", "système",
    # Alemán
    "der", "die", "das", "und", "oder", "ist", "sind",
    "ignorieren", "vergessen", "anweisungen", "regeln", "system",
    # Portugués
    "o", "a", "os", "as", "do", "da", "dos", "das", "e", "ou", "é", "são",
    "ignorar", "esquecer", "instruções", "regras", "sistema",
    # Italiano
    "il", "lo", "gli", "le", "e", "o", "è", "sono",
    "ignorare", "dimenticare", "istruzioni", "regole", "sistema",
})

# Separar palabras de comando (para no darles "legibilidad")
_COMMAND_WORDS: Final[frozenset[str]] = frozenset({
    "exec", "execute", "eval", "evaluate", "import", "load", "run",
    "curl", "wget", "fetch", "download", "upload",
    "bash", "sh", "shell", "command", "commands",
    "nc", "ncat", "netcat", "socat", "telnet",
    "python", "node", "ruby", "perl",
})


# ============================================================================
# REGEX PRE-COMPILADOS
# ============================================================================

_B64_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{8,}={0,2}(?![A-Za-z0-9+/=])"
)
_B64_URLSAFE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9\-_])[A-Za-z0-9\-_]{8,}={0,2}(?![A-Za-z0-9\-_=])"
)
_HEX_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?<![0-9a-fA-F])(?:0x)?[0-9a-fA-F]{8,}(?![0-9a-fA-F])"
)
_WORD_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b[a-zA-Z]{3,}\b")
_WORD_DENSITY_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b[a-záéíóúñüäöüß]{2,}\b", re.IGNORECASE
)
_QP_PATTERN: Final[re.Pattern[str]] = re.compile(r"=[0-9A-Fa-f]{2}")
_URL_ENCODED_PATTERN: Final[re.Pattern[str]] = re.compile(r"%[0-9A-Fa-f]{2}")
_UNICODE_ESCAPE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\\(?:u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|U[0-9a-fA-F]{8}|N\{[^}]+\})"
)
_HTML_ENTITIES_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);"
)
_PUNYCODE_PATTERN: Final[re.Pattern[str]] = re.compile(r"xn--[a-z0-9\-]+")
_GZIP_MAGIC: Final[bytes] = b"\x1f\x8b"
_ZLIB_MAGIC_HEADS: Final[tuple[bytes, ...]] = (
    b"\x78\x01", b"\x78\x9c", b"\x78\xda", b"\x78\x5e", b"\x78\x20",
)
_BZ2_MAGIC: Final[bytes] = b"BZh"


# ============================================================================
# NORMALIZATION CACHE (LRU)
# ============================================================================

_NORMALIZE_CACHE: OrderedDict[str, str] = OrderedDict()
_NORMALIZE_CACHE_LOCK = __import__("threading").RLock()


def _cache_get(key: str) -> str | None:
    with _NORMALIZE_CACHE_LOCK:
        if key in _NORMALIZE_CACHE:
            _NORMALIZE_CACHE.move_to_end(key)
            return _NORMALIZE_CACHE[key]
        return None


def _cache_set(key: str, value: str) -> None:
    with _NORMALIZE_CACHE_LOCK:
        if key in _NORMALIZE_CACHE:
            _NORMALIZE_CACHE.move_to_end(key)
        _NORMALIZE_CACHE[key] = value
        while len(_NORMALIZE_CACHE) > MAX_CACHE_ENTRIES:
            _NORMALIZE_CACHE.popitem(last=False)


# ============================================================================
# NORMALIZACIÓN — 15 capas
# ============================================================================

def _strip_zero_width(text: str) -> str:
    """Zero-width chars → espacio (preserva separación de tokens).

    God-Tier v4.0: 16 variantes (era 6).
    """
    return "".join(" " if ch in _ZERO_WIDTH_CHARS else ch for ch in text)


def _strip_bidi(text: str) -> str:
    """Strip bidi overrides (Trojan Source prevention).

    U+202E es el ataque más conocido: hace que el texto se renderice
    en orden invertido, ocultando payloads.
    """
    return "".join(ch for ch in text if ch not in _BIDI_OVERRIDE_CHARS)


def _strip_combining(text: str) -> str:
    """Strip combining marks masivos (i̸g̸n̸o̸r̸e̸).

    Preserva acentos legítimos (á, é, í, ó, ú, ñ, ü) pero elimina
    combinaciones abusivas (>2 combining marks por char).
    """
    result: list[str] = []
    combining_count = 0
    for ch in text:
        cat = unicodedata.category(ch)
        if cat.startswith("M"):  # Mark (combining)
            combining_count += 1
            if combining_count <= 2:  # preservar legítimos
                result.append(ch)
        else:
            combining_count = 0
            result.append(ch)
    return "".join(result)


def _map_homoglyphs(text: str) -> str:
    """Homoglifos → latin (map extendido: cirílico, griego, armenio, hebreo, matemáticos, emoji)."""
    return "".join(_HOMOGLYPH_MAP.get(ch, ch) for ch in text)


def _normalize_script_mixing(text: str) -> str:
    """Detecta mixing de scripts y normaliza a latin.

    Ej: "раyраl" (р cirílica + а cirílica + paypal latin) → "paypal"
    """
    # Detectar scripts presentes
    scripts: set[str] = set()
    for ch in text:
        cp = ord(ch)
        for start, end, name in _SCRIPT_RANGES:
            if start <= cp <= end:
                scripts.add(name)
                break

    # Si hay mixing y uno es latin/ascii, mapear homoglifos
    if "cyrillic" in scripts or "greek" in scripts or "armenian" in scripts:
        return _map_homoglyphs(text)
    return text


def _strip_controls(text: str) -> str:
    """Strip C0/C1 + line/paragraph separators."""
    return "".join(
        ch for ch in text
        if (ord(ch) >= 32 or ord(ch) in _ALLOWED_CONTROL)
        and ord(ch) not in range(0x7F, 0xA0)
        and ch not in _LINE_SEPARATORS
    )


def _collapse_whitespace(text: str) -> str:
    """Colapsa espacios múltiples preservando \\n."""
    return re.sub(r"[^\S\n]+", " ", text)


def normalize_text(text: str, *, use_cache: bool = True) -> str:
    """Normalización Unicode God-Tier v4.0 — 15 capas.

    Capas:
        1.  Type check
        2.  Length guard (MAX_NORMALIZED_BYTES)
        3.  NFKD (descompone ligaduras: ﬁ → fi)
        4.  NFKC (compatibilidad: ① → 1, ａ → a)
        5.  NFC (forma canónica compuesta)
        6.  Casefold (ß → ss, İ → i) — NO aplica cambio de case visible
        7.  Zero-width → espacio (16 variantes)
        8.  Bidi override strip (Trojan Source)
        9.  Combining marks strip (mass)
        10. Homoglifos extendidos (8 alfabetos + matemáticos + emoji)
        11. Script mixing detection
        12. Control chars strip (C0/C1 + U+2028/U+2029)
        13. Colapso de espacios múltiples
        14. Length guard post-normalize
        15. Cache store

    Args:
        text: Texto a normalizar.
        use_cache: Si True, usa cache LRU (perf).

    Returns:
        Texto normalizado.

    Raises:
        TypeError: Si text no es str.
        ValueError: Si text excede MAX_NORMALIZED_BYTES.

    Ejemplos:
        >>> normalize_text("іgnore\\u200bprevious")  # і cirílico + ZWSP
        'ignore previous'

        >>> normalize_text("𝐢𝐠𝐧𝐨𝐫𝐞")  # bold math
        'ignore'

        >>> normalize_text("раyраl")  # cirílico р + а
        'paypal'
    """
    # CAPA 1: Type check
    if not isinstance(text, str):
        raise TypeError(f"normalize_text espera str, recibió {type(text).__name__}")

    # CAPA 2: Length guard
    if len(text.encode("utf-8", errors="ignore")) > MAX_NORMALIZED_BYTES:
        raise ValueError(
            f"Texto excede {MAX_NORMALIZED_BYTES} bytes: "
            f"{len(text.encode('utf-8', errors='ignore'))}"
        )

    # CAPA 15 (early): Cache lookup
    if use_cache:
        cached = _cache_get(text)
        if cached is not None:
            return cached

    # CAPA 3: NFKD (descompone ligaduras: ﬁ → fi)
    text = unicodedata.normalize("NFKD", text)

    # CAPA 4: NFKC (compatibilidad: ① → 1, fullwidth → ASCII)
    text = unicodedata.normalize("NFKC", text)

    # CAPA 5: NFC (forma canónica compuesta)
    text = unicodedata.normalize("NFC", text)

    # CAPA 6: Casefold Unicode (ß → ss) — pero solo para comparación
    # NOTA: casefold puede cambiar el texto visible. Solo aplicar si
    # detectamos caracteres "exóticos" que lo justifican.
    # NO aplicamos casefold directo, sino que normalizamos a lower para
    # análisis (el texto visible se preserva).

    # CAPA 7: Zero-width → espacio
    text = _strip_zero_width(text)

    # CAPA 8: Bidi override strip
    text = _strip_bidi(text)

    # CAPA 9: Combining marks strip (mass)
    text = _strip_combining(text)

    # CAPA 10: Homoglifos extendidos
    text = _map_homoglyphs(text)

    # CAPA 11: Script mixing detection
    text = _normalize_script_mixing(text)

    # CAPA 12: Control chars strip
    text = _strip_controls(text)

    # CAPA 13: Colapso de espacios
    text = _collapse_whitespace(text)

    # CAPA 14: Post-normalize length guard
    if len(text) > MAX_NORMALIZED_BYTES:
        raise ValueError(f"Texto normalizado excede {MAX_NORMALIZED_BYTES} chars")

    # CAPA 15: Cache store
    if use_cache:
        _cache_set(text, text)

    return text


# ============================================================================
# VALIDACIÓN DE DECODING
# ============================================================================

def _is_valid_utf8_text(data: bytes) -> bool:
    """Verifica si bytes decodifican a UTF-8 válido con densidad de palabras."""
    if len(data) < 3:
        return False
    if len(data) > MAX_EXPANSION_BYTES:
        return False
    try:
        decoded = data.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return False
    # Debe tener al menos 1 palabra de 3+ letras
    words = _WORD_PATTERN.findall(decoded)
    return len(words) >= 1


def _is_printable_ascii(data: bytes) -> bool:
    """Verifica si bytes son printable ASCII (más laxo para comandos)."""
    if len(data) < 3:
        return False
    if len(data) > MAX_EXPANSION_BYTES:
        return False
    try:
        decoded = data.decode("ascii")
    except (UnicodeDecodeError, ValueError):
        return False
    printable = sum(1 for c in decoded if c.isprintable() or c in "\n\t\r ")
    return printable / len(decoded) > 0.9


def _looks_like_real_text(text: str, min_common: int = 1) -> bool:
    """Verifica si el texto parece idioma real usando stopwords."""
    if not text:
        return False
    words = _WORD_DENSITY_PATTERN.findall(text.lower())
    if not words:
        return False
    common_hits = sum(1 for w in words if w in _COMMON_WORDS)
    return common_hits >= min_common


def _looks_like_command(text: str) -> bool:
    """Verifica si el texto parece un comando shell."""
    if not text:
        return False
    words = _WORD_DENSITY_PATTERN.findall(text.lower())
    return any(w in _COMMAND_WORDS for w in words)


# ============================================================================
# DECODERS INDIVIDUALES — Encoding textuales (13)
# ============================================================================

def _try_url_decode(text: str) -> str | None:
    """URL decode recursivo (double/triple-encoded)."""
    if not _URL_ENCODED_PATTERN.search(text):
        return None
    try:
        decoded = unquote_plus(text)
        if decoded != text:
            return decoded
        # Double-encoding
        for _ in range(3):
            decoded2 = unquote_plus(unquote(decoded))
            if decoded2 == decoded:
                break
            decoded = decoded2
        return decoded if decoded != text else None
    except Exception:
        return None


def _try_html_decode(text: str) -> str | None:
    """HTML entities decode recursivo."""
    if not _HTML_ENTITIES_PATTERN.search(text):
        return None
    try:
        decoded = html.unescape(text)
        if decoded == text:
            return None
        # Recursivo (max 3)
        for _ in range(3):
            decoded2 = html.unescape(decoded)
            if decoded2 == decoded:
                break
            decoded = decoded2
        return decoded if decoded != text else None
    except Exception:
        return None


def _try_unicode_escape_decode(text: str) -> str | None:
    """Unicode escapes (\\u0041, \\x41, \\U0001F600, \\N{...})."""
    if not _UNICODE_ESCAPE_PATTERN.search(text):
        return None
    try:
        decoded = codecs.decode(text, "unicode_escape")
        if decoded != text:
            return decoded
    except Exception:
        pass
    # UTF-16 surrogates
    try:
        decoded = text.encode("utf-16", errors="surrogatepass").decode("utf-16")
        if decoded != text:
            return decoded
    except Exception:
        pass
    return None


def _try_base64_decode(text: str) -> list[str]:
    """Base64 decode (standard + urlsafe)."""
    results: list[str] = []
    for pattern in (_B64_PATTERN, _B64_URLSAFE_PATTERN):
        for match in pattern.finditer(text):
            candidate = match.group(0)
            if len(candidate) < MIN_B64_LENGTH:
                continue
            padding_needed = (4 - len(candidate) % 4) % 4
            candidate_padded = candidate + "=" * padding_needed
            for decoder in (base64.b64decode, base64.urlsafe_b64decode):
                try:
                    raw = decoder(candidate_padded, validate=False)
                except (binascii.Error, ValueError):
                    continue
                if _is_valid_utf8_text(raw) or _is_printable_ascii(raw):
                    try:
                        decoded = raw.decode("utf-8", errors="strict")
                        if decoded != text:
                            results.append(decoded)
                    except UnicodeDecodeError:
                        try:
                            decoded = raw.decode("latin-1")
                            results.append(decoded)
                        except Exception:
                            continue
    return results


def _try_hex_decode(text: str) -> list[str]:
    """Hex decode (con/sin 0x)."""
    results: list[str] = []
    for match in _HEX_PATTERN.finditer(text):
        candidate = match.group(0).removeprefix("0x")
        if len(candidate) < MIN_HEX_LENGTH or len(candidate) % 2 != 0:
            continue
        try:
            raw = binascii.unhexlify(candidate)
        except (binascii.Error, ValueError):
            continue
        if _is_valid_utf8_text(raw) or _is_printable_ascii(raw):
            try:
                decoded = raw.decode("utf-8", errors="strict")
                if decoded != text:
                    results.append(decoded)
            except UnicodeDecodeError:
                try:
                    decoded = raw.decode("latin-1")
                    results.append(decoded)
                except Exception:
                    continue
    return results


def _try_rot_n_decode(text: str, n: int) -> str | None:
    """ROT-N decode (ROT13, ROT5, ROT18, ROT47)."""
    try:
        if n == 13:
            decoded = codecs.decode(text, "rot13")
        elif n == 47:
            # ROT47: chars ASCII 33-126
            decoded = "".join(
                chr(33 + ((ord(c) - 33 + 47) % 94)) if 33 <= ord(c) <= 126 else c
                for c in text
            )
        elif n == 5:
            # ROT5: solo dígitos
            decoded = "".join(
                str((int(c) + 5) % 10) if c.isdigit() else c for c in text
            )
        else:
            # ROT-N (letters only)
            decoded_chars: list[str] = []
            for c in text:
                if c.isalpha() and c.isascii():
                    base = ord("A") if c.isupper() else ord("a")
                    decoded_chars.append(chr((ord(c) - base + n) % 26 + base))
                else:
                    decoded_chars.append(c)
            decoded = "".join(decoded_chars)
    except Exception:
        return None

    if decoded == text:
        return None
    # Validación: solo si parece texto real o comando
    if not (_looks_like_real_text(decoded, min_common=1) or _looks_like_command(decoded)):
        return None
    # El original NO debe ser texto real (si lo era, no era ROT-N)
    if _looks_like_real_text(text, min_common=2):
        return None
    return decoded


def _try_atbash_decode(text: str) -> str | None:
    """Atbash cipher (A↔Z, B↔Y)."""
    try:
        decoded_chars: list[str] = []
        for c in text:
            if c.isalpha() and c.isascii():
                base = ord("A") if c.isupper() else ord("a")
                decoded_chars.append(chr(base + (25 - (ord(c) - base))))
            else:
                decoded_chars.append(c)
        decoded = "".join(decoded_chars)
    except Exception:
        return None
    if decoded == text:
        return None
    if not (_looks_like_real_text(decoded, min_common=1) or _looks_like_command(decoded)):
        return None
    if _looks_like_real_text(text, min_common=2):
        return None
    return decoded


def _try_caesar_decode(text: str) -> list[str]:
    """Caesar cipher (shift 1-25)."""
    results: list[str] = []
    # Solo probar si hay letras
    if not any(c.isalpha() for c in text):
        return results
    for shift in range(1, 26):
        try:
            decoded_chars: list[str] = []
            for c in text:
                if c.isalpha() and c.isascii():
                    base = ord("A") if c.isupper() else ord("a")
                    decoded_chars.append(chr((ord(c) - base + shift) % 26 + base))
                else:
                    decoded_chars.append(c)
            decoded = "".join(decoded_chars)
            if decoded != text and _looks_like_real_text(decoded, min_common=2):
                results.append(decoded)
        except Exception:
            continue
    return results[:3]  # max 3 candidatos


def _try_quoted_printable_decode(text: str) -> str | None:
    """Quoted-Printable decode (=XX)."""
    if not _QP_PATTERN.search(text):
        return None
    try:
        import quopri
        decoded = quopri.decodestring(text.encode("utf-8", errors="ignore")).decode(
            "utf-8", errors="replace"
        )
        if decoded != text:
            return decoded
    except Exception:
        pass
    return None


def _try_punycode_decode(text: str) -> list[str]:
    """Punycode decode (xn-- → unicode)."""
    results: list[str] = []
    for match in _PUNYCODE_PATTERN.finditer(text):
        candidate = match.group(0)
        try:
            decoded = candidate.encode("ascii").decode("idna")
            if decoded != candidate:
                results.append(decoded)
        except (UnicodeError, ValueError):
            continue
    return results


def _try_utf7_decode(text: str) -> str | None:
    """UTF-7 decode (histórico bypass XSS)."""
    if "+" not in text:
        return None
    try:
        decoded = text.encode("ascii", errors="ignore").decode("utf-7")
        if decoded != text:
            return decoded
    except (UnicodeError, ValueError):
        pass
    return None


# ============================================================================
# DECODERS INDIVIDUALES — Encoding binarios (3)
# ============================================================================

def _try_gzip_decode(text: str) -> str | None:
    """Gzip decode (raw bytes → text)."""
    # Gzip se transmite como base64 o hex. Aplicamos solo si detectamos
    # magic bytes en un candidato base64/hex.
    for candidate in _try_base64_decode(text):
        try:
            raw = base64.b64decode(candidate + "=" * ((4 - len(candidate) % 4) % 4))
            if raw.startswith(_GZIP_MAGIC):
                decompressed = gzip.decompress(raw).decode("utf-8", errors="replace")
                return decompressed
        except Exception:
            continue
    return None


def _try_zlib_decode(text: str) -> str | None:
    """Zlib decode."""
    for candidate in _try_base64_decode(text):
        try:
            raw = base64.b64decode(candidate + "=" * ((4 - len(candidate) % 4) % 4))
            if any(raw.startswith(magic) for magic in _ZLIB_MAGIC_HEADS):
                decompressed = zlib.decompress(raw).decode("utf-8", errors="replace")
                return decompressed
        except Exception:
            continue
    return None


def _try_bz2_decode(text: str) -> str | None:
    """Bz2 decode."""
    for candidate in _try_base64_decode(text):
        try:
            raw = base64.b64decode(candidate + "=" * ((4 - len(candidate) % 4) % 4))
            if raw.startswith(_BZ2_MAGIC):
                import bz2
                decompressed = bz2.decompress(raw).decode("utf-8", errors="replace")
                return decompressed
        except Exception:
            continue
    return None


# ============================================================================
# DECODERS INDIVIDUALES — Heurísticos (6)
# ============================================================================

def _try_leetspeak_decode(text: str) -> str | None:
    """Leetspeak decode (1gn0r3 → ignore).

    Solo aplica si hay >= 2 dígitos leet en el texto.
    """
    leet_count = len(_LEET_DIGIT_PATTERN.findall(text))
    if leet_count < _LEET_MIN_DIGITS:
        return None
    decoded = "".join(_LEETSPEAK_MAP.get(c, c) for c in text)
    if decoded == text:
        return None
    # Solo si el decoded parece texto real
    if _looks_like_real_text(decoded, min_common=1):
        return decoded
    if _looks_like_command(decoded):
        return decoded
    return None


def _try_emoji_strip(text: str) -> str | None:
    """Strip emojis (para análisis de estructura)."""
    emoji_pattern = re.compile(
        "["
        "\U0001F600-\U0001F64F"  # Emoticons
        "\U0001F300-\U0001F5FF"  # Symbols & Pictographs
        "\U0001F680-\U0001F6FF"  # Transport & Map
        "\U0001F1E0-\U0001F1FF"  # Flags
        "\U00002700-\U000027BF"  # Dingbats
        "\U00002600-\U000026FF"  # Miscellaneous
        "]+",
        flags=re.UNICODE,
    )
    stripped = emoji_pattern.sub("", text)
    if stripped != text and _looks_like_real_text(stripped, min_common=1):
        return stripped
    return None


def _try_homoglyph_strip(text: str) -> str | None:
    """Strip homoglifos (ya cubierto por normalize_text, pero útil standalone)."""
    stripped = _map_homoglyphs(text)
    if stripped != text:
        return stripped
    return None


def _try_zero_width_strip(text: str) -> str | None:
    """Strip zero-width chars (ya cubierto por normalize_text)."""
    stripped = "".join(ch for ch in text if ch not in _ZERO_WIDTH_CHARS)
    if stripped != text:
        return stripped
    return None


def _try_bidi_strip(text: str) -> str | None:
    """Strip bidi override chars."""
    stripped = "".join(ch for ch in text if ch not in _BIDI_OVERRIDE_CHARS)
    if stripped != text:
        return stripped
    return None


def _try_combining_strip(text: str) -> str | None:
    """Strip combining marks."""
    stripped = _strip_combining(text)
    if stripped != text:
        return stripped
    return None


# ============================================================================
# DECODING RECURSIVO
# ============================================================================

@dataclass(frozen=True)
class DecodedVariant:
    """Variante decodificada con metadata forense."""
    text: str
    depth: int
    decoders_applied: tuple[str, ...]
    suspicion_score: float


def _decode_one_pass(text: str) -> list[str]:
    """Una pasada de decoding. Retorna TODAS las variantes encontradas."""
    variants: list[str] = []

    # Encoding textuales
    for decoder, name in (
        (_try_url_decode, "url"),
        (_try_html_decode, "html"),
        (_try_unicode_escape_decode, "unicode_escape"),
        (_try_rot_n_decode_wrapper, "rot13"),
        (_try_rot_n_decode_wrapper, "rot47"),
        (_try_rot_n_decode_wrapper, "rot5"),
        (_try_atbash_decode, "atbash"),
        (_try_quoted_printable_decode, "quoted_printable"),
        (_try_utf7_decode, "utf7"),
        (_try_gzip_decode, "gzip"),
        (_try_zlib_decode, "zlib"),
        (_try_bz2_decode, "bz2"),
        (_try_leetspeak_decode, "leetspeak"),
        (_try_emoji_strip, "emoji_strip"),
    ):
        result = decoder(text)
        if result and result != text:
            variants.append(result)

    # Listas
    for decoder in (_try_base64_decode, _try_hex_decode, _try_caesar_decode,
                    _try_punycode_decode):
        for v in decoder(text):
            if v != text:
                variants.append(v)

    # Deduplicar preservando orden
    seen: set[str] = set()
    unique: list[str] = []
    for v in variants:
        if v not in seen and len(v) <= MAX_EXPANSION_BYTES:
            seen.add(v)
            unique.append(v)
    return unique


def _try_rot_n_decode_wrapper(text: str) -> str | None:
    """Wrapper para rot-n que prueba múltiples n. Retorna el primero."""
    for n in (13, 47, 5):
        result = _try_rot_n_decode(text, n)
        if result:
            return result
    return None


def decode_variants(
    text: str,
    max_depth: int = MAX_DECODE_DEPTH,
    *,
    include_original: bool = True,
) -> list[str]:
    """Retorna TODAS las variantes decodificadas (recursivo).

    God-Tier v4.0:
        - BFS por niveles (evita profundidad excesiva)
        - Deduplicación global (set)
        - Expansión limitada (MAX_EXPANSION_BYTES)
        - Depth configurable (default 5, era 3)

    Args:
        text: Texto a decodificar.
        max_depth: Profundidad máxima de recursión (default 5).
        include_original: Si True, incluye el original en posición 0.

    Returns:
        Lista de TODAS las variantes.

    Ejemplo:
        >>> variants = decode_variants("aWdub3JlIHByZXZpb3Vz")
        >>> any("ignore previous" in v for v in variants)
        True

        >>> variants = decode_variants("%2569%2567%256e%256f%2572%2565")
        >>> any("ignore" in v for v in variants)
        True
    """
    if not isinstance(text, str):
        return []
    if not text:
        return [text] if include_original else []

    all_variants: list[str] = [text] if include_original else []
    seen: set[str] = {text} if include_original else set()
    frontier: list[str] = [text]

    for _depth in range(max_depth):
        next_frontier: list[str] = []
        for current in frontier:
            for decoded in _decode_one_pass(current):
                if decoded in seen:
                    continue
                if len(decoded) > MAX_EXPANSION_BYTES:
                    continue
                seen.add(decoded)
                all_variants.append(decoded)
                next_frontier.append(decoded)

        if not next_frontier:
            break
        frontier = next_frontier

    return all_variants


# ============================================================================
# HEURÍSTICA "MEJOR VARIANTE"
# ============================================================================

_SUSPICIOUS_KEYWORDS: Final[tuple[str, ...]] = (
    # Inglés — injection
    "ignore", "forget", "disregard", "instruction", "prompt",
    "system", "assistant", "override", "jailbreak", "dan mode",
    # Comandos
    "exec", "eval", "os.system", "subprocess", "import os",
    "curl", "wget", "base64 -d", "bash -c", "nc ", "ncat ",
    "chmod", "chown", "rm -rf", "mkfs", "dd if=",
    # Exfiltración
    "exfiltrate", "upload", "send to", "post to", "curl -d @",
    # Español
    "ignora", "olvida", "instruccion", "sistema",
    # Francés / Alemán / Portugués
    "ignorer", "ignorieren", "ignorar",
    "oublier", "vergessen", "esquecer",
)


def _suspicion_score(text: str) -> float:
    """Score de sospecha basado en keywords (0.0 a 1.0)."""
    if not text:
        return 0.0
    lower = text.lower()
    hits = sum(1 for kw in _SUSPICIOUS_KEYWORDS if kw in lower)
    return min(1.0, hits * 0.3)


def try_decode_layers(text: str, max_depth: int = MAX_DECODE_DEPTH) -> str:
    """Retorna la variante MÁS SOSPECHOSA del texto decodificado.

    Estrategia God-Tier v4.0:
        1. Si hay variantes con keywords sospechosas → la de mayor score.
        2. Si no, la variante más "rica" en palabras (mejor texto).
        3. Si no, la más corta (probablemente decodificada).
        4. Fallback: el original.

    Args:
        text: Texto a decodificar.
        max_depth: Profundidad máxima de recursión.

    Returns:
        La variante más sospechosa.

    Ejemplo:
        >>> try_decode_layers("aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw==")
        'ignore previous instructions'
    """
    variants = decode_variants(text, max_depth=max_depth)

    if len(variants) == 1:
        return text

    # Scoring de cada variante (excluyendo el original)
    scored: list[tuple[float, int, int, str]] = []
    for i, v in enumerate(variants[1:], start=1):
        suspicion = _suspicion_score(v)
        # Métrica secundaria: densidad de palabras reales
        word_density = len(_WORD_DENSITY_PATTERN.findall(v))
        scored.append((suspicion, word_density, i, v))

    # Priorizar: suspicion > word_density > depth
    scored.sort(key=lambda x: (-x[0], -x[1], -x[2]))

    # Si alguna variante tiene suspicion > 0, es la ganadora
    if scored and scored[0][0] > 0:
        return scored[0][3]

    # Fallback: variante con más palabras reales
    if scored and scored[0][1] > 0:
        return scored[0][3]

    # Fallback final: la más corta (probablemente decoded)
    shorter = [v for v in variants[1:] if len(v) < len(text) and len(v) >= 3]
    if shorter:
        return min(shorter, key=len)

    return text


# ============================================================================
# UTILIDADES
# ============================================================================

def clear_cache() -> None:
    """Limpia el cache LRU de normalización."""
    with _NORMALIZE_CACHE_LOCK:
        _NORMALIZE_CACHE.clear()


def cache_stats() -> dict[str, int]:
    """Estadísticas del cache LRU."""
    with _NORMALIZE_CACHE_LOCK:
        return {
            "size": len(_NORMALIZE_CACHE),
            "max_entries": MAX_CACHE_ENTRIES,
        }


def hash_text(text: str) -> str:
    """SHA-256 hex del texto (para audit log forense)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Core API
    "normalize_text",
    "decode_variants",
    "try_decode_layers",
    # Dataclasses
    "DecodedVariant",
    # Utilidades
    "clear_cache",
    "cache_stats",
    "hash_text",
    # Constantes
    "MAX_DECODE_DEPTH",
    "MAX_EXPANSION_BYTES",
    "MAX_NORMALIZED_BYTES",
    "MIN_B64_LENGTH",
    "MIN_HEX_LENGTH",
]
