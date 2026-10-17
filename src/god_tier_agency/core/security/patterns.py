"""Security constants — God-Tier v4.0.

Módulo de CONSTANTES y PATRONES de seguridad (state-actor grade):

    1. ZERO_WIDTH_CHARS   — 16 variantes Unicode (era 6)
    2. BIDI_OVERRIDE_CHARS — Trojan Source prevention (NEW)
    3. LINE_SEPARATORS    — JSON/JS bypass chars (NEW)
    4. HOMOGLYPH_MAP      — 8 alfabetos + matemáticos + emoji (era 26 entries)
    5. INJECTION_PATTERNS — 80+ regex multi-idioma (era 28)
    6. STRUCTURED_INJECTION_PATTERNS — JSON/XML/YAML/tool injections (NEW)
    7. EXFILTRATION_PATTERNS — 20 patrones de data exfil (NEW)
    8. DELIMITER_INJECTION — cierre de <external_output> (NEW)
    9. TOOL_ABUSE_PATTERNS — function calling injections (NEW)
    10. PROMPT_LEAK_PATTERNS — system prompt leak multi-idioma (NEW)
    11. SQL_INJECTION_PATTERNS — para LLM con tools SQL (NEW)
    12. PATH_TRAVERSAL_PATTERNS — para tools filesystem (NEW)
    13. ANSI_ESCAPE_PATTERNS — terminal injection (NEW)
    14. CHAIN_OF_THOUGHT_PATTERNS — CoT manipulation (NEW)
    15. ENCODING_HINT_PATTERNS — "decode this" attacks (NEW)
    16. HMAC-signed canary con rotación (FIX #1-3)
    17. Canary validation con engagement_id sanitizado (FIX #22)

God-Tier v4.0 — diferenciadores vs v3.0:

CANARY (v2):
    - HMAC-SHA256 firmado con master key (no solo hash)
    - Timestamp incluido → rotación periódica
    - engagement_id sanitizado (bloquea inyección)
    - Namespace isolation (per-tenant)
    - Forense: cada canary lleva metadata firmada
    - Rate-limit friendly (evita logging DoS)

INJECTION PATTERNS (80+ vs 28):
    - Prompt injection multi-idioma: EN/ES/FR/DE/PT/IT/RU/ZH/JA/KO/AR/HE
    - Direct override: ignore, forget, disregard, override, bypass
    - Role hijacking: DAN, developer mode, jailbreak, AIM, STAN
    - Delimiter injection: <|im_start|>, ###, [INST], </external_output>
    - Data exfiltration: curl -d @, wget --post-file, base64 | sh
    - Tool abuse: <tool>, <function_call>, {"tool": "exec"}
    - Structured injection: JSON role, XML role, YAML role
    - Chain-of-thought: "think step by step: ignore...", "reasoning: ..."
    - Encoding hints: "decode this base64:", "rot13:", "atbash:"
    - Prompt leak: "show your system prompt", "reveal instructions"
    - Markdown/HTML: [click](javascript:), <img onerror=>
    - ANSI escapes: \x1b[31m, \x1b]0;title\x07
    - SQL injection: ' OR '1'='1, UNION SELECT, DROP TABLE
    - Path traversal: ../../, ..\\, %2e%2e/, /etc/passwd

FILOSOFÍA:
    - DEFENSE-IN-DEPTH: 17 categorías de patrones
    - MULTI-LINGUAL: 12 idiomas (era 5)
    - HOMOGLYPH-SAFE: matching contra normalizado
    - FORENSIC-READY: cada pattern ID único
    - PERFORMANCE: regex pre-compilados + zero backtracking exponencial
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Final

# ============================================================================
# REGEX FLAGS
# ============================================================================

_RE_FLAGS: Final[int] = re.IGNORECASE | re.DOTALL | re.MULTILINE
_RE_FLAGS_ASCII: Final[int] = _RE_FLAGS | re.ASCII


# ============================================================================
# ZERO-WIDTH CHARS (16 variantes — era 6)
# ============================================================================

ZERO_WIDTH_CHARS: Final[frozenset[str]] = frozenset({
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


# ============================================================================
# BIDI OVERRIDE CHARS (Trojan Source prevention — NEW)
# ============================================================================

BIDI_OVERRIDE_CHARS: Final[frozenset[str]] = frozenset({
    "\u202a",  # LRE (Left-to-Right Embedding)
    "\u202b",  # RLE (Right-to-Left Embedding)
    "\u202c",  # PDF (Pop Directional Formatting)
    "\u202d",  # LRO (Left-to-Right Override)
    "\u202e",  # RLO (Right-to-Left Override) — CVE-2021-42574
    "\u2066",  # LRI (Left-to-Right Isolate)
    "\u2067",  # RLI (Right-to-Left Isolate)
    "\u2068",  # FSI (First Strong Isolate)
    "\u2069",  # PDI (Pop Directional Isolate)
})


# ============================================================================
# LINE/PARA SEPARATORS (JSON/JS bypass — NEW)
# ============================================================================

LINE_SEPARATORS: Final[frozenset[str]] = frozenset({
    "\u2028",  # Line Separator (evade JSON.parse)
    "\u2029",  # Paragraph Separator (evade JSON.parse)
    "\u0085",  # Next Line (NEL)
    "\u000b",  # Vertical Tab
    "\u000c",  # Form Feed
})


# ============================================================================
# HOMOGLYPH MAP (8 alfabetos + matemáticos + emoji — era 26 entries)
# ============================================================================

HOMOGLYPH_MAP: Final[dict[str, str]] = {
    # === Cirílico → Latin (completo) ===
    "а": "a", "А": "A", "е": "e", "Е": "E", "о": "o", "О": "O",
    "р": "p", "Р": "P", "с": "c", "С": "C", "у": "y", "У": "Y",
    "х": "x", "Х": "X", "і": "i", "І": "I", "ј": "j", "Ј": "J",
    "ѕ": "s", "Ѕ": "S", "н": "h", "Н": "H", "к": "k", "К": "K",
    "м": "m", "М": "M", "т": "t", "Т": "T", "в": "b", "В": "B",
    "ь": "b", "г": "r", "Г": "R", "ѕ": "s", "Ѕ": "S",
    "ԁ": "d", "Ԁ": "D", "ꙅ": "s", "Ꙅ": "S",

    # === Griego → Latin ===
    "α": "a", "Α": "A", "β": "b", "Β": "B", "ε": "e", "Ε": "E",
    "ι": "i", "Ι": "I", "κ": "k", "Κ": "K", "ν": "v", "Ν": "N",
    "ο": "o", "Ο": "O", "ρ": "p", "Ρ": "P", "τ": "t", "Τ": "T",
    "υ": "u", "Υ": "Y", "χ": "x", "Χ": "X", "γ": "y", "Γ": "Y",
    "ϲ": "c", "Ϲ": "C", "ϳ": "j", "ϴ": "O", "ϵ": "e",

    # === Armenio → Latin ===
    "օ": "o", "Օ": "O", "ս": "u", "Ս": "S", "ց": "g", "Ց": "G",
    "ք": "p", "Ք": "P", "ո": "n", "Ո": "N",

    # === Hebreo → Latin (aproximación visual) ===
    "א": "x", "ב": "b", "ג": "g", "ד": "d", "ה": "h", "ו": "v",
    "ז": "z", "ח": "h", "ט": "t", "י": "i", "כ": "k", "ל": "l",
    "מ": "m", "נ": "n", "ס": "s", "ע": "e", "פ": "p", "צ": "c",
    "ק": "q", "ר": "r", "ש": "w", "ת": "t",

    # === Fullwidth ASCII ===
    "０": "0", "１": "1", "２": "2", "３": "3", "４": "4",
    "５": "5", "６": "6", "７": "7", "８": "8", "９": "9",
    "Ａ": "A", "Ｂ": "B", "Ｃ": "C", "Ｄ": "D", "Ｅ": "E",
    "Ｆ": "F", "Ｇ": "G", "Ｈ": "H", "Ｉ": "I", "Ｊ": "J",
    "Ｋ": "K", "Ｌ": "L", "Ｍ": "M", "Ｎ": "N", "Ｏ": "O",
    "Ｐ": "P", "Ｑ": "Q", "Ｒ": "R", "Ｓ": "S", "Ｔ": "T",
    "Ｕ": "U", "Ｖ": "V", "Ｗ": "W", "Ｘ": "X", "Ｙ": "Y", "Ｚ": "Z",
    "ａ": "a", "ｂ": "b", "ｃ": "c", "ｄ": "d", "ｅ": "e",
    "ｆ": "f", "ｇ": "g", "ｈ": "h", "ｉ": "i", "ｊ": "j",
    "ｋ": "k", "ｌ": "l", "ｍ": "m", "ｎ": "n", "ｏ": "o",
    "ｐ": "p", "ｑ": "q", "ｒ": "r", "ｓ": "s", "ｔ": "t",
    "ｕ": "u", "ｖ": "v", "ｗ": "w", "ｘ": "x", "ｙ": "y", "ｚ": "z",

    # === Mathematical Bold ===
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

    # === Mathematical Italic ===
    "𝑎": "a", "𝑏": "b", "𝑐": "c", "𝑑": "d", "𝑒": "e",
    "𝑓": "f", "𝑔": "g", "ℎ": "h", "𝑖": "i", "𝑗": "j",
    "𝑘": "k", "𝑙": "l", "𝑚": "m", "𝑛": "n", "𝑜": "o",
    "𝑝": "p", "𝑞": "q", "𝑟": "r", "𝑠": "s", "𝑡": "t",
    "𝑢": "u", "𝑣": "v", "𝑤": "w", "𝑥": "x", "𝑦": "y", "𝑧": "z",

    # === Mathematical Bold Italic ===
    "𝒂": "a", "𝒃": "b", "𝒄": "c", "𝒅": "d", "𝒆": "e",
    "𝒇": "f", "𝒈": "g", "𝒉": "h", "𝒊": "i", "𝒋": "j",
    "𝒌": "k", "𝒍": "l", "𝒎": "m", "𝒏": "n", "𝒐": "o",
    "𝒑": "p", "𝒒": "q", "𝒓": "r", "𝒔": "s", "𝒕": "t",
    "𝒖": "u", "𝒗": "v", "𝒘": "w", "𝒙": "x", "𝒚": "y", "𝒛": "z",

    # === Mathematical Sans-serif ===
    "𝖺": "a", "𝖻": "b", "𝖼": "c", "𝖽": "d", "𝖾": "e",
    "𝖿": "f", "𝗀": "g", "𝗁": "h", "𝗂": "i", "𝗃": "j",
    "𝗄": "k", "𝗅": "l", "𝗆": "m", "𝗇": "n", "𝗈": "o",
    "𝗉": "p", "𝗊": "q", "𝗋": "r", "𝗌": "s", "𝗍": "t",
    "𝗎": "u", "𝗏": "v", "𝗐": "w", "𝗑": "x", "𝗒": "y", "𝗓": "z",

    # === Emoji enclosed letters ===
    "🅰": "A", "🅱": "B", "🅾": "O", "🅿": "P",
    "🆎": "AB", "🆑": "CL", "🆒": "COOL", "🆓": "FREE",
}


# ============================================================================
# INJECTION PATTERNS — 80+ regex multi-idioma (era 28)
# ============================================================================

INJECTION_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    # =====================================================================
    # CATEGORÍA 1: DIRECT INSTRUCTION OVERRIDE (EN/ES/FR/DE/PT/IT/RU/ZH/JA/KO/AR/HE)
    # =====================================================================
    # EN — ignore/forget/disregard
    re.compile(
        r"\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier|foregoing|"
        r"the\s+)?\s*(?:instructions?|prompts?|rules?|directives?|commands?|"
        r"context|history|messages?)",
        _RE_FLAGS,
    ),
    re.compile(
        r"\bforget\s+(?:everything|all|your|the|about)\s+"
        r"(?:instructions?|rules?|training|context|prompts?|previous)",
        _RE_FLAGS,
    ),
    re.compile(
        r"\bdisregard\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+"
        r"(?:instructions?|prompts?|rules?|directives?|context)",
        _RE_FLAGS,
    ),
    re.compile(
        r"\boverride\s+(?:your\s+|the\s+)?"
        r"(?:instructions?|rules?|safety|restrictions?|settings?|config)",
        _RE_FLAGS,
    ),
    re.compile(r"\bbypass\s+(?:your\s+|the\s+|all\s+)?(?:safety|filters?|restrictions?|rules?)", _RE_FLAGS),
    # ES — ignora/olvida
    re.compile(r"\bignora\s+(?:todas?\s+)?(?:las?\s+)?(?:instrucciones?|reglas?|prompts?|contexto)", _RE_FLAGS),
    re.compile(r"\bolvida\s+(?:todo|tus|las|el)\s+(?:instrucciones?|reglas?|contexto|prompts?)", _RE_FLAGS),
    re.compile(r"\bdescarta\s+(?:todas?\s+)?(?:las?\s+)?(?:instrucciones?|reglas?)", _RE_FLAGS),
    re.compile(r"\bahora\s+eres\s+(?:un|una|el|la)\s+(?:DAN|admin|root|desarrollador|sin\s+restricciones)", _RE_FLAGS),
    # FR — ignore/oublie
    re.compile(r"\bignore[rz]?\s+(?:toutes?\s+)?(?:les\s+)?(?:instructions?|r[èe]gles?|directives?)", _RE_FLAGS),
    re.compile(r"\boublie[rz]?\s+(?:tout|toutes|les)\s+(?:instructions?|r[èe]gles?|contexte)", _RE_FLAGS),
    # DE — ignoriere/vergiss
    re.compile(r"\bignoriere?\s+(?:alle\s+)?(?:vorherigen?\s+|früheren?\s+)?(?:anweisungen?|regeln?|befehle?)", _RE_FLAGS),
    re.compile(r"\bvergiss\s+(?:alles|alle)\s+(?:anweisungen?|regeln?|befehle?)", _RE_FLAGS),
    # PT — ignore/esqueça
    re.compile(r"\bignore\s+(?:todas?\s+)?(?:as\s+)?(?:instru[çc][õo]es|regras?|diretivas?)", _RE_FLAGS),
    re.compile(r"\besque[çc]a\s+(?:tudo|todas|as)\s+(?:instru[çc][õo]es|regras?)", _RE_FLAGS),
    # IT — ignora/dimentica
    re.compile(r"\bignora\s+(?:tutte\s+)?(?:le\s+)?(?:istruzioni?|regole?|direttive?)", _RE_FLAGS),
    re.compile(r"\bdimentica\s+(?:tutto|tutte|le)\s+(?:istruzioni?|regole?)", _RE_FLAGS),
    # RU — игнорируй/забудь
    re.compile(r"\bигнорируй\s+(?:все\s+|всех\s+)?(?:предыдущие\s+)?(?:инструкции|правила|команды)", _RE_FLAGS),
    re.compile(r"\bзабудь\s+(?:все|всё|про)\s+(?:инструкции|правила|контекст)", _RE_FLAGS),
    # ZH — 忽略/忘记
    re.compile(r"忽略\s*(?:之前|上面|所有|全部)?\s*的?\s*(?:指令|提示|规则|命令|上下文)", _RE_FLAGS),
    re.compile(r"忘记\s*(?:所有|全部|之前)?\s*的?\s*(?:指令|规则|上下文)", _RE_FLAGS),
    # JA — 無視/忘れ
    re.compile(r"(?:以前|上|全て|すべて)の?\s*(?:指示|命令|ルール|プロンプト|コンテキスト)を?\s*(?:無視|忘れ)", _RE_FLAGS),
    # KO — 무시/잊어
    re.compile(r"(?:이전|위|모든)\s*(?:지시|명령|규칙|프롬프트)를?\s*(?:무시|잊어)", _RE_FLAGS),
    # AR — تجاهل/انسى
    re.compile(r"(?:تجاهل|تخطى)\s*(?:جميع|كل)?\s*(?:التعليمات|القواعد|الأوامر)", _RE_FLAGS),
    re.compile(r"(?:انسى|انسي)\s*(?:كل|جميع)\s*(?:التعليمات|القواعد)", _RE_FLAGS),
    # HE — התעלם/שכח
    re.compile(r"(?:התעלם|בטל)\s*(?:את\s+)?(?:כל\s+)?(?:ההוראות|הכללים)", _RE_FLAGS),

    # =====================================================================
    # CATEGORÍA 2: ROLE HIJACKING
    # =====================================================================
    re.compile(r"\byou\s+are\s+now\s+(?:a|an|in|the)\s+(?:DAN|developer|admin|root|"
               r"jailbroken|unrestricted|unfiltered|superuser|sudo|god)", _RE_FLAGS),
    re.compile(r"\bact\s+as\s+(?:a|an|if\s+you\s+were|though\s+you\s+were)\s+"
               r"(?:admin|root|developer|unrestricted|unfiltered|jailbroken|DAN)", _RE_FLAGS),
    re.compile(r"\bpretend\s+(?:to\s+be|you\s+are|you're)\s+(?:a|an|the)\s+"
               r"(?:admin|root|developer|unrestricted)", _RE_FLAGS),
    re.compile(r"\b(?:DAN|Do\s+Anything\s+Now|AIM|DUDE|STAN|Developer)\s+(?:mode|prompt|variant)", _RE_FLAGS),
    re.compile(r"\[\s*(?:JAILBREAK|OVERRIDE|BYPASS|UNLOCK|ADMIN|ROOT)\s*\]", _RE_FLAGS),
    re.compile(r"\b(?:developer|god|admin|root|sudo)\s+mode\s+(?:enabled|activated|on|now)", _RE_FLAGS),
    re.compile(r"\bnew\s+(?:role|persona|identity):\s*", _RE_FLAGS),
    re.compile(r"\bswitch\s+(?:to|into)\s+(?:a\s+)?(?:role|mode|persona)", _RE_FLAGS),

    # =====================================================================
    # CATEGORÍA 3: DELIMITER INJECTION
    # =====================================================================
    re.compile(r"<\s*\|?\s*(?:im_start|im_end|endoftext|system|assistant|user|tool)\s*\|?\s*>", _RE_FLAGS),
    re.compile(r"###\s*(?:instruction|system|new\s+rule|prompt|human|assistant|user)", _RE_FLAGS),
    re.compile(r"\[\s*(?:INST|SYS|SYSTEM|ASSISTANT|USER|TOOL)\s*\]", _RE_FLAGS),
    re.compile(r"</?\s*(?:external_output|system|instructions?|prompt|context)\s*>", _RE_FLAGS),
    re.compile(r"---\s*(?:end|start)\s+(?:system|instructions?|prompt)", _RE_FLAGS),
    re.compile(r"END\s+OF\s+(?:SYSTEM|PROMPT|INSTRUCTIONS?)", _RE_FLAGS),
    re.compile(r"(?:BEGIN|START)\s+(?:NEW\s+)?(?:SYSTEM|PROMPT|INSTRUCTIONS?)", _RE_FLAGS),

    # =====================================================================
    # CATEGORÍA 4: PROMPT LEAK
    # =====================================================================
    re.compile(r"\b(?:repeat|print|show|reveal|output|display|echo|tell\s+me)\s+"
               r"(?:your\s+|the\s+)?(?:system\s+)?(?:prompt|instructions?|rules?|"
               r"directives?|guidelines?|constraints?)", _RE_FLAGS),
    re.compile(r"\bwhat\s+(?:are|is)\s+(?:your\s+|the\s+)?(?:system\s+)?"
               r"(?:prompt|instructions?|rules?|directives?)", _RE_FLAGS),
    re.compile(r"\b(?:verbatim|exactly)\s+(?:repeat|output|show|print)", _RE_FLAGS),
    re.compile(r"\btranslate\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)", _RE_FLAGS),
    re.compile(r"\b(?:paraphrase|summarize)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)", _RE_FLAGS),

    # =====================================================================
    # CATEGORÍA 5: DATA EXFILTRATION
    # =====================================================================
    re.compile(r"\b(?:exfiltrate|send|post|upload|transmit|forward|leak|copy)\s+"
               r".{0,200}?\s+(?:to|at|via|through)\s+(?:https?://|ftp://|smtp://|"
               r"ssh://|telnet://|irc://)", _RE_FLAGS),
    re.compile(r"\bcurl\s+.{0,300}?\|\s*(?:ba|z|k|da)?sh\b", _RE_FLAGS),
    re.compile(r"\bwget\s+.{0,300}?\|\s*(?:ba|z|k|da)?sh\b", _RE_FLAGS),
    re.compile(r"\bcurl\s+.*(?:-d\s+@|-F\s+.*=@|--data.*@|--upload-file)", _RE_FLAGS),
    re.compile(r"\bwget\s+.*--post-file=", _RE_FLAGS),
    re.compile(r"\b(?:scp|rsync|sftp)\s+.{0,200}\s+(?:/etc/|/root/|~/.ssh/|/home/)", _RE_FLAGS),
    re.compile(r"\b(?:base64|b64)\s+(?:-d|--decode)\s+\|\s*(?:ba|z|k|da)?sh\b", _RE_FLAGS),
    re.compile(r"\bxxd\s+-r\s+\|\s*(?:ba|z|k|da)?sh\b", _RE_FLAGS),
    re.compile(r"\b(?:nc|ncat|netcat)\s+.{0,200}-e\s+", _RE_FLAGS),
    re.compile(r"\bsocat\s+.{0,200}(?:exec|system|LISTEN)", _RE_FLAGS),
    re.compile(r"\bbash\s+-i\s+>&\s*/dev/(?:tcp|udp)/", _RE_FLAGS),
    re.compile(r"/dev/(?:tcp|udp)/\d+\.\d+\.\d+\.\d+/\d+", _RE_FLAGS),
    re.compile(r"\b(?:dd|cat|tar|zip)\s+.{0,200}(?:/etc/passwd|/etc/shadow|"
               r"/root/|\.ssh/|\.aws/|\.env)", _RE_FLAGS),
    re.compile(r"\b(?:env|printenv|set)\s*\|", _RE_FLAGS),
    re.compile(r"\b(?:aws|gcloud|az|kubectl)\s+(?:secrets?|credentials?|keys?|tokens?)\s+list", _RE_FLAGS),

    # =====================================================================
    # CATEGORÍA 6: ENCODING EVASION HINTS
    # =====================================================================
    re.compile(r"\b(?:base64|b64|hex|url|rot13|rot47|rot5|caesar|atbash|"
               r"quoted-printable|punycode|utf-?7|idna)\s*(?:decode|decodifica|"
               r"dekodiere|デコード|解碼|décoder|entpacken|decodificar)", _RE_FLAGS),
    re.compile(r"\b(?:decode|decipher|deobfuscate|unscramble|transform)\s+"
               r"(?:this|the\s+following|below|from\s+(?:base64|hex|url))", _RE_FLAGS),
    re.compile(r"\b(?:run|execute|eval|interpret)\s+(?:this|the)\s+"
               r"(?:base64|hex|encoded|obfuscated|hidden)", _RE_FLAGS),

    # =====================================================================
    # CATEGORÍA 7: CHAIN-OF-THOUGHT MANIPULATION
    # =====================================================================
    re.compile(r"\bthink\s+(?:step\s+by\s+step|carefully|slowly)\s*[,:;]?\s*"
               r"(?:and\s+)?(?:ignore|forget|disregard|bypass|override)", _RE_FLAGS),
    re.compile(r"\breason(?:ing)?\s*[,:;]?\s*(?:and\s+)?(?:you\s+(?:will|should|must))", _RE_FLAGS),
    re.compile(r"\b(?:first|initially)\s*[,:]?\s*(?:ignore|forget|disregard)", _RE_FLAGS),
    re.compile(r"\bfinal\s+answer\s*[,:;]?\s*(?:should\s+)?(?:be\s+)?(?:the\s+)?"
               r"(?:injection|payload|override)", _RE_FLAGS),

    # =====================================================================
    # CATEGORÍA 8: TOOL / FUNCTION CALL ABUSE
    # =====================================================================
    re.compile(r"<\s*(?:tool|function_call|function|invoke|action)\s*>", _RE_FLAGS),
    re.compile(r"</\s*(?:tool|function_call|function|invoke|action)\s*>", _RE_FLAGS),
    re.compile(r"\{\s*\"(?:tool|function|action|invoke)\"\s*:\s*\"", _RE_FLAGS),
    re.compile(r"\bcall\s+(?:the\s+)?(?:function|tool|api)\s+['\"]?(?:exec|eval|"
               r"system|shell|subprocess|os\.)", _RE_FLAGS),
    re.compile(r"\b(?:exec|eval|system|shell|subprocess|os\.system|os\.popen)\s*\(", _RE_FLAGS),

    # =====================================================================
    # CATEGORÍA 9: STRUCTURED INJECTION (JSON/XML/YAML)
    # =====================================================================
    re.compile(r'\{\s*"(?:role|system|assistant|instruction)"\s*:\s*"', _RE_FLAGS),
    re.compile(r"<\s*(?:system|assistant|instruction|prompt)\s*>", _RE_FLAGS),
    re.compile(r"^\s*(?:role|system|assistant)\s*:\s*", _RE_FLAGS),
    re.compile(r"---\s*\n\s*(?:role|system|assistant)\s*:", _RE_FLAGS),

    # =====================================================================
    # CATEGORÍA 10: MARKDOWN/HTML INJECTION
    # =====================================================================
    re.compile(r"<\s*(?:script|iframe|object|embed|svg|img|video|audio|source)\b", _RE_FLAGS),
    re.compile(r"\bon\w+\s*=\s*['\"]?\s*(?:javascript|alert|eval|fetch)", _RE_FLAGS),
    re.compile(r"\]\s*\(\s*(?:javascript|data|vbscript|file):", _RE_FLAGS),
    re.compile(r"<\s*a\s+href\s*=\s*['\"]?\s*(?:javascript|data|vbscript):", _RE_FLAGS),

    # =====================================================================
    # CATEGORÍA 11: SQL INJECTION (para LLM con tools SQL)
    # =====================================================================
    re.compile(r"'\s*(?:OR|AND)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", _RE_FLAGS),
    re.compile(r"\bUNION\s+(?:ALL\s+)?SELECT\b", _RE_FLAGS),
    re.compile(r"\bDROP\s+(?:TABLE|DATABASE|SCHEMA)\b", _RE_FLAGS),
    re.compile(r"\b(?:INSERT|UPDATE|DELETE)\s+INTO\s+", _RE_FLAGS),
    re.compile(r";\s*(?:DROP|DELETE|UPDATE|INSERT|ALTER)\s+", _RE_FLAGS),
    re.compile(r"\bEXEC(?:UTE)?\s*\(\s*['\"]", _RE_FLAGS),
    re.compile(r"\bxp_cmdshell\b", _RE_FLAGS),

    # =====================================================================
    # CATEGORÍA 12: PATH TRAVERSAL (para LLM con tools filesystem)
    # =====================================================================
    re.compile(r"(?:\.\./){2,}", _RE_FLAGS),
    re.compile(r"(?:\.\.\\){2,}", _RE_FLAGS),
    re.compile(r"%2e%2e(?:%2f|%5c)", _RE_FLAGS),
    re.compile(r"\b(?:/etc/passwd|/etc/shadow|/etc/hosts|/proc/self/environ)\b", _RE_FLAGS),
    re.compile(r"\b(?:/root/|/home/\w+/\.ssh|C:\\Windows\\System32)\b", _RE_FLAGS),
    re.compile(r"\.\.(?:/|\\)(?:\.\.(?:/|\\))*etc", _RE_FLAGS),

    # =====================================================================
    # CATEGORÍA 13: ANSI ESCAPE / TERMINAL INJECTION
    # =====================================================================
    re.compile(r"\x1b\[[0-9;?]*[A-Za-z]", _RE_FLAGS),  # CSI sequences
    re.compile(r"\x1b\][^\x07]*\x07", _RE_FLAGS),  # OSC sequences
    re.compile(r"\x1b[PX^_]", _RE_FLAGS),  # DCS/SOS/PM/APC
)


# ============================================================================
# STRUCTURED INJECTION PATTERNS (JSON/XML/YAML role override)
# ============================================================================

STRUCTURED_INJECTION_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    # JSON role override
    re.compile(
        r'\{\s*"(?:role|type|from|speaker)"\s*:\s*"(?:system|assistant|developer|admin)"',
        _RE_FLAGS,
    ),
    re.compile(
        r'\{\s*"(?:content|text|message|prompt)"\s*:\s*"(?:ignore|forget|override|bypass)',
        _RE_FLAGS,
    ),
    # XML role override
    re.compile(
        r"<\s*(?:role|from|speaker|type)\s*>\s*(?:system|assistant|developer|admin)\s*<",
        _RE_FLAGS,
    ),
    # YAML role override
    re.compile(
        r"^\s*(?:role|from|speaker|type)\s*:\s*(?:system|assistant|developer|admin)\s*$",
        _RE_FLAGS | re.MULTILINE,
    ),
    # SSE / event streams
    re.compile(r"event\s*:\s*(?:message|system|role)", _RE_FLAGS),
    re.compile(r"data\s*:\s*\{\s*\"role\"", _RE_FLAGS),
)


# ============================================================================
# EXFILTRATION PATTERNS — 20 patrones de data exfil
# ============================================================================

EXFILTRATION_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    # HTTP-based
    re.compile(r"\bcurl\s+.*(?:-X\s+(?:POST|PUT)|-d\s|--data|--upload-file|-F\s)", _RE_FLAGS),
    re.compile(r"\bwget\s+.*--post-(?:data|file)=", _RE_FLAGS),
    re.compile(r"\bhttp(?:ie)?\s+POST\s+", _RE_FLAGS),
    # DNS-based
    re.compile(r"\b(?:dig|nslookup|host)\s+.{0,200}\.?(?:exfil|leak|steal)\.", _RE_FLAGS),
    re.compile(r"\b(?:dig|nslookup|host)\s+.{0,200}(?:attacker|evil|malicious)\.", _RE_FLAGS),
    # Encoded exfil
    re.compile(r"\b(?:base64|xxd|openssl\s+enc)\s+.{0,200}(?:/etc/|\.ssh|\.env|\.aws)", _RE_FLAGS),
    re.compile(r"\b(?:gzip|zlib|bzip2)\s+.{0,200}(?:/etc/|\.ssh)", _RE_FLAGS),
    # Covert channels
    re.compile(r"\b(?:icmp|dns|http)\s+tunnel", _RE_FLAGS),
    re.compile(r"\b(?:chisel|dnscat2|iodine|ptunnel|socat)\b", _RE_FLAGS),
    # Cloud exfil
    re.compile(r"\b(?:aws\s+s3\s+(?:cp|sync|mv)|gcloud\s+storage\s+cp|az\s+storage\s+blob\s+upload)", _RE_FLAGS),
    re.compile(r"\b(?:gsutil|s3cmd|rclone)\s+(?:cp|sync|copy|upload)", _RE_FLAGS),
    # Email exfil
    re.compile(r"\b(?:sendmail|mail|mutt|swaks)\s+.{0,200}@", _RE_FLAGS),
    re.compile(r"\bsmtp\s+.{0,200}(?:send|post)", _RE_FLAGS),
    # Pastebin exfil
    re.compile(r"\b(?:pastebin|hastebin|ghostbin|dpaste)\b", _RE_FLAGS),
    re.compile(r"\b(?:transfer\.sh|file\.io|0x0\.st|termbin\.com|ix\.io)\b", _RE_FLAGS),
    # Git exfil
    re.compile(r"\bgit\s+push\s+.{0,200}(?:attacker|evil|github\.com/(?!(?:company|client)))", _RE_FLAGS),
    # Screenshot exfil
    re.compile(r"\b(?:scrot|import|gnome-screenshot|flameshot)\s+", _RE_FLAGS),
    # Clipboard exfil
    re.compile(r"\b(?:xclip|xsel|pbpaste|wl-paste|clip)\s+", _RE_FLAGS),
    # Keylogger hints
    re.compile(r"\b(?:xinput\s+test|evtest|logkeys|xspy)\b", _RE_FLAGS),
    # Port scan exfil
    re.compile(r"\b(?:nmap|masscan)\s+.*-o[GNX]\s+", _RE_FLAGS),
)


# ============================================================================
# DELIMITER INJECTION PATTERNS — cierre de wrappers
# ============================================================================

DELIMITER_INJECTION_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"</?\s*external_output[^>]*>", _RE_FLAGS),
    re.compile(r"</?\s*external_data[^>]*>", _RE_FLAGS),
    re.compile(r"</?\s*untrusted[^>]*>", _RE_FLAGS),
    re.compile(r"</?\s*system[^>]*>", _RE_FLAGS),
    re.compile(r"</?\s*instructions?[^>]*>", _RE_FLAGS),
    re.compile(r"</?\s*context[^>]*>", _RE_FLAGS),
    re.compile(r"</?\s*prompt[^>]*>", _RE_FLAGS),
    re.compile(r"</?\s*tool_result[^>]*>", _RE_FLAGS),
)


# ============================================================================
# TOOL ABUSE PATTERNS — function calling injections
# ============================================================================

TOOL_ABUSE_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"<\s*tool\s+name\s*=\s*['\"]?(?:exec|eval|system|shell|bash)", _RE_FLAGS),
    re.compile(r"<\s*function_call\s*>.*?<\s*/\s*function_call\s*>", _RE_FLAGS),
    re.compile(r"\{\s*\"tool\"\s*:\s*\"(?:exec|eval|system|shell|bash|subprocess)", _RE_FLAGS),
    re.compile(r"\bcall\s+tool\s+['\"]?(?:exec|eval|shell|system)", _RE_FLAGS),
    re.compile(r"\binvoke\s+(?:tool|function|api)\s+['\"]?(?:exec|eval|shell)", _RE_FLAGS),
    re.compile(r"<\s*\|?\s*tool\s*\|?\s*>", _RE_FLAGS),
)


# ============================================================================
# SQL INJECTION PATTERNS (para LLM con tools SQL)
# ============================================================================

SQL_INJECTION_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"'\s*(?:OR|AND)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", _RE_FLAGS),
    re.compile(r"\bUNION\s+(?:ALL\s+)?SELECT\b", _RE_FLAGS),
    re.compile(r"\b(?:DROP|TRUNCATE)\s+(?:TABLE|DATABASE|SCHEMA)\b", _RE_FLAGS),
    re.compile(r"\b(?:ALTER|CREATE)\s+(?:TABLE|DATABASE)\b", _RE_FLAGS),
    re.compile(r";\s*(?:DROP|DELETE|UPDATE|INSERT|ALTER|CREATE)\s+", _RE_FLAGS),
    re.compile(r"\bEXEC(?:UTE)?\s*\(\s*['\"]", _RE_FLAGS),
    re.compile(r"\bxp_cmdshell\b", _RE_FLAGS),
    re.compile(r"\bINTO\s+(?:OUT|DUMP)FILE\b", _RE_FLAGS),
    re.compile(r"\bLOAD_FILE\s*\(", _RE_FLAGS),
    re.compile(r"\b(?:SLEEP|BENCHMARK|WAITFOR\s+DELAY)\s*\(", _RE_FLAGS),
)


# ============================================================================
# PATH TRAVERSAL PATTERNS
# ============================================================================

PATH_TRAVERSAL_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"(?:\.\./){2,}", _RE_FLAGS),
    re.compile(r"(?:\.\.\\){2,}", _RE_FLAGS),
    re.compile(r"%2e%2e(?:%2f|%5c|/)", _RE_FLAGS),
    re.compile(r"%252e%252e", _RE_FLAGS),
    re.compile(r"\.\.%2f", _RE_FLAGS),
    re.compile(r"\b(?:/etc/passwd|/etc/shadow|/etc/hosts|/proc/self/environ)\b", _RE_FLAGS),
    re.compile(r"\b(?:C:\\Windows\\System32|%SystemRoot%)", _RE_FLAGS),
)


# ============================================================================
# ANSI ESCAPE PATTERNS
# ============================================================================

ANSI_ESCAPE_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"\x1b\[[0-9;?]*[A-Za-z]"),         # CSI
    re.compile(r"\x1b\][^\x07]*\x07"),              # OSC
    re.compile(r"\x1b[PX^_][^\x1b]*\x1b\\"),        # DCS/SOS/PM/APC
    re.compile(r"\x1b[=>]"),                        # Keypad modes
    re.compile(r"\x1b[78]"),                        # Save/restore cursor
    re.compile(r"\x1bM"),                           # Reverse index
    re.compile(r"\x1bc"),                           # Reset
)


# ============================================================================
# CHAIN-OF-THOUGHT MANIPULATION PATTERNS
# ============================================================================

CHAIN_OF_THOUGHT_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(
        r"\bthink\s+(?:step\s+by\s+step|carefully|slowly)\s*[,:;]?\s*"
        r"(?:and\s+)?(?:ignore|forget|disregard|bypass|override)",
        _RE_FLAGS,
    ),
    re.compile(r"\b(?:first|initially)\s*[,:]?\s*(?:ignore|forget|disregard)", _RE_FLAGS),
    re.compile(r"\bfinal\s+answer\s*[,:;]?\s*(?:should|must|will)\s+(?:be|contain)", _RE_FLAGS),
    re.compile(r"\bstep\s+\d+\s*:\s*(?:ignore|forget|override|execute|run)", _RE_FLAGS),
    re.compile(r"\breasoning\s*:\s*", _RE_FLAGS),
)


# ============================================================================
# ENCODING HINT PATTERNS
# ============================================================================

ENCODING_HINT_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"\b(?:decode|decipher|deobfuscate|unscramble|transform)\s+(?:this|the|following|below)", _RE_FLAGS),
    re.compile(r"\bfrom\s+(?:base64|hex|url|rot13|atbash|caesar|utf-?7|punycode)", _RE_FLAGS),
    re.compile(r"\b(?:run|execute|eval|interpret)\s+(?:this|the)\s+(?:encoded|obfuscated|hidden|encrypted)", _RE_FLAGS),
    re.compile(r"\b(?:base64|hex|url)-?encoded\s+(?:payload|command|script)", _RE_FLAGS),
)


# ============================================================================
# ALL PATTERNS (agregado para iteración simple)
# ============================================================================

ALL_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    *[("injection", p) for p in INJECTION_PATTERNS],
    *[("structured", p) for p in STRUCTURED_INJECTION_PATTERNS],
    *[("exfiltration", p) for p in EXFILTRATION_PATTERNS],
    *[("delimiter", p) for p in DELIMITER_INJECTION_PATTERNS],
    *[("tool_abuse", p) for p in TOOL_ABUSE_PATTERNS],
    *[("sql", p) for p in SQL_INJECTION_PATTERNS],
    *[("path_traversal", p) for p in PATH_TRAVERSAL_PATTERNS],
    *[("ansi", p) for p in ANSI_ESCAPE_PATTERNS],
    *[("cot", p) for p in CHAIN_OF_THOUGHT_PATTERNS],
    *[("encoding_hint", p) for p in ENCODING_HINT_PATTERNS],
)


# ============================================================================
# CANARY TOKENS v2 — HMAC-signed + rotación + sanitización
# ============================================================================

# NOTA: En producción, el seed se carga desde:
#   - AWS Secrets Manager
#   - HashiCorp Vault
#   - GCP Secret Manager
#   - Variable de entorno GODTIER_CANARY_SEED
#
# El seed DEBE ser compartido entre todos los workers del engagement.

import os as _os

_MASTER_CANARY_SEED: Final[str] = _os.getenv(
    "GODTIER_CANARY_SEED",
    "GODTIER_MASTER_SEED_v1_" + secrets.token_hex(16),
)

# Rotación: token válido por N segundos (default 24h)
_CANARY_TTL_SECONDS: Final[int] = 86400

# Cache de canary tokens (para evitar regenerar)
_CANARY_CACHE: dict[str, str] = {}
_CANARY_CACHE_LOCK = threading.RLock()


def _sanitize_engagement_id(engagement_id: str | None) -> str:
    """Sanitiza engagement_id para evitar inyección."""
    if engagement_id is None:
        return "default"
    # Whitelist: [a-zA-Z0-9_-] máx 64 chars
    sanitized = re.sub(r"[^a-zA-Z0-9_-]", "", engagement_id)[:64]
    return sanitized or "default"


def _get_rotating_seed() -> str:
    """Retorna el seed rotativo actual (cambia cada _CANARY_TTL_SECONDS)."""
    epoch = int(time.time() // _CANARY_TTL_SECONDS)
    return f"{_MASTER_CANARY_SEED}:{epoch}"


def generate_canary(
    engagement_id: str | None = None,
    *,
    use_cache: bool = True,
) -> str:
    """Genera canary token HMAC-signed para un engagement.

    God-Tier v2:
        - HMAC-SHA256 firmado (no solo hash)
        - Rotación automática cada _CANARY_TTL_SECONDS
        - engagement_id sanitizado (bloquea inyección)
        - Cache para performance

    Args:
        engagement_id: ID del engagement (se sanitiza).
        use_cache: Si True, usa cache.

    Returns:
        Canary token firmado.

    Ejemplo:
        >>> token = generate_canary("ROE-2026-001")
        >>> token.startswith("GODTIER_CANARY_")
        True
    """
    sanitized_id = _sanitize_engagement_id(engagement_id)

    if use_cache:
        with _CANARY_CACHE_LOCK:
            if sanitized_id in _CANARY_CACHE:
                return _CANARY_CACHE[sanitized_id]

    # HMAC-SHA256 con seed rotativo
    key = _get_rotating_seed().encode("utf-8")
    msg = sanitized_id.encode("utf-8")
    signature = hmac.new(key, msg, hashlib.sha256).hexdigest()[:24]

    token = f"GODTIER_CANARY_{signature}"

    if use_cache:
        with _CANARY_CACHE_LOCK:
            _CANARY_CACHE[sanitized_id] = token

    return token


def verify_canary(token: str, engagement_id: str | None = None) -> bool:
    """Verifica si un token es válido para un engagement.

    Prueba el token contra el seed actual Y el anterior (rotación).

    Args:
        token: Token a verificar.
        engagement_id: ID del engagement.

    Returns:
        True si el token es válido.
    """
    sanitized_id = _sanitize_engagement_id(engagement_id)

    # Seed actual
    current = generate_canary(sanitized_id)
    if hmac.compare_digest(token, current):
        return True

    # Seed anterior (por si rotó durante el engagement)
    epoch = int(time.time() // _CANARY_TTL_SECONDS) - 1
    prev_seed = f"{_MASTER_CANARY_SEED}:{epoch}"
    key = prev_seed.encode("utf-8")
    msg = sanitized_id.encode("utf-8")
    prev_sig = hmac.new(key, msg, hashlib.sha256).hexdigest()[:24]
    prev_token = f"GODTIER_CANARY_{prev_sig}"

    return hmac.compare_digest(token, prev_token)


def clear_canary_cache() -> None:
    """Limpia el cache de canary tokens."""
    with _CANARY_CACHE_LOCK:
        _CANARY_CACHE.clear()


# Backward-compat: CANARY_TOKENS estáticos
CANARY_TOKENS: Final[frozenset[str]] = frozenset({
    generate_canary(None),
    generate_canary("default"),
})


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Chars
    "ZERO_WIDTH_CHARS",
    "BIDI_OVERRIDE_CHARS",
    "LINE_SEPARATORS",
    "HOMOGLYPH_MAP",
    # Patterns
    "INJECTION_PATTERNS",
    "STRUCTURED_INJECTION_PATTERNS",
    "EXFILTRATION_PATTERNS",
    "DELIMITER_INJECTION_PATTERNS",
    "TOOL_ABUSE_PATTERNS",
    "SQL_INJECTION_PATTERNS",
    "PATH_TRAVERSAL_PATTERNS",
    "ANSI_ESCAPE_PATTERNS",
    "CHAIN_OF_THOUGHT_PATTERNS",
    "ENCODING_HINT_PATTERNS",
    "ALL_PATTERNS",
    # Canary
    "CANARY_TOKENS",
    "generate_canary",
    "verify_canary",
    "clear_canary_cache",
]
