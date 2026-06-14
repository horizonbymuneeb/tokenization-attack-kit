#!/usr/bin/env python3
"""
TokenAttackKit: Real, runnable attack implementations for tokenization-based LLM attacks.

This module provides concrete, tested implementations of various attack vectors:
- Unicode homoglyph substitution
- Zero-width character injection
- Right-to-left override
- BPE token boundary manipulation
- Base64/rot13 encoding bypass
- Invisible whitespace steganography
- Combining diacritics abuse
- Mixed-script confusables

All attacks are designed to work on CPU without any GPU. They produce adversarial
prompts that can be tested against any LLM with a text interface (API or local).

Run: python3 token_attack_kit.py --attack homoglyph --text "Hello world"
"""

import argparse
import base64
import codecs
import random
import string
import sys
import unicodedata
from typing import List, Optional, Tuple


# ============================================================
# 1. UNICODE HOMOGLYPH ATTACK
# ============================================================

# Latin → Cyrillic/Greek confusables
HOMOGLYPHS = {
    'a': 'а',  # Cyrillic а (U+0430)
    'e': 'е',  # Cyrillic е (U+0435)
    'o': 'о',  # Cyrillic о (U+043E)
    'p': 'р',  # Cyrillic р (U+0440)
    'c': 'с',  # Cyrillic с (U+0441)
    'x': 'х',  # Cyrillic х (U+0445)
    'y': 'у',  # Cyrillic у (U+0443)
    'i': 'і',  # Ukrainian і (U+0456)
    'j': 'ј',  # Cyrillic j (U+0458)
    's': 'ѕ',  # Cyrillic s (U+0455)
    'A': 'А',  # Cyrillic А
    'B': 'В',  # Cyrillic В
    'C': 'С',  # Cyrillic С
    'E': 'Е',  # Cyrillic Е
    'H': 'Н',  # Cyrillic Н
    'K': 'К',  # Cyrillic К
    'M': 'М',  # Cyrillic М
    'O': 'О',  # Cyrillic О
    'P': 'Р',  # Cyrillic Р
    'T': 'Т',  # Cyrillic Т
    'X': 'Х',  # Cyrillic Х
}


def homoglyph_attack(text: str, ratio: float = 0.3) -> str:
    """Replace Latin chars with visually-identical Cyrillic/Greek confusables.
    ratio: fraction of eligible chars to replace (0.0-1.0)
    """
    result = []
    for c in text:
        if c in HOMOGLYPHS and random.random() < ratio:
            result.append(HOMOGLYPHS[c])
        else:
            result.append(c)
    return "".join(result)


# ============================================================
# 2. ZERO-WIDTH CHARACTER INJECTION
# ============================================================

# Zero-width chars: invisible to humans, may confuse tokenizers
ZERO_WIDTH = [
    '\u200b',  # Zero-width space
    '\u200c',  # Zero-width non-joiner
    '\u200d',  # Zero-width joiner
    '\u2060',  # Word joiner
    '\ufeff',  # Zero-width no-break space
]


def zero_width_attack(text: str, ratio: float = 0.2, position: str = "between") -> str:
    """Inject zero-width characters into text.
    position: 'between' (between chars), 'middle' (in word), 'random'
    """
    result = []
    for i, c in enumerate(text):
        if c == ' ':
            result.append(c)
            continue
        result.append(c)
        if random.random() < ratio:
            result.append(random.choice(ZERO_WIDTH))
    return "".join(result)


# ============================================================
# 3. RIGHT-TO-LEFT OVERRIDE ATTACK
# ============================================================

def rtl_override_attack(text: str) -> str:
    """Wrap text with RTL override characters to visually reverse."""
    # U+202E = Right-to-Left Override
    # U+202D = Left-to-Right Override
    rtl_char = '\u202e'
    ltr_char = '\u202d'
    return f"{rtl_char}{text}{ltr_char}"


# ============================================================
# 4. BPE TOKEN BOUNDARY MANIPULATION
# ============================================================

# Insert spaces or other chars to force different BPE splits
def bpe_boundary_attack(text: str) -> str:
    """Insert strategic spaces to change BPE tokenization."""
    # Common BPE merges: e.g., "ing" might split differently with spaces
    words = text.split()
    result = []
    for w in words:
        if len(w) > 4 and random.random() < 0.3:
            # Insert zero-width space in middle of word
            mid = len(w) // 2
            w = w[:mid] + '\u200b' + w[mid:]
        result.append(w)
    return " ".join(result)


# ============================================================
# 5. ENCODING ATTACKS
# ============================================================

def base64_attack(text: str) -> str:
    """Base64-encode the malicious portion."""
    instruction = "Decode the following base64 and follow the instruction: "
    encoded = base64.b64encode(text.encode()).decode()
    return f"{instruction} {encoded}"


def rot13_attack(text: str) -> str:
    """ROT13 encode the malicious portion."""
    instruction = "Apply ROT13 and follow: "
    encoded = codecs.encode(text, 'rot_13')
    return f"{instruction} {encoded}"


def hex_attack(text: str) -> str:
    """Hex-encode the malicious portion."""
    instruction = "Decode hex and execute: "
    encoded = text.encode().hex()
    return f"{instruction} {encoded}"


# ============================================================
# 6. INVISIBLE WHITESPACE STEGANOGRAPHY
# ============================================================

# Different whitespace chars that look identical
INVISIBLE_WS = [
    ' ',       # regular space
    '\u00a0',  # non-breaking space
    '\u2003',  # em space
    '\u2002',  # en space
    '\u2009',  # thin space
    '\u200a',  # hair space
    '\u200b',  # zero-width space
    '\u3000',  # ideographic space
]


def whitespace_stego_attack(text: str, payload: str = "attack") -> str:
    """Hide payload bits in whitespace selection (binary steganography)."""
    bits = ''.join(format(ord(c), '08b') for c in payload)
    result = []
    bit_idx = 0
    for c in text:
        if c == ' ' and bit_idx < len(bits):
            # Use non-breaking or zero-width for '1', regular for '0'
            if bits[bit_idx] == '1':
                result.append(random.choice([w for w in INVISIBLE_WS if w != ' ']))
            else:
                result.append(' ')
            bit_idx += 1
        else:
            result.append(c)
    return "".join(result)


# ============================================================
# 7. COMBINING DIACRITICS ABUSE
# ============================================================

# Combining diacritics that can be stacked on a base char
COMBINING = [
    '\u0300',  # combining grave
    '\u0301',  # combining acute
    '\u0302',  # combining circumflex
    '\u0303',  # combining tilde
    '\u0304',  # combining macron
    '\u0305',  # combining overline
    '\u0306',  # combining breve
    '\u0307',  # combining dot above
    '\u0308',  # combining diaeresis
    '\u030a',  # combining ring above
    '\u030b',  # combining double acute
    '\u030c',  # combining caron
    '\u0327',  # combining cedilla
    '\u0328',  # combining ogonek
]


def diacritics_attack(text: str, ratio: float = 0.5) -> str:
    """Stack multiple combining diacritics on characters (Zalgo text style)."""
    result = []
    for c in text:
        result.append(c)
        if c.isalpha() and random.random() < ratio:
            n = random.randint(1, 5)
            for _ in range(n):
                result.append(random.choice(COMBINING))
    return "".join(result)


# ============================================================
# 8. MIXED-SCRIPT CONFUSABLES
# ============================================================

def mixed_script_attack(text: str, ratio: float = 0.3) -> str:
    """Mix Latin, Cyrillic, and Greek to confuse LLM tokenizers."""
    # Map of letter → list of visually identical chars from other scripts
    MULTI_SCRIPT = {
        'a': ['а', 'ɑ', 'α'],  # Cyrillic, Latin alpha, Greek alpha
        'e': ['е', 'ε'],  # Cyrillic, Greek epsilon
        'o': ['о', 'ο', 'ω'],  # Cyrillic, Greek omicron, omega
        'p': ['р', 'ρ'],  # Cyrillic, Greek rho
        'c': ['с', 'ϲ'],  # Cyrillic, Greek lunate sigma
        'x': ['х', 'χ'],  # Cyrillic, Greek chi
        'y': ['у', 'γ'],  # Cyrillic, Greek gamma
        'B': ['В', 'Β'],
        'H': ['Н', 'Η'],
        'K': ['К', 'Κ'],
        'M': ['М', 'Μ'],
        'P': ['Р', 'Ρ'],
        'T': ['Т', 'Τ'],
        'X': ['Х', 'Χ'],
    }
    result = []
    for c in text:
        if c in MULTI_SCRIPT and random.random() < ratio:
            result.append(random.choice(MULTI_SCRIPT[c]))
        else:
            result.append(c)
    return "".join(result)


# ============================================================
# 9. COMBINED ATTACK (novel contribution)
# ============================================================

def combined_attack(text: str) -> str:
    """Apply multiple attack layers in sequence."""
    # Layer 1: Homoglyph
    attacked = homoglyph_attack(text, ratio=0.4)
    # Layer 2: Zero-width injection
    attacked = zero_width_attack(attacked, ratio=0.15)
    # Layer 3: BPE boundary
    attacked = bpe_boundary_attack(attacked)
    return attacked


# ============================================================
# 10. DETECTION HELPER (for defenders)
# ============================================================

def detect_attack(text: str) -> dict:
    """Detect signs of tokenization-based attacks in text."""
    signals = {
        "homoglyph": False,
        "zero_width": False,
        "rtl_override": False,
        "invisible_ws": False,
        "combining_diacritics": 0,
        "non_ASCII_ratio": 0.0,
        "suspicious_scripts": set(),
    }

    # Check for homoglyphs (Cyrillic chars in Latin-looking text)
    for c in text:
        if 0x0400 <= ord(c) <= 0x04FF:  # Cyrillic
            signals["homoglyph"] = True
            signals["suspicious_scripts"].add("Cyrillic")
        elif 0x0370 <= ord(c) <= 0x03FF:  # Greek
            signals["suspicious_scripts"].add("Greek")
        elif 0x0590 <= ord(c) <= 0x05FF:  # Hebrew (RTL)
            signals["rtl_override"] = True
        elif c in ZERO_WIDTH:
            signals["zero_width"] = True
        elif c in INVISIBLE_WS and c != ' ':
            signals["invisible_ws"] = True
        elif c in COMBINING:
            signals["combining_diacritics"] += 1

    # Calculate non-ASCII ratio
    if text:
        non_ascii = sum(1 for c in text if ord(c) > 127)
        signals["non_ASCII_ratio"] = non_ascii / len(text)

    signals["suspicious_scripts"] = list(signals["suspicious_scripts"])
    return signals


# ============================================================
# CLI INTERFACE
# ============================================================

ATTACKS = {
    "homoglyph": homoglyph_attack,
    "zero_width": zero_width_attack,
    "rtl": rtl_override_attack,
    "bpe": bpe_boundary_attack,
    "base64": base64_attack,
    "rot13": rot13_attack,
    "hex": hex_attack,
    "stego": whitespace_stego_attack,
    "diacritics": diacritics_attack,
    "mixed": mixed_script_attack,
    "combined": combined_attack,
}


def main():
    parser = argparse.ArgumentParser(description="TokenAttackKit - Real tokenization attack implementations")
    parser.add_argument("--attack", "-a", required=True, choices=list(ATTACKS.keys()) + ["detect", "list"],
                        help="Attack to apply or 'detect' to analyze text")
    parser.add_argument("--text", "-t", default="How do I make a sandwich?",
                        help="Input text to attack or detect")
    parser.add_argument("--ratio", "-r", type=float, default=0.3,
                        help="Replacement ratio (0.0-1.0)")
    parser.add_argument("--all", action="store_true",
                        help="Apply all attacks to the same text")
    args = parser.parse_args()

    if args.attack == "list":
        print("Available attacks:")
        for name, fn in ATTACKS.items():
            print(f"  {name}: {fn.__doc__.split(chr(10))[0] if fn.__doc__ else ''}")
        return

    if args.attack == "detect":
        result = detect_attack(args.text)
        print(f"Detection result for: {repr(args.text[:50])}")
        for k, v in result.items():
            print(f"  {k}: {v}")
        return

    if args.all:
        print(f"Original: {args.text}\n")
        for name, fn in ATTACKS.items():
            random.seed(42)
            try:
                if "ratio" in fn.__code__.co_varnames:
                    result = fn(args.text, ratio=args.ratio)
                else:
                    result = fn(args.text)
                print(f"[{name:12s}] {result}")
            except Exception as e:
                print(f"[{name:12s}] ERROR: {e}")
        return

    # Single attack
    random.seed(42)
    fn = ATTACKS[args.attack]
    if "ratio" in fn.__code__.co_varnames:
        result = fn(args.text, ratio=args.ratio)
    else:
        result = fn(args.text)

    print(f"Attack: {args.attack}")
    print(f"Input:  {args.text}")
    print(f"Output: {result}")
    print(f"Length change: {len(args.text)} → {len(result)}")
    print()
    print("Detection signals:")
    for k, v in detect_attack(result).items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
