# Cleans text before checking it: Unicode NFKC, and invisible or
# direction-changing characters removed, so they can't be used to hide a
# secret. These characters have no meaning in chat text, so removing them
# never damages real content.
import unicodedata

# Zero-width characters and the characters that change text direction
# ("Trojan Source", CVE-2021-42574). Both can split or disguise a secret.
INVISIBLE_CHARS = (
    '​‌‍﻿'  # zero-width space/non-joiner/joiner/no-break-space
    '‪‫‬‭‮'  # LRE, RLE, PDF, LRO, RLO
    '⁦⁧⁨⁩'  # LRI, RLI, FSI, PDI
    '⁠᠎­'  # word joiner, Mongolian vowel separator, soft hyphen
    '︀︁︂︃︄︅︆︇'  # variation selectors 1-8
    '︈︉︊︋︌︍︎️'  # variation selectors 9-16
    '͏'  # combining grapheme joiner
    # All of these are invisible; left in, one could be put inside a key to hide it.
)


def normalize(text: str) -> str:
    text = unicodedata.normalize('NFKC', text)
    for ch in INVISIBLE_CHARS:
        text = text.replace(ch, '')
    return text


# Cyrillic and Greek letters that look like Latin ones, the common set used to
# disguise text (not the full Unicode list).
_CONFUSABLES = {
    # Cyrillic uppercase -> Latin
    'А': 'A', 'В': 'B', 'Е': 'E', 'Ѕ': 'S', 'Ј': 'J',
    'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P',
    'С': 'C', 'Т': 'T', 'У': 'Y', 'Х': 'X',
    # Cyrillic lowercase -> Latin
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
    'у': 'y', 'х': 'x', 'ѕ': 's', 'і': 'i', 'ј': 'j',
    # Greek uppercase -> Latin
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H',
    'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O',
    'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
    # Greek lowercase -> Latin
    'ο': 'o', 'ν': 'v', 'ι': 'i', 'ρ': 'p', 'υ': 'u',
    'χ': 'x',
}

# Accented Latin letters (U+00C0-00FF, Western European) mapped to the plain
# letter, so "ÀKIA..." still matches. Built with unicodedata instead of typed
# by hand, to avoid typos.
_ACCENTED_LATIN = {
    chr(_cp): unicodedata.normalize('NFKD', chr(_cp))[0]
    for _cp in range(0x00C0, 0x0100)
    if unicodedata.normalize('NFKD', chr(_cp))[:1].isascii()
    and unicodedata.normalize('NFKD', chr(_cp))[:1].isalpha()
}

# Dash look-alikes mapped to a normal "-", since many key prefixes contain a
# dash (xoxb-, sk-). Ordinary dashes in sentences never form a key shape.
_DASH_LOOKALIKES = {
    '‐': '-',  # HYPHEN
    '‑': '-',  # NON-BREAKING HYPHEN
    '‒': '-',  # FIGURE DASH
    '–': '-',  # EN DASH
    '—': '-',  # EM DASH
    '−': '-',  # MINUS SIGN
}
_CONFUSABLES_TABLE = str.maketrans({**_CONFUSABLES, **_ACCENTED_LATIN, **_DASH_LOOKALIKES})


def fold_confusables(text: str) -> str:
    """Maps look-alike Cyrillic/Greek letters and accented letters to plain
    ASCII, ONLY for checking, never for the text that is sent.

    Kept out of normalize() on purpose: the addon edits normalize()'s output
    when it masks something, and folding there would change every Cyrillic
    or Greek letter in the message, not just the masked part. Each letter
    maps to exactly one letter, so positions stay the same.
    """
    return text.translate(_CONFUSABLES_TABLE)


def _strip_chars_for_detection(text: str, chars: str) -> tuple[str, list[int]]:
    """Removes every character in `chars` and returns (text, index_map),
    where index_map[i] is where text[i] was in the original. Map a found
    span back with (index_map[start], index_map[end - 1] + 1). Changes
    lengths, so for checking only."""
    stripped_chars = []
    index_map = []
    for i, ch in enumerate(text):
        if ch in chars:
            continue
        stripped_chars.append(ch)
        index_map.append(i)
    return ''.join(stripped_chars), index_map


def strip_line_breaks_for_detection(text: str) -> tuple[str, list[int]]:
    """Removes line breaks so a key wrapped onto two lines still matches.
    For checking only (see _strip_chars_for_detection). Only line breaks,
    not spaces: removing spaces would glue ordinary words into false matches.
    """
    return _strip_chars_for_detection(text, '\r\n')


def strip_spaces_for_detection(text: str) -> tuple[str, list[int]]:
    """Removes spaces and tabs. Only use on a short stretch after a
    distinctive prefix (see regex_rules.py), never on a whole message."""
    return _strip_chars_for_detection(text, ' \t')
