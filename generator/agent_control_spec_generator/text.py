# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Render untrusted text without terminal controls or Markdown structure."""

import json
import re
import unicodedata


def is_control(char: str) -> bool:
    return unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"}


def terminal_text(text: str, *, multiline: bool = False) -> str:
    return "".join(
        json.dumps(char, ensure_ascii=True)[1:-1]
        if is_control(char) and not (multiline and char == "\n")
        else char
        for char in text
    )


def inline_code(text: str) -> str:
    text = terminal_text(text)
    fence = "`" * (max((len(m[0]) for m in re.finditer(r"`+", text)), default=0) + 1)
    return f"{fence} {text} {fence}"


def code_block(text: str) -> str:
    fence = "`" * max(
        3, max((len(m[0]) for m in re.finditer(r"`+", text)), default=0) + 1
    )
    return f"{fence}rego\n{text}\n{fence}"
