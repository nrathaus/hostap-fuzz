#!/usr/bin/env python3
"""Just enough C structure to answer two questions mechanically.

  split_functions(src) -> [(name, body)]   which function is a line inside
  calls_in(body)       -> {name, ...}      what does it call

hostap is written in a consistent style: a function's return type and name begin
at column 0 and its closing brace is a lone '}' at column 0. That is the whole
basis for the split below. It is a convention, not a guarantee, so a file that
breaks it yields fewer functions rather than wrong ones -- the split only ever
merges neighbours, and a merged pair is still a region of real code whose calls
and markers are real. Nothing downstream assumes the regions are minimal.
"""

import re

FUNC_SIG = re.compile(
    r"^(?P<decl>[A-Za-z_][\w \t*]*?)(?P<name>[A-Za-z_]\w*)[ \t]*\((?P<args>[^;]*?)\)"
    r"[ \t\n]*\{",
    re.M | re.S)


def strip_comments(src):
    """Replace comments and string bodies with same-length blanks.

    Same length so every offset computed on the result indexes the original.
    """
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
            continue
        if c in "\"'":
            q, j = c, i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == q:
                    break
                j += 1
            i = min(j + 1, n)
            continue
        i += 1
    return "".join(out)


def split_functions(src):
    """[(name, body)] for every definition whose brace sits at column 0."""
    blank = strip_comments(src)
    out = []
    for m in FUNC_SIG.finditer(blank):
        if m.group("decl").strip().endswith("="):
            continue
        if re.search(r"\b(if|for|while|switch|return|sizeof)\s*$",
                     m.group("decl")):
            continue
        start = m.end() - 1               # the '{'
        end = blank.find("\n}", start)
        end = len(src) if end < 0 else end + 2
        out.append((m.group("name"), src[start:end]))
    return out


CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
NOT_CALLS = {
    "if", "for", "while", "switch", "return", "sizeof", "defined",
}


def calls_in(body):
    return {m.group(1) for m in CALL.finditer(strip_comments(body))
            if m.group(1) not in NOT_CALLS}


def function_body(src, name):
    for fname, body in split_functions(src):
        if fname == name:
            return body
    return None
