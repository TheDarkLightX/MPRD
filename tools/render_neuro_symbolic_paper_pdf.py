#!/usr/bin/env python3
"""Render the neuro-symbolic disaster-loop preprint to a Zenodo-ready PDF.

This intentionally avoids Pandoc because the local environment may not have it.
The converter is scoped to docs/whitepapers/NEURO_SYMBOLIC_DISASTER_LOOP.md and
supports the Markdown constructs used by that paper.
"""

from __future__ import annotations

import argparse
import html
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MD = ROOT / "docs/whitepapers/NEURO_SYMBOLIC_DISASTER_LOOP.md"
DEFAULT_TEX = ROOT / "docs/whitepapers/NEURO_SYMBOLIC_DISASTER_LOOP.tex"
DEFAULT_PDF = ROOT / "docs/whitepapers/NEURO_SYMBOLIC_DISASTER_LOOP.pdf"


SPECIALS = {
    "\\": r"\textbackslash{}",
    "&": r"\&",
    "%": r"\%",
    "$": r"\$",
    "#": r"\#",
    "_": r"\_",
    "{": r"\{",
    "}": r"\}",
    "~": r"\textasciitilde{}",
    "^": r"\textasciicircum{}",
}


def tex_escape(text: str) -> str:
    return "".join(SPECIALS.get(ch, ch) for ch in text)


def convert_links(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        label = tex_escape(match.group(1))
        url = tex_escape(match.group(2))
        return rf"\href{{{url}}}{{{label}}}"

    return re.sub(r"\[([^\]]+)\]\(([^)]+)\)", repl, text)


def convert_inline(text: str) -> str:
    text = text.replace("“", '"').replace("”", '"').replace("’", "'")
    parts = re.split(r"(`[^`]+`|\$[^$\n]+\$)", text)
    out: list[str] = []
    for part in parts:
        if part.startswith("`") and part.endswith("`"):
            raw_code = part[1:-1]
            if "|" not in raw_code and (" " not in raw_code) and ("/" in raw_code or len(raw_code) > 28):
                out.append(r"\path|" + raw_code + "|")
            else:
                code = tex_escape(raw_code)
                out.append(rf"\texttt{{{code}}}")
        elif part.startswith("$") and part.endswith("$"):
            out.append(part)
        else:
            rendered = convert_links(tex_escape(part))
            rendered = re.sub(r"\*\*([^*]+)\*\*", r"\\textbf{\1}", rendered)
            out.append(rendered)
    return "".join(out)


def clean_heading(heading: str) -> str:
    """Drop source-authored section numbers; LaTeX supplies PDF numbering."""
    return re.sub(r"^\d+(?:\.\d+)*\.\s+", "", heading)


def table_alignment(separator: str, width: int) -> str:
    cells = [cell.strip() for cell in separator.strip().strip("|").split("|")]
    if len(cells) != width:
        return "|".join(["l"] * width)
    aligns = []
    for cell in cells:
        if cell.startswith(":") and cell.endswith(":"):
            aligns.append("c")
        elif cell.endswith(":"):
            aligns.append("r")
        else:
            aligns.append("l")
    return "|".join(aligns)


def render_table(rows: list[str]) -> list[str]:
    header = [cell.strip() for cell in rows[0].strip().strip("|").split("|")]
    aligns = table_alignment(rows[1], len(header)).split("|")
    body_rows = [
        [cell.strip() for cell in row.strip().strip("|").split("|")]
        for row in rows[2:]
    ]

    colspec = []
    for idx, _ in enumerate(header):
        if len(header) <= 2:
            colspec.append("p{0.58\\linewidth}" if idx == 0 else "p{0.28\\linewidth}")
        elif aligns[idx] == "r":
            colspec.append("r")
        else:
            colspec.append("p{0.23\\linewidth}")

    out = [
        r"\begin{center}",
        r"\small",
        r"\begin{tabular}{" + "".join(colspec) + r"}",
        r"\toprule",
        " & ".join(convert_inline(cell) for cell in header) + r" \\",
        r"\midrule",
    ]
    for row in body_rows:
        padded = row + [""] * (len(header) - len(row))
        out.append(" & ".join(convert_inline(cell) for cell in padded[: len(header)]) + r" \\")
    out.extend([r"\bottomrule", r"\end{tabular}", r"\end{center}"])
    return out


def render_front_matter(lines: list[str]) -> tuple[list[str], int]:
    title = lines[0].lstrip("#").strip()
    idx = 1
    while idx < len(lines) and not lines[idx].strip():
        idx += 1

    meta: list[str] = []
    while idx < len(lines):
        line = lines[idx].strip()
        if line.startswith("Primary implementation:") or line.startswith("Reference implementation:"):
            break
        if line.startswith("## Abstract"):
            break
        if line:
            meta.append(line.rstrip("  "))
        idx += 1

    primary: list[str] = []
    while idx < len(lines):
        line = lines[idx]
        if line.startswith("## Abstract"):
            break
        primary.append(line)
        idx += 1

    out = [
        r"\begin{titlepage}",
        r"\centering",
        r"\vspace*{0.7in}",
        r"{\LARGE\bfseries " + convert_inline(title) + r"\par}",
        r"\vspace{0.5in}",
    ]
    for line in meta:
        out.append(r"{\large " + convert_inline(line) + r"\par}")
    out.extend(
        [
            r"\vspace{0.35in}",
            r"\begin{minipage}{0.88\linewidth}",
        ]
    )
    para: list[str] = []
    for line in primary:
        stripped = line.strip()
        if not stripped:
            if para:
                out.append(" ".join(para))
                out.append("")
                para = []
            continue
        para.append(convert_inline(stripped))
    if para:
        out.append(" ".join(para))
    out.extend(
        [
            r"\end{minipage}",
            r"\vfill",
            r"\end{titlepage}",
            r"\pagenumbering{roman}",
            r"\tableofcontents",
            r"\newpage",
            r"\pagenumbering{arabic}",
        ]
    )
    return out, idx


def render_body(lines: list[str]) -> list[str]:
    out: list[str] = []
    paragraph: list[str] = []
    itemize = False
    enumerate_ = False
    quote = False
    code = False
    math = False
    in_abstract = False
    table: list[str] = []

    def flush_paragraph() -> None:
        nonlocal paragraph
        if paragraph:
            out.append(" ".join(paragraph))
            out.append("")
            paragraph = []

    def close_lists() -> None:
        nonlocal itemize, enumerate_
        if itemize:
            out.append(r"\end{itemize}")
            itemize = False
        if enumerate_:
            out.append(r"\end{enumerate}")
            enumerate_ = False

    def close_quote() -> None:
        nonlocal quote
        if quote:
            out.append(r"\end{quote}")
            quote = False

    def flush_table() -> None:
        nonlocal table
        if table:
            out.extend(render_table(table))
            out.append("")
            table = []

    for raw in lines:
        line = raw.rstrip("\n")
        stripped = line.strip()

        if code:
            if stripped.startswith("```"):
                out.append(r"\end{verbatim}")
                code = False
            else:
                out.append(line)
            continue

        if math:
            if stripped in {"$$", r"\]"}:
                out.append(r"\]")
                math = False
            else:
                out.append(line)
            continue

        if stripped.startswith("```"):
            flush_paragraph()
            flush_table()
            close_lists()
            close_quote()
            out.append(r"\begin{verbatim}")
            code = True
            continue

        if stripped in {"$$", r"\["}:
            flush_paragraph()
            flush_table()
            close_lists()
            close_quote()
            out.append(r"\[")
            math = True
            continue

        if stripped.startswith("|") and stripped.endswith("|"):
            flush_paragraph()
            close_lists()
            close_quote()
            table.append(stripped)
            continue
        else:
            flush_table()

        if not stripped:
            flush_paragraph()
            close_lists()
            close_quote()
            continue

        if stripped.startswith("### "):
            flush_paragraph()
            close_lists()
            close_quote()
            out.append(r"\subsection{" + convert_inline(clean_heading(stripped[4:])) + "}")
            continue
        if stripped.startswith("## "):
            flush_paragraph()
            close_lists()
            close_quote()
            heading = clean_heading(stripped[3:])
            if heading == "Abstract":
                out.append(r"\begin{abstract}")
                in_abstract = True
            else:
                if in_abstract:
                    out.append(r"\end{abstract}")
                    in_abstract = False
                out.append(r"\section{" + convert_inline(heading) + "}")
            continue

        if stripped.startswith(">"):
            flush_paragraph()
            close_lists()
            if not quote:
                out.append(r"\begin{quote}")
                quote = True
            out.append(convert_inline(stripped.lstrip("> ").strip()))
            continue

        if stripped.startswith("- "):
            flush_paragraph()
            close_quote()
            if enumerate_:
                out.append(r"\end{enumerate}")
                enumerate_ = False
            if not itemize:
                out.append(r"\begin{itemize}")
                itemize = True
            out.append(r"\item " + convert_inline(stripped[2:]))
            continue

        number_match = re.match(r"^\d+\.\s+(.*)", stripped)
        if number_match:
            flush_paragraph()
            close_quote()
            if itemize:
                out.append(r"\end{itemize}")
                itemize = False
            if not enumerate_:
                out.append(r"\begin{enumerate}")
                enumerate_ = True
            out.append(r"\item " + convert_inline(number_match.group(1)))
            continue

        if itemize or enumerate_:
            out.append(convert_inline(stripped))
        else:
            paragraph.append(convert_inline(stripped))

    flush_table()
    flush_paragraph()
    close_lists()
    close_quote()
    if code:
        out.append(r"\end{verbatim}")
    if in_abstract:
        out.append(r"\end{abstract}")
    return out


def render_tex(markdown: str) -> str:
    lines = markdown.splitlines()
    front, start = render_front_matter(lines)
    body = render_body(lines[start:])
    return "\n".join(
        [
            r"\documentclass[11pt]{article}",
            r"\usepackage[letterpaper,margin=1in]{geometry}",
            r"\usepackage[T1]{fontenc}",
            r"\usepackage[utf8]{inputenc}",
            r"\usepackage{lmodern}",
            r"\usepackage{microtype}",
            r"\usepackage{amsmath}",
            r"\usepackage{amssymb}",
            r"\usepackage{hyperref}",
            r"\usepackage{xcolor}",
            r"\usepackage{booktabs}",
            r"\usepackage{array}",
            r"\usepackage{enumitem}",
            (
                r"\hypersetup{colorlinks=true,linkcolor=blue,urlcolor=blue,citecolor=blue,"
                r"pdftitle={What-If Witness Spaces: A Neuro-Symbolic Disaster Loop for Fail-Closed Software Hardening},"
                r"pdfauthor={Dana Edwards},"
                r"pdfsubject={Neuro-symbolic software assurance},"
                r"pdfkeywords={software assurance, formal methods, neuro-symbolic systems, witness spaces, fail-closed verification}}"
            ),
            r"\setlist{itemsep=0.25em,topsep=0.3em}",
            r"\setlength{\parskip}{0.6em}",
            r"\setlength{\parindent}{0pt}",
            r"\sloppy",
            r"\begin{document}",
            r"\pagenumbering{gobble}",
            *front,
            *body,
            r"\end{document}",
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--markdown", type=Path, default=DEFAULT_MD)
    parser.add_argument("--tex", type=Path, default=DEFAULT_TEX)
    parser.add_argument("--pdf", type=Path, default=DEFAULT_PDF)
    args = parser.parse_args()

    markdown = args.markdown.read_text(encoding="utf-8")
    tex = render_tex(markdown)
    args.tex.write_text(tex, encoding="utf-8")

    subprocess.run(
        ["pdflatex", "-interaction=nonstopmode", "-halt-on-error", args.tex.name],
        cwd=args.tex.parent,
        check=True,
    )
    subprocess.run(
        ["pdflatex", "-interaction=nonstopmode", "-halt-on-error", args.tex.name],
        cwd=args.tex.parent,
        check=True,
    )

    produced_pdf = args.tex.with_suffix(".pdf")
    if produced_pdf != args.pdf:
        args.pdf.write_bytes(produced_pdf.read_bytes())
    print(args.pdf)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
