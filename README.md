# Old Bugs, New Protocol

Research article: *A Root-Cause Analysis of Security Failures in the Model Context Protocol Ecosystem Under Rapid Adoption*.

Author: Negai Marin, IS-261M, Technical University of Moldova.

## Structure

| Path | Content |
|---|---|
| `main.tex` | Entry point (UTM report template) |
| `additional/`, `chapters/` | Article text |
| `bibliography/references.bib` | Sources (biblatex + biber) |
| `data/mcp_security_records.csv` | Coded dataset of 54 records |
| `analysis/analyze.py` | Generates every number, table and chart in Chapter 3 |
| `generated/` | Output of the analysis script, included by LaTeX |

## Build

```sh
python3 analysis/analyze.py
pdflatex main.tex
biber main
pdflatex main.tex
pdflatex main.tex
```

The template class needs the `glossaries` package, which depends on `tracklang`. On Arch Linux install it with `sudo pacman -S texlive-plaingeneric`. Overleaf works out of the box (set the compiler to pdfLaTeX).
