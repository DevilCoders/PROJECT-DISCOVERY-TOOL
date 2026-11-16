# Documentation Format Coverage

Built-in structural extraction:
- Markdown: headings, links and word count.
- HTML: title, headings, links and visible-text word count. Script, style and noscript text is excluded.
- reStructuredText: heading outline and word count.
- TXT, AsciiDoc and LaTeX: line and word metrics.
- PDF: optional `pypdf` extraction of page text and metadata.
- DOCX: optional `python-docx` extraction of paragraphs and tables.

Install optional document parsers with:

```bash
python -m pip install -e ".[documents]"
```

Document parsers run locally. No document content is sent to external services. Missing optional dependencies produce UNKNOWN capability findings. Parse success only confirms that text/structure was extracted; documentation claims are never treated as proof that described software features are implemented.
