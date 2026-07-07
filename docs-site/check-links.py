#!/usr/bin/env python3
"""Validate intra-site Markdown links and heading anchors for the mdBook docs.

For each locale book under ``docs-site/<loc>/{src,book}`` every relative
Markdown link (and same-page ``#anchor``) found in the source is resolved
against the *built* HTML, so a renamed heading or a cross-language anchor
mismatch fails CI instead of shipping a dead link. mdBook's own generated
heading ids are used as ground truth (no slug algorithm is re-implemented).

External (http/https/mailto) and site-absolute links are skipped. Run after
``mdbook build`` so the ``book/`` directories exist.
"""
import re
import sys
import pathlib

LOCALES = ["en"]

# Markdown inline links, excluding images (![]()), allowing an optional title.
LINK_RE = re.compile(r'(?<!\!)\[[^\]]*\]\(\s*([^)\s]+?)(?:\s+"[^"]*")?\s*\)')
# Heading anchors as emitted by mdBook: <h1..6 ... id="...">
HEADING_ID_RE = re.compile(r'<h[1-6][^>]*\bid="([^"]+)"')
# Strip fenced and inline code so example link syntax is not treated as a link.
FENCE_RE = re.compile(r'```.*?```', re.DOTALL)
INLINE_CODE_RE = re.compile(r'`[^`]*`')


def strip_code(text):
    return INLINE_CODE_RE.sub('', FENCE_RE.sub('', text))


def heading_ids(html_path, cache):
    if html_path not in cache:
        try:
            cache[html_path] = set(HEADING_ID_RE.findall(
                html_path.read_text(encoding='utf-8')))
        except FileNotFoundError:
            cache[html_path] = None
    return cache[html_path]


def src_to_html(src_md, loc_root):
    rel = src_md.relative_to(loc_root / 'src')
    return loc_root / 'book' / rel.with_suffix('.html')


def check_locale(loc_root, loc, errors):
    loc_root = loc_root.resolve()
    src_root = loc_root / 'src'
    if not (loc_root / 'book').exists():
        errors.append(f"[{loc}] built book/ not found — run `mdbook build {loc_root}` first")
        return
    cache = {}
    for md in sorted(src_root.rglob('*.md')):
        if md.name == 'SUMMARY.md':
            continue
        rel_name = md.relative_to(src_root)
        for m in LINK_RE.finditer(strip_code(md.read_text(encoding='utf-8'))):
            target = m.group(1).strip()
            if target.startswith(('http://', 'https://', 'mailto:', '//', '/')):
                continue
            path_part, _, anchor = target.partition('#')
            if path_part and not path_part.endswith('.md'):
                continue  # relative non-md (images etc.) — out of scope
            if path_part == '':
                html = src_to_html(md, loc_root)  # same-page anchor
            else:
                tgt_md = (md.parent / path_part).resolve()
                try:
                    tgt_md.relative_to(src_root)
                except ValueError:
                    errors.append(f"[{loc}] {rel_name} -> {target}: target escapes src/")
                    continue
                if not tgt_md.exists():
                    errors.append(f"[{loc}] {rel_name} -> {target}: target file does not exist")
                    continue
                html = src_to_html(tgt_md, loc_root)
            if not anchor:
                continue
            ids = heading_ids(html, cache)
            if ids is None:
                errors.append(f"[{loc}] {rel_name} -> {target}: built page {html.name} missing")
            elif anchor not in ids:
                errors.append(f"[{loc}] {rel_name} -> {target}: no heading anchor #{anchor} in {html.name}")


def main():
    base = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 \
        else pathlib.Path(__file__).resolve().parent
    errors = []
    for loc in LOCALES:
        check_locale(base / loc, loc, errors)
    if errors:
        print(f"Doc link check FAILED ({len(errors)} issue(s)):")
        for e in errors:
            print('  - ' + e)
        return 1
    print("Doc link check passed: all intra-site links and heading anchors resolve.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
