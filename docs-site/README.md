# Subnetra documentation site

A comprehensive documentation site for Subnetra, built with
[mdBook](https://github.com/rust-lang/mdBook) and deployed to GitHub Pages at
<https://jamiesun.github.io/subnetra/>.

This directory is self-contained; it does not replace the design docs under
[`../docs/`](../docs) (which the README files link to directly).

## Layout

```
docs-site/
  index.html            root redirect → en/
  en/                   the book
    book.toml
    src/                Markdown chapters (SUMMARY.md + content)
    theme/              custom.css
```

## Prerequisites

[mdBook](https://rust-lang.github.io/mdBook/guide/installation.html) **0.5.3+**
and the [mdbook-mermaid](https://github.com/badboy/mdbook-mermaid) preprocessor
**0.17.0+** (the architecture diagrams are mermaid flowcharts):

```bash
# macOS
brew install mdbook
# or, any platform with Rust
cargo install mdbook --version 0.5.3

# mermaid preprocessor (not in brew — install via cargo or a release binary)
cargo install mdbook-mermaid --version 0.17.0
```

`mdbook-mermaid` must be on your `PATH`; `book.toml` references it as
`command = "mdbook-mermaid"`. The `mermaid.min.js` / `mermaid-init.js` assets are
already committed next to `book.toml`, so you only need the binary to build.

## Preview locally

The hero image is tracked once at the repo root and copied into the book at
build time, so copy it first:

```bash
mkdir -p docs-site/en/src/images
cp subnetra.png docs-site/en/src/images/subnetra.png
mdbook serve docs-site/en -p 3000 --open      # http://localhost:3000
```

## Build

```bash
mkdir -p docs-site/en/src/images
cp subnetra.png docs-site/en/src/images/subnetra.png
mdbook build docs-site/en      # → docs-site/en/book/
```

The `book/` output directory and the copied image are git-ignored (see
[`.gitignore`](.gitignore)).

## Authoring notes

- **Add a page:** create the file in `en/src/`, then add a matching
  `- [Title](path.md)` line to `SUMMARY.md`.
- **Internal links:** use relative `.md` links (e.g. `../concepts/architecture.md`);
  mdBook rewrites them to `.html`. Cross-page `#anchor` fragments use the slug
  mdBook derives from the heading text.
- **External links** in `SUMMARY.md` list items break the build ("Unable to create
  missing chapters") — keep them in page bodies, not the table of contents.
- Don't hand-edit anything under `book/` — it is generated.

## Deployment

[`.github/workflows/docs.yml`](../.github/workflows/docs.yml) builds the book on
every push to `main` that touches `docs-site/`, assembles it into a `site/` tree
(`site/index.html`, `site/en/`), and deploys to GitHub Pages. Pull requests build
the site (as a check) but do not deploy.

The `site-url` in `book.toml` is set to the project-pages base (`/subnetra/en/`);
navigation is relative, so the book also works when previewed under any other
base path.
