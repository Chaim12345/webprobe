# UML diagrams

Mermaid diagrams; GitHub renders them in place.

| Diagram | Shows | Source |
|---|---|---|
| [crates.md](crates.md) | The four workspace crates and their dependencies | generated from `cargo metadata` |
| [flows.md](flows.md) | A proxied request, the states of a held intercept item, a REST scan task | written by hand |
| [support.md](support.md) | Support crate types | generated |
| [report.md](report.md) | Report crate types | generated |
| [core-net.md](core-net.md) | Proxy, interception, sending, shared state | generated |
| [core-scan.md](core-scan.md) | Scanner run, issues, crawl and audit | generated |
| [core-scan-checks.md](core-scan-checks.md) | Scan checks | generated |
| [core-bcheck.md](core-bcheck.md) | BCheck parser and runner | generated |
| [desktop-ui.md](desktop-ui.md) | Desktop UI view types | generated |

## Regenerating

```sh
cargo install auto-uml
scripts/gen-uml.sh
```

The generated files are overwritten; `flows.md` and this file are not.

## Reading the class diagrams

They come from `auto-uml`, which parses the source with tree-sitter:

- A box is a struct, enum or trait, with its public fields and methods.
- Rust has no class inheritance. A trait such as `Default` appears as its own
  box, and the links are trait implementations and field types, not
  "is-a" relationships.
- The diagrams are per directory. Types from other directories appear only
  by name in field types.
- Free functions, which are most of the desktop UI and much of the engine,
  are not shown. That is why `desktop-ui.md` is nearly empty.
