# egui upgrade tooling — findings (2026-11-16)

No egui-specific migration tool exists: no codemod, no `cargo-*` subcommand, no MIGRATION.md,
no compatibility shim, no lint crate (all candidate crates.io/GitHub names are 404/empty).
egui's policy is "deprecate, delete within 1–2 releases" (0.35 removed everything deprecated),
so aliases only help if you hop one minor at a time.

Practical kit:
1. **Staged hops** 0.29 → 0.31 → 0.33 → 0.35 → 0.37 with `RUSTFLAGS="-D deprecated"`;
   the deprecation warnings name the replacement while it still exists.
2. **Compiler-driven fixes** for everything semantic (App::ui, Panel API, allocate_ui_at_rect,
   ctx.style, exact_height, copied_text, …). Our 0.35 pass produced 53 errors → 17 → 0-style waves.
3. **ast-grep** for mechanical text rewrites. Installed version 0.43.0 did NOT match Rust patterns
   here (`sg run -p 'Margin::same($N)' --json` returned `[]` on a file containing it), so either
   upgrade ast-grep or use `sed`/python for the handful of textual renames:
   - `Frame::none()` → `Frame::NONE`
   - `Rounding::same/ZERO` → `CornerRadius::same/ZERO`; `.rounding(` → `.corner_radius(`
   - `ctx.style()`/`set_style(` → `ctx.global_style()`/`set_global_style(`
   - `ctx.screen_rect()` → `ctx.viewport_rect()`
   - `ctx.wants_keyboard_input()` → `ctx.egui_wants_keyboard_input()`
   - `ui.close_menu()` → `ui.close()`
   - `.exact_height(` → `.exact_size(` (Panel)
   - `ui.id()` → `ui.scope_id()`
   - `TopBottomPanel::top/bottom` → `Panel::top/bottom` (then move `.show(ctx,` → `.show(ui,`)
   - `PlatformOutput.copied_text = X` → `ctx.copy_text(X)`
   - `Button::frame(Frame)` → `.frame(false)`; `TextEdit::frame(false)` → `.frame(Frame::default())`
   - `allocate_ui_at_rect(rect, f)` → `scope_builder(UiBuilder::new().max_rect(rect), f)`
9. **cargo-semver-checks** (`cargo semver-checks -p egui --baseline-version 0.29.1`) to inventory
   removals/renames before starting.
10. **egui_kittest 0.37** snapshot + AccessKit assertions to catch behavior changes that compile
    (padding, corner radii, menu-close semantics, kerning).
