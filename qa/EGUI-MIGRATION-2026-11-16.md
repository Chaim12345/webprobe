# egui upgrade: changelog → our code (2026-11-16)

Target: `/root/webprobe-egui33` (branch `egui33-trial`), isolated from `master`.
Reference: egui CHANGELOG (0.34.0, 0.35.0, 0.36.0, 0.37.0) and docs.rs/egui/0.37.0.

## Version decision

| Version | Requires | Verdict |
|---|---|---|
| 0.33 | 1.92 | first MCP-compatible step (`egui-mcp-client` pins `egui = "0.33"`) |
| 0.34 / 0.35 | 1.92 | **chosen**: newest that builds on this box's rustc 1.92 |
| 0.36 / 0.37 | 1.95 | not buildable here — `rustup toolchain install stable` could not complete (network); 0.37 also needs a larger migration |

So the work is done against **0.35**, with every 0.37-only change identified so the
next bump is a version change, not a rewrite.

## Changes that hit our code

### 0.31–0.33 (landed while we were on 0.29)

| Change | Sites | Action |
|---|---|---|
| `Margin` fields/`same`/`symmetric` became `i8` | ui.rs (6), collaborator_ui.rs, shortcuts.rs, theme.rs (`SPACE_* as i8`) | float literals → integers |
| `Rounding` → `CornerRadius`; `.rounding(..)` → `.corner_radius(..)` | ui.rs, msgpane.rs, shortcuts.rs, theme.rs | renamed |
| `Frame::none()` → `Frame::NONE` | collaborator_ui.rs, ui.rs, shortcuts.rs, theme.rs | renamed |
| `Painter::rect` gained `StrokeKind` | history_filter.rs:325, ui.rs:3663 | added `egui::StrokeKind::Inside` |
| `PlatformOutput::copied_text` removed | ui.rs ×5 (Copy buttons, menu actions) | → `ui.ctx().copy_text(..)` |
| `Fonts::layout_job` takes `&mut self` | msgpane.rs:346 | → `ui.painter().layout_job(job)` |
| `TextEditOutput.cursor_range` is now `CCursorRange` | msgpane.rs:551 | `as_ccursor_range()` dropped |
| `PlacedRow.rect` removed | msgpane.rs:560 | → `row.pos.y` |
| `glow::PixelPackData::Slice(Option<&mut [u8]>)` | main.rs:506 | `Some(&mut pixels)` |

### 0.34–0.35 (the structural change)

| Change | Sites | Action |
|---|---|---|
| `App::update` deprecated (0.34), replaced by `App::ui(&mut Ui, &mut Frame)` + `logic` | main.rs `impl eframe::App` | `fn ui(...)`; `let ctx = ui.ctx().clone();` at the top |
| `SidePanel`/`TopBottomPanel` deprecated (0.34), removed in 0.35 → `Panel` | ui.rs ×3 (`menu_bar`, `main_bar`, `status_bar`) | `egui::Panel::top/bottom(id).frame(..).show(ui, ..)` |
| `CentralPanel::show(ctx)` deprecated → `show(ui)` | ui.rs:339 | `.show(ui, ..)` |
| `accesskit` feature always on (0.34) | Cargo.toml | kept `accesskit` in the feature list; drop if 0.35 rejects it |
| deprecated APIs removed in 0.35 (`clip_rect_margin`, `Context::style`, `AsId`, …) | none found (grep: 0 hits) | — |

### 0.36–0.37 (not taken)

- `RawInput.modifiers` removed; modifiers became an `Event` (0.36) — we have 0 hits.
- `Ui::id` → `Ui::scope_id`; `AsId` removed; `Id::new` deprecated (0.37) — 0 hits.
- `default_fonts` no longer a default feature (0.37) — we request it explicitly.
- `Panel::show_inside` renamed back to `Panel::show` (0.37) — already using `show`.
- `WidgetType` → `egui::Role` (0.37) — no AccessKit-specific code.

## Crates that pinned old egui

- `egui-mcp-client 0.0.5` → `egui = "0.33"`. Vendored to `vendor/egui-mcp-client`,
  dependency set to 0.35, wired with `[patch.crates-io]`.
- `egui-phosphor 0.8` → `egui 0.30`. Vendored to `vendor/egui-phosphor`, dependency
  set to 0.35. (`egui-pop-phosphor 0.15` exists but targets 0.37, which we can't build.)

## MCP integration shape (from the upstream demo, not the README)

`McpClient` is `&self` + tokio:

1. build a `tokio::runtime::Runtime`, keep it in `App`;
2. `McpClient::new()`, spawn `IpcServer::run(client.clone())`;
3. `cc.egui_ctx.enable_accesskit()` in the creation closure;
4. `impl eframe::App::raw_input_hook`: `take_pending_inputs()` + `egui_mcp_client::inject_inputs`;
5. `update/ui`: poll `take_screenshot_request()`, send `ViewportCommand::Screenshot`,
   answer `Event::Screenshot` with `set_screenshot(png)`;
6. `draw_highlights(ctx, &get_highlights())` at the end of the frame.

## Status

- Mechanical 0.33 fixes: applied.
- App/Panel migration: applied.
- Vendor patches: applied.
- Build: in progress (`/tmp/opencode/egui35-errors.log`).
- MCP client wiring: pending the green build.
## What each release adds, and why it matters to WebProbe

| Version | Headline changes | Benefit to us |
|---|---|---|
| **0.33** (Dec 2025) | Plugin API, better kerning, `egui::Plugin`; the version `egui-mcp-client` targets | Baseline that can carry the MCP IPC client |
| **0.34** (Mar 2026) | New `App::ui`/`logic` and unified `Panel` (deprecations); AccessKit always on; Skrifa + vello_cpu font rendering with hinting; font variations | Ui-based root matches what egui-mcp expects; crisp text in dense tables; accessibility is not a feature flag any more |
| **0.35** (Jun 2026) | Inspection protocol + plugin; `Classes` on `UiBuilder`/widgets; real IME composition visuals; drag-to-close panels; harfrust kerning/ligatures; Atoms/`AtomLayout`; `IdSalt`; custom OS cursors; new Window margins; 0.2 s animations | Better typography (kerning/ligatures) for code/HTTP text; CSS-like `Classes` for theming; draggable panels could replace custom splitters; inspection plugin helps debugging the UI; IME fixes for CJK input |
| **0.36** (Aug 2026) | `BoxedWidget` (dynamic widgets); `Window::title_frame`; drag-to-open panels; popup/scroll/window fixes; MSRV 1.95 | Dynamic dialogs (Settings, findings) without enum match; custom title bars; fewer popup/scroll bugs in menus and tables |
| **0.37** (Oct 2026) | Runtime font provider + glyph rasterizer (system fonts); better popup/menu/modal/panel trees; AccessKit `Role`, accessible names, hidden widgets excluded; image paste; `Aligned`, `RangeSlider`, `CompletionPopup`; kinetic scrolling; `RoundedRect`/`BandShape`; roomier buttons | Accessibility tree quality for MCP (`get_ui_tree` labels/roles); system fonts instead of bundling; completion popup for filters/search; range slider for port/timing settings; smoother menus; roomier controls closer to Burp's spacing |

### Cost of going further

0.36/0.37 require **Rust 1.95**; this box has 1.92 and cannot download a newer toolchain, so
0.35 is the ceiling here. The 0.37-only code work is already done (App::ui, Panel, CornerRadius,
`show(ui, …)`), so a future bump is a manifest change plus a short compile-fix pass — not a rewrite.

## Update: Rust 1.100 installed → 0.37 is now the target (same day)

The box was upgraded to rustc/cargo **1.100.0** (2026-11-09) and `wp-queue` was repointed at
`/root/.cargo/bin/cargo`. With MSRV 1.95 satisfied, the trial moved from 0.35 to **0.37**:

- `eframe/egui/egui_glow/egui_extras = "0.37"`, `egui-pop-phosphor = "0.15"` (the 0.37 icon fork),
  vendored `egui-mcp-client` retargeted to egui 0.37.
- `ui.id()` → `ui.scope_id()` (0.37 rename).
- `Id::new(...)` still compiles (deprecated).
- Build trap: the queue wrapper runs `/root/.cargo/bin/cargo` (1.100) but cargo resolves `rustc`
  from `PATH`, where `/usr/bin/rustc` is still 1.92 — pass `RUSTC=/usr/local/bin/rustc` (1.100)
  explicitly, otherwise deps fail with "requires rustc 1.95".
