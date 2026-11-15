# Visual review by MiniMax M3.1 Flash (nvidia/minimaxai/minimax-m3.1-flash), 2026-11-15

Single-image reviews (multi-image prompts are rejected by the provider's content-safety screen). Screens: current build.

## Repeater (p04-repeater-fixed.png)
Dark single-column workspace, request editor above response viewer, bottom status bar. Controls: `Rep 1` tab and add button, `Send (Ctrl+Space)`, request options, font-size selector, Raw/Hex/Pretty/JSON response tabs, dismissible toast.
**Findings:** no overlap or clipping; typography very small and low-contrast; controls cramped; the mostly empty lower area feels vertically unbalanced.

## Tab bar (p02-tabs.png)
Dense dashboard: top nav, secondary tabs, filter toolbar, action buttons, HTTP history table, status bar. Orange marks Proxy, blue marks HTTP history, status colours red/yellow/green.
**Worst three:**
1. Tiny low-contrast typography → use 12–13 px body/table text, 28–32 px rows, secondary text ≥ 4.5:1.
2. Cramped toolbar with unevenly sized dropdowns → group into labelled rows, 8–12 px gaps, standardise control heights.
3. Inconsistent selected-state colours (orange nav vs blue sub-tab) → one accent for active navigation, reserve other colours for status.

## HTTP history (p05-history-fixed.png)
Charcoal/navy, filter strip, sortable table, footer status bar.
**Worst three:**
1. Text too small and muted → raise sizes and secondary contrast.
2. Filter/action row cramped and ambiguous → structured grid, labels above fields, separate filter from destructive actions.
3. Table does not use available vertical space → fill the viewport, sticky header, consistent row heights and zebra striping.

## Intruder (p10-intruder-fixed.png)
Stacked request editor, payload editor, results area; upper half cramped, most of the page unused.
**Worst three:**
1. Unreadable typography and contrast → 12–13 px, lighter secondary (`#A7AFBC` on `#17191D`), WCAG AA.
2. Empty results area lacks structure → bordered panel with a bounded empty-state card (~160 px).
3. Cramped, weak control hierarchy → segmented controls for attack type, consistent 28–32 px heights, 8–12 px gaps.

## Fixes applied after the review
- **Secondary text contrast** raised from `0x6A6A6C` (~3.2:1) to `0x9AA0A6` (≥ 4.5:1 on the dark background) in `theme.rs`.
- **Type floor** raised: 10.5 → 11.5, 11.0 → 12.0, 11.5 → 12.0 across `src/*.rs`.
- **History table height** now fills the remaining space (`table_h = pane_h - min(split_detail, 60% of pane_h)`, minimum 160 px), so it no longer stops above a blank area.
- **Intruder empty state** wrapped in a bordered card with a 120 px minimum height.

## Still open
- One accent for active navigation (orange nav vs blue sub-tabs) — needs a design-token decision.
- Toolbar grouping/spacing on Proxy and Intruder (8–12 px gaps, labelled rows).
- Repeater lower-area balance.
