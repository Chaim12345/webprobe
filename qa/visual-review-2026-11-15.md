# Visual review, Burp reference vs WebProbe (2026-11-15)

Produced by the multimodal-looker subagent (nemotron VL) reading the screenshot pairs; saved here because the agent had no write tool.

## Pair 6, Comparer (WebProbe side)
Dark header; orange "Comparator" tab with dropdown arrow. Subtitle: "Edit the two inputs and Compare. The diff is an exact line-level LCS; line numbers are 1-based per side and byte lengths cover the displayed line text (terminators excluded)." Chip row: "Selected request → A", "Selected response → A", "Selected request → B", "Selected response → B". Two panes labelled "A / left side" and "B / right side" (empty). "Compare" and "Clear" buttons below; hint "no diff yet; press Compare to produce row(s)". No column headers (# / Length / Data), no Paste/Load/Remove/Clear stack, no "Compare … / Words / Bytes" grouping.

## Ranked visual/UX gaps in WebProbe
1. **Repeater has no response inspection.** Add a Pretty/Raw/HEX tab strip above the request editor and a right Inspector panel (Notes/Explanations/Custom actions tabs), min-height ~300 px per pane.
2. **Decoder lost its mode controls and output.** Restore the Text | Hex radio, "Decode as / Encode as / Hash" dropdowns and a primary "Smart decode" button; label the top editor "Input" and add a bottom "Output" pane.
3. **Comparer lost its per-item structure.** Restore "Select item 1/2" headings with # / Length / Data columns; add a Paste/Load/Remove/Clear stack per item; relabel the panes "Item 1"/"Item 2".
4. **Proxy filter row is crammed under the intercept banner.** Wrap it in a bordered container with ≥8 px gap below the banner; pin the column headers; increase row padding so status chips have ~6 px clearance.
5. **Dashboard setup lacks a severity breakdown and pause/resume.** Add per-severity issue pills (red/orange/blue/gray counts) to the Overview stat cards and a prominent "Resume"/"Continue audit" CTA; mirror the reference's task-configuration/progress/task-log rail on the right.

## Visual defects in WebProbe
- Repeater request pane has no visible borders or separators and collapses; no indication a response pane exists.
- Decoder's flat row of eight action buttons is visually undifferentiated (no primary action) and has no output area, so it is ambiguous where results appear.
- Comparer panes lack labels inside ("left side"/"right side" sit above, not within), making the inputs ambiguous; empty panes have no placeholder text.
- Proxy table rows are tight; status chips (red 500, orange 404) nearly touch adjacent cell borders; the "40 of 40" count floats without a clear container.
- Dashboard "Jump to" pill row is long and wraps riskily on narrower viewports; no visual grouping against "Listeners"/"Project" below.
- Low contrast: the "intercept off – click to turn on" banner text on the dark gray header is marginally readable; the recent-activity log is small gray text on a dark background.
