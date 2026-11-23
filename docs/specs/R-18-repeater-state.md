# R-18: owned Repeater UI state

This is the next structural slice after the Comparer/Decoder/Sequencer extraction in #104. It is not the completion of R-18.

`App.repeater: tool_state::RepeaterState` now owns eight fields: pane split, request/response message panes, configure-target dialog flag, content-length update flag, selected tab, and the two legacy view-choice fields. Defaults match the previous App constructor exactly: split0.5, request pane view1, default response pane, target dialog closed, update-content-length enabled, selected tab0, legacy response view0 and request view1. A regression checks those defaults. The legacy fields remain even though the current message panes have their own view state.

`repeater_ops::State` stays separate. It also contains Intercept and WebSocket behavior; moving that state into a Repeater-only owner would misstate its scope. The shared engine and threading model are unchanged.

All seven changed non-main callers match their original token streams after normalizing only these access paths and whitespace. Project serialization keys are unchanged, including the stored pane split and selected Repeater tab. This slice changes no conditions, message bytes, callbacks, network operations or field defaults.

Verification: workspace test build, full tests, rustfmt and all-target clippy passed. Actual desktop pixels were inspected for initial Raw-request/Pretty-response defaults and the configure-target dialog. A local HTTP fixture was configured through that dialog, a request was typed into Repeater and sent, and the response pane displayed HTTP200, the fixture Server header and response body. No external service was contacted for that QA.

The remaining App/Shared decomposition and narrower subsystem APIs remain open.
