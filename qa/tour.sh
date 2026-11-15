#!/usr/bin/env bash
# Full visual tour: seeded data + sub-tabs + dialogs, one shot per state.
cd "/root/Documents/Craft Anything/burpsuite" || exit 1
D=/root/webprobe-shots/tour
mkdir -p "$D"
export QA_SHOTS="$D"

up() { qa/qa.sh up "$@" >/dev/null 2>&1; }

# 1. Dashboard with traffic and issues
up WEBPROBE_TAB=dashboard WEBPROBE_SEED_HISTORY=120
qa/qa.sh shot 01-dashboard

# 2. History with a row selected, message pane populated
up WEBPROBE_TAB=proxy WEBPROBE_PROXY_SUB=1 WEBPROBE_SEED_HISTORY=120 WEBPROBE_SELECT_ID=119
qa/qa.sh shot 02-history-selected

# 3. Column chooser open
qa/qa.sh click 40 181
sleep 1
qa/qa.sh shot 03-columns
qa/qa.sh key Escape

# 4. Message pane: Response, then Hex
qa/qa.sh click 106 657
sleep 1
qa/qa.sh shot 04-message-response
qa/qa.sh click 230 657
sleep 1
qa/qa.sh shot 05-message-hex

# 5. Intercept
up WEBPROBE_TAB=proxy WEBPROBE_PROXY_SUB=0 WEBPROBE_SEED_HISTORY=20
qa/qa.sh shot 06-intercept

# 6. Options (listeners, match and replace)
up WEBPROBE_TAB=proxy WEBPROBE_PROXY_SUB=3 WEBPROBE_SEED_HISTORY=20
qa/qa.sh shot 07-options

# 7. Repeater (seeded request, three panes)
up WEBPROBE_TAB=repeater WEBPROBE_SEED_REPEATER=/tmp/opencode/rep.txt
qa/qa.sh shot 08-repeater

# 8. Intruder with positions auto-marked
up WEBPROBE_TAB=intruder
qa/qa.sh click 700 90
sleep 1
qa/qa.sh shot 09-intruder-marked

# 9. Target with hosts
up WEBPROBE_TAB=target WEBPROBE_SEED_HISTORY=120
qa/qa.sh shot 10-target

# 10. Decoder
up WEBPROBE_TAB=decoder
qa/qa.sh shot 11-decoder

# 11. Comparer
up WEBPROBE_TAB=comparer WEBPROBE_SEED_HISTORY=20
qa/qa.sh shot 12-comparer

# 12. Settings window (hotkeys)
up WEBPROBE_TAB=dashboard WEBPROBE_SETTINGS=hotkeys
qa/qa.sh shot 13-settings-hotkeys

# 13. Command palette
up WEBPROBE_TAB=dashboard
qa/qa.sh key ctrl+k
sleep 1
qa/qa.sh shot 14-palette

qa/qa.sh down
ls "$D" | wc -l