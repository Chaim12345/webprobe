#!/usr/bin/env bash
# wp-queue — serialize heavy Rust jobs on a box shared by many AI agents.
#
# Why: ~10 agents run `cargo build` / `cargo test` in the same crate. They fight
# over Cargo's target-dir lock, every invocation re-links a big egui binary, and
# the machine stops responding. This queue runs one job at a time under `flock`
# and keeps a durable record of every run (exit code + `test result:` lines) so
# numbers can be trusted.
#
# Usage: wp-queue [--nowait] <subcommand> [args...]
#   build | test [FILTER...] | test-one <file> | check | clippy | fmt-check
#   run -- <cmd...> | status | log [N] | wait | history [N] | help
#
# Env: WP_APP_DIR (crate dir), WP_QUEUE_TIMEOUT (seconds, default 1800),
#      WP_QUEUE_DIR (state dir, default /tmp/wp-queue).
#
# Exit codes: the job's own status; 124 on timeout; 75 if --nowait and busy.

set -euo pipefail

# ---------------------------------------------------------------- configuration

WP_QUEUE_DIR=${WP_QUEUE_DIR:-/tmp/wp-queue}
LOCK_FILE="$WP_QUEUE_DIR/cargo.lock"
HOLDER_FILE="$WP_QUEUE_DIR/holder"
WAIT_DIR="$WP_QUEUE_DIR/waiters"
HISTORY="$WP_QUEUE_DIR/history.tsv"
TIMEOUT_SECS=${WP_QUEUE_TIMEOUT:-1800}
MAX_LOGS=200
MAX_LOG_AGE_SLACK=50          # only prune when we are this far past MAX_LOGS
NICE_LEVEL=10

SELF_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

# Resolve the crate directory: explicit env > sibling of this script > default.
if [[ -n ${WP_APP_DIR:-} ]]; then
    APP_DIR=$WP_APP_DIR
elif [[ -d "$SELF_DIR/../app" && -f "$SELF_DIR/../app/Cargo.toml" ]]; then
    APP_DIR=$(cd -- "$SELF_DIR/.." && pwd)/app
elif [[ -d "$SELF_DIR/app" && -f "$SELF_DIR/app/Cargo.toml" ]]; then
    APP_DIR=$SELF_DIR/app
else
    APP_DIR="/root/Documents/Craft Anything/burpsuite/app"
fi

NOWAIT=0

# ------------------------------------------------------------------- utilities

now_iso()   { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
now_stamp() { date -u '+%Y%m%dT%H%M%SZ'; }

die() { printf 'wp-queue: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
wp-queue — serialize cargo build/test across concurrent agents.

usage: wp-queue [--nowait] <subcommand> [args...]

  build                 cargo build
  test [FILTER...]      cargo test [FILTER...]
  test-one <file>       scripts/test-one.sh <file>, else cargo test --test <stem>
  check                 cargo check
  clippy                cargo clippy
  fmt-check             cargo fmt --check
  run -- <cmd...>       run any command under the same lock
  status                lock holder, queue depth, last 10 history rows
  log [N]               tail the newest job log (default 60 lines)
  wait                  block until the queue is idle
  history [N]           last N history rows (default 20)

env: WP_APP_DIR (crate dir), WP_QUEUE_TIMEOUT (default 1800s),
     WP_QUEUE_DIR (state dir, default /tmp/wp-queue)
exit: job status; 124 = timeout; 75 = busy and --nowait
EOF
}

ensure_dirs() {
    mkdir -p -- "$WP_QUEUE_DIR" "$WAIT_DIR"
    [[ -f $HISTORY ]] || : >"$HISTORY"
}

pid_alive() {
    local p=${1:-}
    [[ $p =~ ^[0-9]+$ ]] || return 1
    kill -0 "$p" 2>/dev/null
}

# Holder record: line 1 pid, line 2 ISO start, line 3 command string.
holder_field() {
    local n=$1
    [[ -f $HOLDER_FILE ]] || { printf ''; return 0; }
    sed -n "${n}p" "$HOLDER_FILE" 2>/dev/null || printf ''
}

count_waiters() {
    local f n=0
    [[ -d $WAIT_DIR ]] || { printf '0'; return 0; }
    for f in "$WAIT_DIR"/*; do
        [[ -e $f ]] || continue
        if pid_alive "$(basename -- "$f")"; then n=$((n + 1)); fi
    done
    printf '%s' "$n"
}

# True if the lock is currently held by somebody.
lock_is_held() {
    local fd
    exec {fd}>"$LOCK_FILE"
    if flock -n "$fd"; then
        flock -u "$fd"; exec {fd}>&-
        return 1
    fi
    exec {fd}>&-
    return 0
}

slugify() {
    local s
    s=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' \
        | tr -cs 'a-z0-9' '-' | sed 's/^-*//; s/-*$//')
    printf '%s' "${s:0:48}"
}

# Render argv as a single shell-quoted string (for logs, history, holder).
cmd_string() {
    local out='' a
    for a in "$@"; do out+=$(printf '%q ' "$a"); done
    printf '%s' "${out% }"
}

# Tab/newline-safe single-field text for the TSV history.
tsv_safe() { printf '%s' "$1" | tr '\t\n' '  '; }

# --------------------------------------------------------------------- locking

# Blocks (or fails with 75) until this process owns LOCK_FILE.
acquire_lock() {
    exec {LOCK_FD}>"$LOCK_FILE"

    if flock -n "$LOCK_FD"; then return 0; fi

    local hpid hcmd
    hpid=$(holder_field 1); hcmd=$(holder_field 3)

    if (( NOWAIT )); then
        printf 'wp-queue: busy (held by pid %s: %s); --nowait given, not waiting\n' \
            "${hpid:-?}" "${hcmd:-unknown}" >&2
        exit 75
    fi

    printf 'wp-queue: queued behind pid %s (%s) at %s\n' \
        "${hpid:-?}" "${hcmd:-unknown}" "$(now_iso)" >&2

    local wf="$WAIT_DIR/$$"
    : >"$wf"
    # shellcheck disable=SC2064
    trap "rm -f -- '$wf'" EXIT

    local t0=${SECONDS}
    flock "$LOCK_FD"
    rm -f -- "$wf"
    trap - EXIT
    printf 'wp-queue: lock acquired after %ss\n' "$((SECONDS - t0))" >&2
}

release_lock() {
    [[ -n ${LOCK_FD:-} ]] || return 0
    flock -u "$LOCK_FD" 2>/dev/null || true
    exec {LOCK_FD}>&-
    LOCK_FD=''
}

# ------------------------------------------------------------------ log upkeep

prune_logs() {
    local -a logs=()
    local n i
    mapfile -t logs < <(find "$WP_QUEUE_DIR" -maxdepth 1 -type f -name '*.log' -print | sort)
    n=${#logs[@]}
    (( n > MAX_LOGS + MAX_LOG_AGE_SLACK )) || return 0
    for (( i = 0; i < n - MAX_LOGS; i++ )); do
        rm -f -- "${logs[i]}"
    done
}

# ------------------------------------------------------------------ job runner

# run_job SLUG -- command...
# Holds the lock for the whole run, tees output to a log, records history,
# prints a compact summary, and returns the job's exit status.
run_job() {
    local slug=$1; shift
    if [[ ${1:-} == -- ]]; then shift; fi
    (( $# )) || die "run_job: no command"

    local cmdstr start end dur log rc=0 t_start t_end
    cmdstr=$(cmd_string "$@")
    start=$(now_iso)
    t_start=$(date +%s)
    log="$WP_QUEUE_DIR/$(now_stamp)-$slug.log"

    acquire_lock
    # We own the lock now: publish who we are, run, record, release.
    {
        printf '%s\n' "$$"
        printf '%s\n' "$start"
        printf '%s\n' "$cmdstr"
    } >"$HOLDER_FILE"
    # shellcheck disable=SC2064
    trap "rm -f -- '$HOLDER_FILE'" EXIT

    {
        printf '# wp-queue %s\n' "$start"
        printf '# cwd: %s\n' "$PWD"
        printf '# cmd: %s\n' "$cmdstr"
    } >"$log"

    local -a wrap=()
    if command -v ionice >/dev/null 2>&1; then wrap+=(ionice -c3 -t); fi
    if command -v nice   >/dev/null 2>&1; then wrap+=(nice -n "$NICE_LEVEL"); fi
    wrap+=(timeout --kill-after=30 -s TERM "$TIMEOUT_SECS")

    set +e
    if [[ -t 1 ]]; then
        # Interactive: show output live and keep the log.
        "${wrap[@]}" "$@" {LOCK_FD}>&- 2>&1 | tee -a -- "$log"
        rc=${PIPESTATUS[0]}
    else
        "${wrap[@]}" "$@" {LOCK_FD}>&- >>"$log" 2>&1
        rc=$?
    fi
    set -e

    end=$(now_iso)
    t_end=$(date +%s)
    dur=$((t_end - t_start))

    local timed_out=0
    if (( rc == 124 )); then timed_out=1; fi
    if (( rc == 137 && dur >= TIMEOUT_SECS )); then timed_out=1; fi

    # Extract every `test result:` line, normalised to key=value pairs.
    local tests=''
    local line p f i st
    while IFS= read -r line; do
        [[ $line == 'test result:'* ]] || continue
        st=${line#test result: }; st=${st%%.*}
        p=$(sed -n 's/.* \([0-9]\+\) passed.*/\1/p' <<<"$line")
        f=$(sed -n 's/.* \([0-9]\+\) failed.*/\1/p' <<<"$line")
        i=$(sed -n 's/.* \([0-9]\+\) ignored.*/\1/p' <<<"$line")
        p=${p:-0}; f=${f:-0}; i=${i:-0}
        tests+="${tests:+; }${st} total=$((p + f + i)) passed=$p failed=$f ignored=$i"
    done < <(grep -a 'test result:' "$log" || true)

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$start" "$end" "$dur" "$rc" "$(tsv_safe "$cmdstr")" "$(tsv_safe "$tests")" \
        >>"$HISTORY"

    rm -f -- "$HOLDER_FILE"
    trap - EXIT
    release_lock
    prune_logs
    ln -sfn -- "$(basename -- "$log")" "$WP_QUEUE_DIR/latest.log"

    # ------------------------------------------------------------- summary block
    local note=''
    if (( timed_out )); then note=" (TIMEOUT after ${TIMEOUT_SECS}s)"; fi
    printf '\n──────── wp-queue: %s\n' "$cmdstr"
    printf 'exit:     %s%s\n' "$rc" "$note"
    printf 'duration: %ss (%s -> %s)\n' "$dur" "$start" "$end"
    printf 'log:      %s\n' "$log"
    if [[ -n $tests ]]; then
        printf 'tests:    %s\n' "$tests"
        grep -a 'test result:' "$log" | sed 's/^/          /' || true
    fi
    if (( rc != 0 )); then
        local -a errs=()
        mapfile -t errs < <(grep -anE 'error(\[E[0-9]+\])?:|panicked at|^FAILED|^failures:|^ *thread .* panicked' "$log" | head -40 || true)
        if (( ${#errs[@]} )); then
            printf 'errors:   first %s matching lines\n' "${#errs[@]}"
            printf '%s\n' "${errs[@]}" | sed 's/^/          /'
        else
            printf 'errors:   no error lines matched; tail of log\n'
            tail -n 20 -- "$log" | sed 's/^/          /'
        fi
    fi
    printf '────────\n'

    return "$rc"
}

# -------------------------------------------------------------- cargo wrappers

require_app_dir() {
    [[ -d $APP_DIR ]] || die "target directory does not exist: $APP_DIR"
    [[ -f $APP_DIR/Cargo.toml ]] || die "no Cargo.toml in $APP_DIR"
    cd -- "$APP_DIR"
}

job_build()     { require_app_dir; run_job build cargo build "$@"; }
job_check()     { require_app_dir; run_job check cargo check "$@"; }
job_clippy()    { require_app_dir; run_job clippy cargo clippy "$@"; }
job_fmt()       { require_app_dir; run_job fmt-check cargo fmt --check "$@"; }

job_test() {
    require_app_dir
    local slug=test
    (( $# )) && slug="test-$(slugify "$*")"
    run_job "$slug" cargo test "$@"
}

job_test_one() {
    (( $# )) || die "test-one: missing <file>"
    local f=$1 stem helper
    stem=$(basename -- "$f" .rs)
    require_app_dir
    helper=''
    if [[ -f $APP_DIR/scripts/test-one.sh ]]; then
        helper=$APP_DIR/scripts/test-one.sh
    elif [[ -f $APP_DIR/../scripts/test-one.sh ]]; then
        helper=$(cd -- "$APP_DIR/.." && pwd)/scripts/test-one.sh
    fi
    if [[ -n $helper ]]; then
        run_job "test-one-$stem" bash "$helper" "$f"
    else
        run_job "test-$stem" cargo test --test "$stem"
    fi
}

job_run() {
    if [[ ${1:-} == -- ]]; then shift; fi
    (( $# )) || die "run: missing command (usage: wp-queue run -- <cmd...>)"
    # Arbitrary commands still get a sane cwd, but a missing crate is not fatal.
    if [[ -d $APP_DIR ]]; then cd -- "$APP_DIR"; fi
    local slug
    slug="run-$(slugify "$(cmd_string "$@")")"
    run_job "$slug" "$@"
}

# ------------------------------------------------------------- read-only views

cmd_status() {
    ensure_dirs
    local held=0 hpid='' hstart='' hcmd='' depth
    lock_is_held && held=1
    hpid=$(holder_field 1); hstart=$(holder_field 2); hcmd=$(holder_field 3)
    depth=$(count_waiters)

    printf 'lock:    %s\n' "$LOCK_FILE"
    if (( held )); then
        printf 'state:   HELD by pid %s since %s\n' "${hpid:-?}" "${hstart:-?}"
        printf 'command: %s\n' "${hcmd:-unknown}"
        if [[ -n $hpid ]] && ! pid_alive "$hpid"; then
            printf 'warning: lock is held but recorded pid %s is not running (stale holder record)\n' "$hpid"
        fi
    elif [[ -n $hpid ]]; then
        printf 'state:   idle (stale holder record for pid %s, not running; lock is free)\n' "$hpid"
        printf 'stale:   %s\n' "${hcmd:-unknown}"
    else
        printf 'state:   idle\n'
    fi
    printf 'queue:   %s waiting\n' "$depth"
    printf 'app:     %s\n' "$APP_DIR"
    printf 'timeout: %ss\n' "$TIMEOUT_SECS"
    printf 'history: %s rows\n' "$(wc -l <"$HISTORY" | tr -d ' ')"
    printf '\nlast 10 rows:\n'
    history_rows 10
}

history_rows() {
    local n=${1:-10}
    [[ -s $HISTORY ]] || { printf '  (empty)\n'; return 0; }
    printf '  %-20s %-20s %6s %4s  %s\n' 'START (UTC)' 'END (UTC)' 'SECS' 'RC' 'COMMAND | tests'
    awk -F'\t' -v n="$n" '{ rows[NR] = $0 } END {
        start = NR - n + 1; if (start < 1) start = 1
        for (i = start; i <= NR; i++) {
            split(rows[i], f, "\t")
            printf "  %-20s %-20s %6s %4s  %s%s\n", f[1], f[2], f[3], f[4], f[5], (f[6] != "" ? " | " f[6] : "")
        }
    }' "$HISTORY"
}

cmd_history() {
    ensure_dirs
    local n=${1:-20}
    [[ $n =~ ^[0-9]+$ ]] || die "history: N must be a number"
    printf '%s rows in %s\n' "$(wc -l <"$HISTORY" | tr -d ' ')" "$HISTORY"
    history_rows "$n"
}

cmd_log() {
    ensure_dirs
    local n=${1:-60}
    [[ $n =~ ^[0-9]+$ ]] || die "log: N must be a number"
    local f="$WP_QUEUE_DIR/latest.log"
    if [[ ! -e $f ]]; then
        f=$(find "$WP_QUEUE_DIR" -maxdepth 1 -type f -name '*.log' -print | sort | tail -1)
        [[ -n $f ]] || die "no job logs in $WP_QUEUE_DIR yet"
    fi
    printf '==> %s (last %s lines)\n' "$(readlink -f -- "$f")" "$n"
    tail -n "$n" -- "$f"
}

cmd_wait() {
    ensure_dirs
    local waited=0
    while :; do
        if (( $(count_waiters) == 0 )) && ! lock_is_held; then
            printf 'wp-queue: queue idle after %ss\n' "$waited" >&2
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
}

# ----------------------------------------------------------------------- main

main() {
    local -a args=()
    local a
    for a in "$@"; do
        case $a in
            --nowait) NOWAIT=1 ;;
            *) args+=("$a") ;;
        esac
    done
    set -- "${args[@]+"${args[@]}"}"

    local sub=${1:-help}
    if (( $# )); then shift; fi

    ensure_dirs

    case $sub in
        build)      job_build "$@" ;;
        test)       job_test "$@" ;;
        test-one)   job_test_one "$@" ;;
        check)      job_check "$@" ;;
        clippy)     job_clippy "$@" ;;
        fmt-check)  job_fmt "$@" ;;
        run)        job_run "$@" ;;
        status)     cmd_status ;;
        log)        cmd_log "${1:-60}" ;;
        wait)       cmd_wait ;;
        history)    cmd_history "${1:-20}" ;;
        help|-h|--help) usage ;;
        *)          die "unknown subcommand: $sub (try: wp-queue help)" ;;
    esac
}

main "$@"
