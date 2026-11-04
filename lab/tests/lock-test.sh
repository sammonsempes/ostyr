#!/usr/bin/env bash
# Usage: lab/tests/lock-test.sh
# Checks that a held build lock only blocks labs that need that image, that a waiting up.sh says what it waits for, and that init fails fast. Needs libvirt.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

readonly TASK="TLOCKTEST"
readonly PRESENT_PROFILE="ubuntu-single"
readonly MISSING_PROFILE="tlocktest-missing"
readonly MISSING_IMAGE="tlocktest-missing"
readonly HOLD_SECONDS=120
readonly WAIT_SECONDS=8
readonly PROCEED_SECONDS=20
readonly INIT_LIMIT_SECONDS=3
readonly FAKE_INIT_SLEEP_SECONDS=30

failures=0
check() {
    local description="$1"
    shift
    if "$@"; then
        log "ok   $description"
    else
        log "FAIL $description"
        failures=$((failures + 1))
    fi
}

work_dir="$(mktemp -d)"
missing_profile_file="$LAB_DIR/profiles/$MISSING_PROFILE.yaml"
missing_lock="$LAB_STATE_ROOT/build-$MISSING_IMAGE.lock"
present_lock="$LAB_STATE_ROOT/build-ubuntu-2404.lock"
missing_holder_pid=""
present_holder_pid=""
cleanup() {
    kill "$missing_holder_pid" "$present_holder_pid" 2>/dev/null || log "lock holders already gone"
    LAB_REAPER_ACTIVE=1 "$LAB_DIR/down.sh" "$TASK" >/dev/null 2>&1 || log "cleanup of $TASK failed"
    rm -rf "$work_dir" "$missing_profile_file" "$missing_lock"
}
trap cleanup EXIT

mkdir -p "$LAB_STATE_ROOT"
cat >"$work_dir/fake-binary" <<SCRIPT
#!/usr/bin/env bash
if [[ "\${2:-}" == "init" && -n "\${FAKE_INIT_SLEEP:-}" ]]; then
    sleep "\$FAKE_INIT_SLEEP"
fi
if [[ "\${2:-}" == "apply" ]]; then
    echo applied >>"$work_dir/applied"
fi
exit 0
SCRIPT
chmod +x "$work_dir/fake-binary"

cat >"$missing_profile_file" <<PROFILE
vms:
  - name: vm
    base_image: $MISSING_IMAGE.qcow2
    vcpu: 2
    ssh_user: ubuntu
PROFILE

run_up() {
    LAB_PROFILE="$1" LAB_TOFU_BIN="$work_dir/fake-binary" LAB_PLUGIN_CACHE="$work_dir/cache" LAB_REAPER_ACTIVE=1 \
        timeout "$2" "$LAB_DIR/up.sh" "$TASK" >"$work_dir/up.out" 2>&1
}

flock "$missing_lock" sleep "$HOLD_SECONDS" &
missing_holder_pid=$!
flock "$present_lock" sleep "$HOLD_SECONDS" &
present_holder_pid=$!
sleep 1

status=0
run_up "$PRESENT_PROFILE" "$PROCEED_SECONDS" || status=$?
check "up.sh with present images proceeds to apply while build locks are held (status $status)" test -s "$work_dir/applied"
check "the provider cache directory was created outside the checkout" test -d "$work_dir/cache"
LAB_REAPER_ACTIVE=1 "$LAB_DIR/down.sh" "$TASK" >/dev/null 2>&1

status=0
run_up "$MISSING_PROFILE" "$WAIT_SECONDS" || status=$?
check "up.sh for a missing image waits on its build lock (status $status)" test "$status" -eq 124
check "the wait is logged once with the lock name" test "$(grep -c "waiting for lock build-$MISSING_IMAGE.lock" "$work_dir/up.out")" -eq 1

status=0
FAKE_INIT_SLEEP="$FAKE_INIT_SLEEP_SECONDS" LAB_INIT_TIMEOUT="$INIT_LIMIT_SECONDS" run_up "$PRESENT_PROFILE" "$PROCEED_SECONDS" || status=$?
check "init timeout makes up.sh fail with a clear message (status $status)" grep -q "neither in" "$work_dir/up.out"

if ((failures > 0)); then
    die "$failures check(s) failed"
fi
log "all checks passed"
