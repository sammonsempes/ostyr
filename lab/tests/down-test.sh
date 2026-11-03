#!/usr/bin/env bash
# Usage: lab/tests/down-test.sh
# Starts two transient domains, fakes a hung OpenTofu (sleeps), runs down.sh with a short timeout, checks it ends in bounded time and nothing remains. Needs libvirt.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

readonly TASK="TDOWNHANG"
readonly TIMEOUT_SECONDS=5
readonly MAX_SECONDS=40
readonly HANG_SECONDS=613

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

prefix="$(lab_prefix "$TASK")"
lab_state="$(state_dir "$TASK")"
work_dir="$(mktemp -d)"
cleanup() {
    LAB_REAPER_ACTIVE=1 "$LAB_DIR/down.sh" "$TASK" >/dev/null 2>&1 || log "cleanup of $TASK failed"
    rm -rf "$work_dir"
}
trap cleanup EXIT

printf '#!/usr/bin/env bash\nsleep %s\n' "$HANG_SECONDS" >"$work_dir/hung-binary"
chmod +x "$work_dir/hung-binary"

for vm in a b; do
    cat >"$work_dir/$vm.xml" <<EOF
<domain type='kvm'>
  <name>$prefix-$vm</name>
  <memory unit='MiB'>16</memory>
  <os><type>hvm</type></os>
</domain>
EOF
    virsh_lab create "$work_dir/$vm.xml" >/dev/null
done

mkdir -p "$lab_state"
: >"$lab_state/lab.tfstate"
printf '{}' >"$lab_state/vars.json"

remaining_names() {
    (
        virsh_lab list --all --name
        virsh_lab net-list --all --name
    ) | names_with_prefix "$prefix"
}

check "two domains are running before down" test "$(virsh_lab list --name | names_with_prefix "$prefix-" | wc -l)" -eq 2

started="$(date +%s)"
down_status=0
LAB_TOFU_BIN="$work_dir/hung-binary" LAB_DESTROY_TIMEOUT="$TIMEOUT_SECONDS" LAB_REAPER_ACTIVE=1 "$LAB_DIR/down.sh" "$TASK" >/dev/null 2>&1 ||
    down_status=$?
elapsed=$(($(date +%s) - started))

check "down.sh exits 0" test "$down_status" -eq 0
check "down.sh took under ${MAX_SECONDS}s (took ${elapsed}s)" test "$elapsed" -lt "$MAX_SECONDS"
check "no domain or network remains" test -z "$(remaining_names)"
check "no descendant of the hung binary is left" test -z "$(pgrep -f "^sleep $HANG_SECONDS\$" || true)"
check "state directory is gone" test ! -e "$lab_state"

if ((failures > 0)); then
    die "$failures check(s) failed"
fi
log "all checks passed"
