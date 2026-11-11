#!/usr/bin/env bash
# Usage: lab/tests/subnet-test.sh
# Runs 6 up.sh at once, 3 from each of two lab copies (two checkouts, two state directories, one lock directory), with stub virsh, ssh and
# OpenTofu binaries that need no VM, and checks that the 6 labs get 6 distinct /24 subnets. No VM, no network.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

readonly LABS_PER_COPY=3
readonly APPLY_SECONDS=2
readonly EXPECTED_LABS=6
readonly TASKS="T227A T227B T227C T227D T227E T227F"

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

mkdir -p "$REPO_DIR/target"
work_dir="$(mktemp -d -p "$REPO_DIR/target")"
trap 'rm -rf "$work_dir"' EXIT
mkdir -p "$work_dir/home/.local/bin" "$work_dir/nets" "$work_dir/locks"

for copy in one two; do
    mkdir -p "$work_dir/$copy/lab/images" "$work_dir/$copy/lab/profiles"
    cp "$LAB_DIR/lib.sh" "$LAB_DIR/up.sh" "$LAB_DIR/egress-allow.txt" "$work_dir/$copy/lab/"
    grep -v "^egress:" "$LAB_DIR/profiles/ubuntu-single.yaml" >"$work_dir/$copy/lab/profiles/ubuntu-single.yaml"
    printf '#!/usr/bin/env bash\nexit 0\n' >"$work_dir/$copy/lab/images/build.sh"
    chmod +x "$work_dir/$copy/lab/images/build.sh"
done

cat >"$work_dir/home/.local/bin/virsh" <<'STUB'
#!/usr/bin/env bash
shift 2
command="$1"
case "$command" in
    pool-info) echo "State: running" ;;
    net-list) for file in "$STUB_NETS"/*; do [[ ! -e "$file" ]] || basename "$file"; done ;;
    net-dumpxml) cat "$STUB_NETS/$2" ;;
    vol-list) printf 'Name Path\n----\n ubuntu-2404.qcow2 /pool/ubuntu-2404.qcow2\n' ;;
    vol-download) exit 1 ;;
    list) ;;
esac
exit 0
STUB
printf '#!/usr/bin/env bash\nexit 0\n' >"$work_dir/home/.local/bin/ssh"
cat >"$work_dir/fake-binary" <<'STUB'
#!/usr/bin/env bash
for argument in "$@"; do
    [[ "$argument" == -state=* ]] && state="${argument#-state=}"
done
lab_state="$(dirname "${state:-/none/x}")"
case "${2:-}" in
    apply)
        octet="$(jq -r .subnet_octet "$lab_state/vars.json")"
        sleep "$STUB_APPLY_SECONDS"
        printf '<network><ip address="192.168.%s.1"/></network>\n' "$octet" >"$STUB_NETS/ostyr-$(basename "$lab_state")"
        ;;
    output)
        printf 'vm ubuntu 192.168.%s.2\n' "$(jq -r .subnet_octet "$lab_state/vars.json")"
        ;;
esac
exit 0
STUB
chmod +x "$work_dir/home/.local/bin/"* "$work_dir/fake-binary"

run_lab() {
    local copy="$1" task="$2"
    HOME="$work_dir/home" STUB_NETS="$work_dir/nets" STUB_APPLY_SECONDS="$APPLY_SECONDS" LAB_PROFILE=ubuntu-single \
        LAB_TOFU_BIN="$work_dir/fake-binary" LAB_PLUGIN_CACHE="$work_dir/cache" LAB_LOCK_DIR="$work_dir/locks" LAB_REAPER_ACTIVE=1 \
        LAB_MAX_VMS=100 timeout 120 "$work_dir/$copy/lab/up.sh" "$task" >"$work_dir/$task.out" 2>&1
}

pids=""
index=0
for task in $TASKS; do
    copy=one
    if ((index >= LABS_PER_COPY)); then copy=two; fi
    run_lab "$copy" "$task" &
    pids="$pids $!"
    index=$((index + 1))
done
for pid in $pids; do
    check "up.sh process $pid exits 0" wait "$pid"
done
if ((failures > 0)); then
    tail -n 5 "$work_dir"/T227*.out >&2
fi

octets="$(find "$work_dir/one/lab/state" "$work_dir/two/lab/state" -name vars.json -exec jq -r .subnet_octet {} + | sort -n)"
check "$EXPECTED_LABS labs got an octet" test "$(printf '%s\n' "$octets" | awk 'NF' | wc -l)" -eq "$EXPECTED_LABS"
check "the octets are distinct" test "$(printf '%s\n' "$octets" | sort -u | wc -l)" -eq "$EXPECTED_LABS"
check "subnet_holder names the network holding an octet" test "$(PATH="$work_dir/home/.local/bin:$PATH" STUB_NETS="$work_dir/nets" subnet_holder "$(printf '%s\n' "$octets" | head -n 1)" | wc -w)" -eq 1

if ((failures > 0)); then
    die "$failures check(s) failed"
fi
log "all subnet checks passed"
