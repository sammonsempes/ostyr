#!/usr/bin/env bash
# Usage: lab/tests/build-skip-test.sh
# Checks the input fingerprint of images/build.sh with stub packer, virsh, curl, gpgv and qemu-img: first build runs Packer once, a second
# build never, an edited template once, --force once, two concurrent builds once in total. No VM, no network.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

readonly IMAGE="ubuntu-2404"
readonly SLOW_SECONDS=3

failures=0
fails() {
    ! "$@"
}

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
trap 'rm -rf "$work_dir"' EXIT
mkdir -p "$work_dir/home/.local/bin" "$work_dir/pool" "$work_dir/lab"
cp -r "$LAB_DIR/lib.sh" "$LAB_DIR/images" "$work_dir/lab/"
image_file="$(sed -n 's/^ *iso_url *= *"\${var.image_base_url}\/\(.*\)"/\1/p' "$LAB_DIR/images/$IMAGE.pkr.hcl")"

cat >"$work_dir/home/.local/bin/packer" <<'STUB'
#!/usr/bin/env bash
if [[ "$1" == "build" ]]; then
    echo call >>"$STUB_COUNT"
    printf '%s\n' "$*" >"$STUB_ARGS"
    for argument in "$@"; do
        [[ "$argument" == output_directory=* ]] && output="${argument#output_directory=}"
    done
    [[ -z "${STUB_SLOW:-}" ]] || sleep "$STUB_SLOW"
    mkdir -p "$output"
    echo image >"$output/ubuntu-2404.qcow2"
fi
STUB
cat >"$work_dir/home/.local/bin/curl" <<'STUB'
#!/usr/bin/env bash
while [[ $# -gt 0 ]]; do
    [[ "$1" == "--output" ]] && output="$2"
    shift
done
printf '%064d *%s\n' 0 "$STUB_IMAGE_FILE" >"$output"
STUB
cat >"$work_dir/home/.local/bin/virsh" <<'STUB'
#!/usr/bin/env bash
shift 2
command="$1"
shift
while [[ "${1:-}" == --* ]]; do
    if [[ "$1" == "--pool" || "$1" == "--format" ]]; then shift; fi
    shift
done
case "$command" in
    pool-info) echo "State: running" ;;
    vol-info) [[ -e "$STUB_POOL/$1" ]] ;;
    vol-create-as) : >"$STUB_POOL/$1" ;;
    vol-upload) cat "$2" >"$STUB_POOL/$1" ;;
    vol-download) cat "$STUB_POOL/$1" >"$2" ;;
    vol-delete) rm -f "$STUB_POOL/$1" ;;
    vol-path) echo "$STUB_POOL/$1" ;;
    vol-list) printf 'Name Path\n----\n' ;;
esac
STUB
printf '#!/usr/bin/env bash\n' >"$work_dir/home/.local/bin/gpgv"
printf '#!/usr/bin/env bash\n' >"$work_dir/home/.local/bin/qemu-img"
chmod +x "$work_dir/home/.local/bin/"*

export STUB_ARGS="$work_dir/args" STUB_COUNT="$work_dir/count" STUB_POOL="$work_dir/pool" STUB_IMAGE_FILE="$image_file"
export LAB_BUILD_LOCK_DIR="$work_dir/locks"
export HOME="$work_dir/home"
build="$work_dir/lab/images/build.sh"
template="$work_dir/lab/images/$IMAGE.pkr.hcl"

reset_count() {
    : >"$STUB_COUNT"
}

calls() {
    wc -l <"$STUB_COUNT" | tr -d ' '
}

run_build() {
    "$build" "$@" >"$work_dir/output" 2>&1
}

reset_count
check "first build succeeds" run_build "$IMAGE"
check "first build calls packer once" test "$(calls)" = 1
check "first build stores the fingerprint" test -s "$work_dir/pool/$IMAGE.qcow2.inputs"
reset_count
check "second build succeeds" run_build "$IMAGE"
check "second build does not call packer" test "$(calls)" = 0
check "second build says up to date" grep -q 'up to date' "$work_dir/output"

printf '\n' >>"$template"
reset_count
check "build after a template edit succeeds" run_build "$IMAGE"
check "template edit rebuilds once" test "$(calls)" = 1

reset_count
check "forced build succeeds" run_build --force "$IMAGE"
check "--force rebuilds once" test "$(calls)" = 1
reset_count
check "LAB_FORCE_BUILD build succeeds" env LAB_FORCE_BUILD=1 "$build" "$IMAGE" >/dev/null 2>&1
check "LAB_FORCE_BUILD=1 rebuilds once" test "$(calls)" = 1

rm -f "$work_dir/pool/$IMAGE.qcow2.inputs"
reset_count
check "build with a missing fingerprint succeeds" run_build "$IMAGE"
check "missing fingerprint rebuilds" test "$(calls)" = 1

rm -f "$work_dir/pool/"*
reset_count
(STUB_SLOW="$SLOW_SECONDS" "$build" "$IMAGE" >/dev/null 2>&1) &
first_pid=$!
(STUB_SLOW="$SLOW_SECONDS" "$build" "$IMAGE" >/dev/null 2>&1) &
second_pid=$!
check "first concurrent build succeeds" wait "$first_pid"
check "second concurrent build succeeds" wait "$second_pid"
check "concurrent builds call packer once" test "$(calls)" = 1

invalid_accel() {
    (
        export LAB_ACCEL=xen
        lab_accel
    ) 2>/dev/null
}

touch "$work_dir/fake-kvm"
check "LAB_ACCEL=kvm is kvm" test "$(LAB_ACCEL=kvm lab_accel)" = kvm
check "LAB_ACCEL=tcg is tcg" test "$(LAB_ACCEL=tcg lab_accel)" = tcg
check "readable device selects kvm" test "$(LAB_KVM_DEVICE="$work_dir/fake-kvm" lab_accel)" = kvm
check "missing device selects tcg" test "$(LAB_KVM_DEVICE="$work_dir/absent" lab_accel)" = tcg
check "LAB_ACCEL overrides the device" test "$(LAB_ACCEL=tcg LAB_KVM_DEVICE="$work_dir/fake-kvm" lab_accel)" = tcg
check "invalid LAB_ACCEL is refused" fails invalid_accel
check "kvm factor is 1" test "$(LAB_ACCEL=kvm accel_timeout_factor)" = 1
check "tcg factor is TCG_TIMEOUT_FACTOR" test "$(LAB_ACCEL=tcg accel_timeout_factor)" = "$TCG_TIMEOUT_FACTOR"

fingerprint_before="$(cat "$work_dir/pool/$IMAGE.qcow2.inputs")"
for accel in kvm tcg; do
    check "forced $accel build succeeds" env LAB_ACCEL="$accel" "$build" --force "$IMAGE" >/dev/null 2>&1
    check "packer receives accelerator=$accel" grep -q -- "-var accelerator=$accel " "$STUB_ARGS"
    check "$accel build keeps the fingerprint" test "$(cat "$work_dir/pool/$IMAGE.qcow2.inputs")" = "$fingerprint_before"
done
check "tcg passes the timeout factor" grep -q -- "-var timeout_factor=$TCG_TIMEOUT_FACTOR " "$STUB_ARGS"

[[ "$failures" -eq 0 ]] || die "$failures check(s) failed"
log "all build-skip checks passed"
