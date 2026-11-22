#!/usr/bin/env bash
# Usage: lab/profiles/windows-single.setup.sh <lab-state-dir> <lab-prefix>
# Run by up.sh once ws answers SSH: installs Sysmon from the pinned, Authenticode-checked Sysinternals zip. LAB_SYSMON_ZIP uses a local zip instead of
# the download, LAB_SYSMON_SHA256 replaces the pin (both for tests of the checks only).
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

readonly SYSMON_PIN_NAME="sysmon"
readonly DOWNLOAD_TIMEOUT_SECONDS=300
readonly REMOTE_ZIP="C:/Windows/Temp/Sysmon.zip"
readonly REMOTE_DIR="C:/Windows/Temp/ostyr-sysmon"
readonly EVENT_ATTEMPTS=30
readonly EVENT_DELAY_SECONDS=2
readonly EXPORT_ATTEMPTS=6
readonly EXPORT_DELAY_SECONDS=10
readonly WINGET_SOURCE_URL="https://cdn.winget.microsoft.com/cache/source.msix"

lab_state="${1:?usage: windows-single.setup.sh <lab-state-dir> <lab-prefix>}"
key="$lab_state/id_ed25519"
read -r _ ws_user ws_address < <(awk '$1 == "ws"' "$lab_state/vms.txt")
[[ -n "$ws_address" ]] || die "vms.txt lacks the ws VM"
pins_file="$(dirname "${BASH_SOURCE[0]}")/../images/pins.tsv"
IFS=$'\t' read -r _ pinned_sha256 _ _ sysmon_url < <(awk -F'\t' -v name="$SYSMON_PIN_NAME" '$1 == name' "$pins_file")
expected_sha256="${LAB_SYSMON_SHA256:-${pinned_sha256:-}}"
[[ "$expected_sha256" =~ ^[0-9a-f]{64}$ ]] || die "no valid $SYSMON_PIN_NAME pin in $pins_file"

ssh_options=(-i "$key" -o BatchMode=yes -o ConnectTimeout=5 -o ServerAliveInterval=5 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)

ps_remote() {
    ssh -n "${ssh_options[@]}" "$ws_user@$ws_address" \
        "powershell -NoProfile -NonInteractive -EncodedCommand $(printf '%s' "\$ProgressPreference = 'SilentlyContinue'; $1" | iconv -f UTF-8 -t UTF-16LE | base64 -w0)" | tr -d '\r'
}

download_dir="$(mktemp -d "$lab_state/sysmon-dl.XXXXXX")"
zip_file="$download_dir/Sysmon.zip"
if [[ -n "${LAB_SYSMON_ZIP:-}" ]]; then
    cp -- "$LAB_SYSMON_ZIP" "$zip_file"
else
    log "ws: downloading Sysmon.zip"
    curl --fail --location --silent --show-error --max-time "$DOWNLOAD_TIMEOUT_SECONDS" --output "$zip_file" "$sysmon_url" ||
        die "Sysmon download failed (use LAB_SYSMON_ZIP=<path> when the URL is refused)"
fi
actual_sha256="$(sha256sum "$zip_file" | cut -d' ' -f1)"
[[ "$actual_sha256" == "$expected_sha256" ]] || die "Sysmon.zip digest $actual_sha256 differs from the pin $expected_sha256 (update the pin by a task)"

log "ws: copying and checking Sysmon64.exe"
scp "${ssh_options[@]}" "$zip_file" "$ws_user@$ws_address:$REMOTE_ZIP"
signature="$(ps_remote "Remove-Item -Recurse -Force '$REMOTE_DIR' -ErrorAction SilentlyContinue; Expand-Archive -Path '$REMOTE_ZIP' -DestinationPath '$REMOTE_DIR'; \
\$sig = Get-AuthenticodeSignature '$REMOTE_DIR/Sysmon64.exe'; \"\$(\$sig.Status)|\$(\$sig.SignerCertificate.Subject)\"")"
[[ "$signature" == Valid\|*"O=Microsoft Corporation"* ]] || die "Sysmon64.exe signature check failed: $signature"
log "ws: signature $signature"

ps_remote "& '$REMOTE_DIR/Sysmon64.exe' -accepteula -i | Out-Null; exit \$LASTEXITCODE" >/dev/null || die "Sysmon64.exe -i failed"
service_state="$(ps_remote "(Get-Service Sysmon64).Status")"
[[ "$service_state" == "Running" ]] || die "Sysmon64 service is not running: $service_state"
event_count=0
for ((attempt = 0; attempt < EVENT_ATTEMPTS && event_count < 1; attempt++)); do
    event_count="$(ps_remote "@(Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 1 -ErrorAction SilentlyContinue).Count" || echo 0)"
    [[ "$event_count" =~ ^[0-9]+$ ]] || event_count=0
    ((event_count >= 1)) || sleep "$EVENT_DELAY_SECONDS"
done
((event_count >= 1)) || die "no event in Microsoft-Windows-Sysmon/Operational"
bridge_address="${ws_address%.*}.1"
set_proxy="\$k = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'; Set-ItemProperty \$k ProxyEnable 1; Set-ItemProperty \$k ProxyServer '$bridge_address:$PROXY_PORT';"
log "ws: pointing the WinINet proxy at $bridge_address:$PROXY_PORT and registering winget"
ps_remote "Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe" >/dev/null || die "registering DesktopAppInstaller failed"
ps_remote "$set_proxy [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy('http://$bridge_address:$PROXY_PORT'); \
Invoke-WebRequest '$WINGET_SOURCE_URL' -OutFile C:\\Windows\\Temp\\source.msix -UseBasicParsing; Add-AppxPackage C:\\Windows\\Temp\\source.msix" >/dev/null ||
    die "installing the winget source package failed"
export_status=1
for ((attempt = 0; attempt < EXPORT_ATTEMPTS && export_status != 0; attempt++)); do
    export_status="$(ps_remote "$set_proxy winget export --include-versions --accept-source-agreements -o C:\\Windows\\Temp\\winget-check.json | Out-Null; \$LASTEXITCODE" || echo 1)"
    [[ "$export_status" =~ ^-?[0-9]+$ ]] || export_status=1
    ((export_status == 0)) || sleep "$EXPORT_DELAY_SECONDS"
done
[[ "$export_status" == "0" ]] || die "winget export failed with exit $export_status"
log "windows-single ready: Sysmon64 running, one Sysmon event read back, winget export works"
