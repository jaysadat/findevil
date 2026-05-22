[CmdletBinding()]
param(
    [string]$HostConfigPath = $env:FINDEVIL_SIFT_CONFIG,
    [string]$VmxPath = $env:SIFT_VMX_PATH,
    [string]$GuestUser = $env:SIFT_GUEST_USER,
    [string]$GuestPassword = $env:SIFT_GUEST_PASSWORD,
    [string]$VmrunPath = $env:VMRUN_PATH
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$hostConfig = $null
if (-not [string]::IsNullOrWhiteSpace($HostConfigPath)) {
    if (-not (Test-Path -LiteralPath $HostConfigPath)) {
        throw "SIFT host config was not found at '$HostConfigPath'."
    }
    $hostConfig = Get-Content -LiteralPath $HostConfigPath -Raw | ConvertFrom-Json
    if ($hostConfig.sift_vm.PSObject.Properties.Name -contains 'guest_password' -or
        $hostConfig.sift_vm.PSObject.Properties.Name -contains 'password' -or
        $hostConfig.sift_vm.PSObject.Properties.Name -contains 'token') {
        throw 'Keep SIFT guest secrets out of host config and use SIFT_GUEST_PASSWORD.'
    }
}

if ([string]::IsNullOrWhiteSpace($VmxPath)) {
    $VmxPath = if ($hostConfig -and $hostConfig.sift_vm.vmx_path) {
        $hostConfig.sift_vm.vmx_path
    } else {
        'E:\Ollama\SIFT\SIFT.vmx'
    }
}
if ([string]::IsNullOrWhiteSpace($GuestUser)) {
    $GuestUser = if ($hostConfig -and $hostConfig.sift_vm.guest_user) {
        $hostConfig.sift_vm.guest_user
    } else {
        'sansforensics'
    }
}
if ([string]::IsNullOrWhiteSpace($VmrunPath)) {
    $VmrunPath = if ($hostConfig -and $hostConfig.sift_vm.vmrun_path) {
        $hostConfig.sift_vm.vmrun_path
    } else {
        'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
    }
}

if (-not (Test-Path -LiteralPath $VmrunPath)) {
    throw "vmrun was not found at '$VmrunPath'."
}

if (-not (Test-Path -LiteralPath $VmxPath)) {
    throw "SIFT VMX was not found at '$VmxPath'."
}

if ([string]::IsNullOrWhiteSpace($GuestPassword)) {
    throw 'Set SIFT_GUEST_PASSWORD before running the guest probe.'
}

function Invoke-Vmrun {
    param([string[]]$Arguments)

    $output = & $VmrunPath @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "vmrun failed: $($output -join [Environment]::NewLine)"
    }

    return $output
}

$runningVms = Invoke-Vmrun -Arguments @('list')
if ($runningVms -notcontains $VmxPath) {
    Invoke-Vmrun -Arguments @('start', $VmxPath, 'nogui') | Out-Null
}

$toolsState = Invoke-Vmrun -Arguments @(
    '-gu', $GuestUser,
    '-gp', $GuestPassword,
    'checkToolsState',
    $VmxPath
)

$toolsStateValue = ($toolsState -join '').Trim()
if ($toolsStateValue -notin @('installed', 'running')) {
    throw "VMware Tools are not ready in the guest. State: $($toolsState -join ' ')"
}

$guestIp = Invoke-Vmrun -Arguments @('getGuestIPAddress', $VmxPath, '-wait')
$guestProbePath = '/tmp/findevil-sift-probe.json'
$hostProbePath = Join-Path $env:TEMP 'findevil-sift-probe.json'
$bashProbe = @'
set -eu
python3 - <<'PY'
import json
import os
import platform
import shutil
import socket

commands = [
    "python3",
    "ewfinfo",
    "fls",
    "log2timeline.py",
    "vol",
    "volatility3",
    "mcp",
]

result = {
    "hostname": socket.gethostname(),
    "platform": platform.platform(),
    "user": os.environ.get("USER"),
    "commands": {command: shutil.which(command) for command in commands},
    "protocol_sift_home": os.path.exists(os.path.expanduser("~/protocol-sift")),
}

with open("/tmp/findevil-sift-probe.json", "w", encoding="utf-8") as handle:
    json.dump(result, handle, indent=2, sort_keys=True)
PY
'@

Invoke-Vmrun -Arguments @(
    '-gu', $GuestUser,
    '-gp', $GuestPassword,
    'runScriptInGuest',
    $VmxPath,
    '/bin/bash',
    $bashProbe
) | Out-Null

Invoke-Vmrun -Arguments @(
    '-gu', $GuestUser,
    '-gp', $GuestPassword,
    'copyFileFromGuestToHost',
    $VmxPath,
    $guestProbePath,
    $hostProbePath
) | Out-Null

$probe = Get-Content -LiteralPath $hostProbePath -Raw | ConvertFrom-Json
[pscustomobject]@{
    vmx_path = $VmxPath
    guest_ip = ($guestIp -join '').Trim()
    vmware_tools = $toolsStateValue
    probe = $probe
} | ConvertTo-Json -Depth 6
