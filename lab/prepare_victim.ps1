<#
.SYNOPSIS
  Enables the Windows logging the lab scenario needs (task 3.1, defensive part). Run ONCE on
  each lab victim, as administrator, BEFORE the scenario; then run lab\check_logging.ps1.

.DESCRIPTION
  This script ONLY configures logging. It changes no other setting, downloads nothing and
  starts no other program (except the local Sysmon installer if -SysmonExe is given).
  - Advanced audit policy (by subcategory GUID, so it works on any Windows language):
      Process Creation (4688), Other Object Access Events (4698-4702 scheduled tasks),
      Logon (4624/4625), Logoff (4634/4647), Special Logon (4672),
      Other Logon/Logoff Events (4778/4779 RDP reconnect/disconnect),
      Credential Validation (4776), Security System Extension (4697 service installed),
      Audit Policy Change (4719), Security State Change (4608).
  - SCENoApplyLegacyAuditPolicy = 1 so these subcategories are not overridden by the legacy
    category policy.
  - Command line in 4688 (ProcessCreationIncludeCmdLine_Enabled = 1).
  - PowerShell Script Block Logging (4104) and Module Logging (4103), machine policy.
  - Microsoft-Windows-TaskScheduler/Operational enabled (106, 140, 141, 200).
  - Larger logs: Security, System, PowerShell, TaskScheduler, Terminal Services logs.
  - Optional: Sysmon from a LOCAL installer and configuration file chosen by the team.

.PARAMETER SecurityLogMB
  Maximum size of the Security log in MB (default 1024).

.PARAMETER OtherLogMB
  Maximum size of the other logs in MB (default 256).

.PARAMETER SysmonExe
  Optional local path of Sysmon64.exe (not downloaded by this script).

.PARAMETER SysmonConfig
  Configuration file for Sysmon (required with -SysmonExe).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File lab\prepare_victim.ps1
  powershell -ExecutionPolicy Bypass -File lab\prepare_victim.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateRange(64, 4096)][int]$SecurityLogMB = 1024,
    [ValidateRange(16, 2048)][int]$OtherLogMB = 256,
    [string]$SysmonExe = "",
    [string]$SysmonConfig = ""
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

# Advanced audit subcategories: GUID -> name (names for display only; auditpol gets the GUID).
# Keep in sync with lab\check_logging.ps1 (checked by tests/test_lab_eval.py).
$AuditSubcategories = [ordered]@{
    "{0CCE922B-69AE-11D9-BED3-505054503030}" = "Process Creation (4688)"
    "{0CCE9227-69AE-11D9-BED3-505054503030}" = "Other Object Access Events (4698 scheduled task)"
    "{0CCE9215-69AE-11D9-BED3-505054503030}" = "Logon (4624, 4625)"
    "{0CCE9216-69AE-11D9-BED3-505054503030}" = "Logoff (4634, 4647)"
    "{0CCE921B-69AE-11D9-BED3-505054503030}" = "Special Logon (4672)"
    "{0CCE921C-69AE-11D9-BED3-505054503030}" = "Other Logon/Logoff Events (4778, 4779)"
    "{0CCE923F-69AE-11D9-BED3-505054503030}" = "Credential Validation (4776)"
    "{0CCE9211-69AE-11D9-BED3-505054503030}" = "Security System Extension (4697)"
    "{0CCE922F-69AE-11D9-BED3-505054503030}" = "Audit Policy Change (4719)"
    "{0CCE9210-69AE-11D9-BED3-505054503030}" = "Security State Change (4608)"
}

$Logs = [ordered]@{
    "Security"                                                          = $SecurityLogMB
    "System"                                                            = $OtherLogMB
    "Windows PowerShell"                                                = $OtherLogMB
    "Microsoft-Windows-PowerShell/Operational"                          = $OtherLogMB
    "Microsoft-Windows-TaskScheduler/Operational"                       = $OtherLogMB
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" = $OtherLogMB
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"     = $OtherLogMB
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-RegDword([string]$Path, [string]$Name, [int]$Value) {
    if ($PSCmdlet.ShouldProcess("$Path\$Name", "set DWORD $Value")) {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
        Write-Host "  OK   $Path\$Name = $Value"
    }
}

if (-not (Test-Admin)) {
    [Console]::Error.WriteLine("Run this script as administrator.")
    exit 2
}
if ($SysmonExe -and -not $SysmonConfig) {
    [Console]::Error.WriteLine("-SysmonConfig is required with -SysmonExe.")
    exit 2
}

Write-Host "== Advanced audit policy"
Set-RegDword "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "SCENoApplyLegacyAuditPolicy" 1
foreach ($guid in $AuditSubcategories.Keys) {
    if ($PSCmdlet.ShouldProcess($AuditSubcategories[$guid], "auditpol success+failure")) {
        & auditpol.exe /set "/subcategory:$guid" /success:enable /failure:enable | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "auditpol failed for $($AuditSubcategories[$guid])" }
        Write-Host "  OK   $($AuditSubcategories[$guid])"
    }
}

Write-Host "== Command line in 4688"
Set-RegDword "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    "ProcessCreationIncludeCmdLine_Enabled" 1

Write-Host "== PowerShell logging (4104 script blocks, 4103 modules)"
$ps = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
Set-RegDword "$ps\ScriptBlockLogging" "EnableScriptBlockLogging" 1
Set-RegDword "$ps\ModuleLogging" "EnableModuleLogging" 1
if ($PSCmdlet.ShouldProcess("$ps\ModuleLogging\ModuleNames", "log every module (*)")) {
    if (-not (Test-Path "$ps\ModuleLogging\ModuleNames")) {
        New-Item -Path "$ps\ModuleLogging\ModuleNames" -Force | Out-Null
    }
    New-ItemProperty -Path "$ps\ModuleLogging\ModuleNames" -Name "*" -Value "*" `
        -PropertyType String -Force | Out-Null
    Write-Host "  OK   ModuleNames\* = *"
}

Write-Host "== Event logs: enabled and maximum size"
foreach ($name in $Logs.Keys) {
    $bytes = [int64]$Logs[$name] * 1MB
    if ($PSCmdlet.ShouldProcess($name, "enable, max size $($Logs[$name]) MB")) {
        try {
            $log = Get-WinEvent -ListLog $name -ErrorAction Stop
        } catch {
            Write-Warning "  log not found on this host: $name"
            continue
        }
        $log.IsEnabled = $true
        if ($log.MaximumSizeInBytes -lt $bytes) { $log.MaximumSizeInBytes = $bytes }
        $log.SaveChanges()
        Write-Host ("  OK   {0} ({1} MB)" -f $name, [int]($log.MaximumSizeInBytes / 1MB))
    }
}

if ($SysmonExe) {
    Write-Host "== Sysmon (optional, local installer)"
    foreach ($f in @($SysmonExe, $SysmonConfig)) {
        if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { throw "file not found: $f" }
    }
    $hash = (Get-FileHash -LiteralPath $SysmonExe -Algorithm SHA256).Hash
    $sig = (Get-AuthenticodeSignature -LiteralPath $SysmonExe).Status
    Write-Host "  Sysmon installer SHA-256 $hash, signature $sig (note both in the lab sheet)"
    if ($sig -ne "Valid") { throw "Sysmon installer signature is not valid: $sig" }
    if ($PSCmdlet.ShouldProcess($SysmonExe, "install with $SysmonConfig")) {
        & $SysmonExe -accepteula -i $SysmonConfig
        if ($LASTEXITCODE -ne 0) { throw "Sysmon install failed ($LASTEXITCODE)" }
        Write-Host "  OK   Sysmon installed"
    }
}

Write-Host ""
Write-Host "Done. Now run: powershell -ExecutionPolicy Bypass -File lab\check_logging.ps1"
Write-Host "Every line must be OK before the 'T1-logging' snapshot."
