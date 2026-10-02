<#
.SYNOPSIS
  Checks (read-only) that a lab victim logs what the scenario needs (task 3.1, defensive part).
  Run as administrator after lab\prepare_victim.ps1, before the scenario: every line must be OK.

.DESCRIPTION
  Reads only; changes nothing. Checks:
  - each advanced audit subcategory set by prepare_victim.ps1 audits at least Success
    (read with "auditpol /backup", whose numeric "Setting Value" column does not depend on the
    Windows language);
  - SCENoApplyLegacyAuditPolicy = 1, command line in 4688, PowerShell 4104 and 4103 policies;
  - each log is enabled and at least as large as requested;
  - Sysmon (optional: WARN when absent);
  - prints the time zone and the UTC time to note in the lab sheet (clocks, L3 section 2).
  Exit code: 0 = all OK, 1 = at least one FAIL, 2 = not administrator.

.PARAMETER OutFile
  Optional JSON report (UTF-8) to keep with the lab sheet.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File lab\check_logging.ps1 -OutFile C:\lab\WS-042_logging.json
#>
[CmdletBinding()]
param(
    [ValidateRange(64, 4096)][int]$SecurityLogMB = 1024,
    [ValidateRange(16, 2048)][int]$OtherLogMB = 256,
    [string]$OutFile = ""
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

# Same GUIDs as lab\prepare_victim.ps1 (checked by tests/test_lab_eval.py).
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

$Results = New-Object System.Collections.Generic.List[object]
function Add-Result([string]$Status, [string]$Check, [string]$Detail) {
    $Results.Add([pscustomobject]@{ status = $Status; check = $Check; detail = $Detail })
    Write-Host ("{0,-4} {1} {2}" -f $Status, $Check, $Detail)
}

function Get-RegValue([string]$Path, [string]$Name) {
    $item = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    $prop = $item.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}

function Test-RegDword([string]$Check, [string]$Path, [string]$Name, $Expected) {
    $v = Get-RegValue $Path $Name
    if ($null -ne $v -and "$v" -eq "$Expected") { Add-Result "OK" $Check "$Name = $v" }
    else { Add-Result "FAIL" $Check "$Path\$Name = $v (expected $Expected)" }
}

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    [Console]::Error.WriteLine("Run this script as administrator (auditpol needs it).")
    exit 2
}

Write-Host "== Advanced audit policy (effective)"
$tmp = Join-Path $env:TEMP ("auditpol_{0}.csv" -f [guid]::NewGuid())
try {
    & auditpol.exe /backup "/file:$tmp" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "auditpol /backup failed ($LASTEXITCODE)" }
    $settings = @{}
    foreach ($line in (Get-Content -LiteralPath $tmp | Select-Object -Skip 1)) {
        $cols = $line.Split(",")
        if ($cols.Count -ge 7 -and $cols[3] -match "^\{[0-9A-Fa-f-]+\}$") {
            $settings[$cols[3].ToUpperInvariant()] = $cols[6]
        }
    }
} finally {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
}
foreach ($guid in $AuditSubcategories.Keys) {
    $value = 0
    if ($settings.ContainsKey($guid) -and "$($settings[$guid])" -match "^[0-9]+$") {
        $value = [int]$settings[$guid]
    }
    $label = @{0 = "no auditing"; 1 = "success"; 2 = "failure only"; 3 = "success and failure"}[$value]
    if ($value -band 1) { Add-Result "OK" $AuditSubcategories[$guid] $label }
    else { Add-Result "FAIL" $AuditSubcategories[$guid] "$label (success required)" }
}
Test-RegDword "Advanced audit policy not overridden by legacy policy" `
    "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "SCENoApplyLegacyAuditPolicy" 1

Write-Host "== Command line and PowerShell"
Test-RegDword "Command line in 4688" `
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    "ProcessCreationIncludeCmdLine_Enabled" 1
$ps = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
Test-RegDword "PowerShell script blocks (4104)" "$ps\ScriptBlockLogging" "EnableScriptBlockLogging" 1
Test-RegDword "PowerShell modules (4103)" "$ps\ModuleLogging" "EnableModuleLogging" 1
Test-RegDword "PowerShell modules: all names" "$ps\ModuleLogging\ModuleNames" "*" "*"

Write-Host "== Event logs"
foreach ($name in $Logs.Keys) {
    try {
        $log = Get-WinEvent -ListLog $name -ErrorAction Stop
    } catch {
        Add-Result "FAIL" "Log $name" "not found"
        continue
    }
    $mb = [int]($log.MaximumSizeInBytes / 1MB)
    if (-not $log.IsEnabled) { Add-Result "FAIL" "Log $name" "disabled" }
    elseif ($mb -lt $Logs[$name]) { Add-Result "FAIL" "Log $name" "$mb MB < $($Logs[$name]) MB" }
    else { Add-Result "OK" "Log $name" "enabled, $mb MB, $($log.RecordCount) records" }
}

Write-Host "== Optional"
try {
    $sys = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction Stop
    Add-Result "OK" "Sysmon" "log present, enabled=$($sys.IsEnabled)"
} catch {
    Add-Result "WARN" "Sysmon" "not installed (optional)"
}

Write-Host "== Clock (note in the lab sheet)"
$tz = [TimeZoneInfo]::Local
$utc = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
Add-Result "INFO" "Time zone" "$($tz.Id) (UTC offset $($tz.GetUtcOffset([DateTime]::Now)))"
Add-Result "INFO" "UTC now" $utc

$fails = @($Results | Where-Object { $_.status -eq "FAIL" }).Count
if ($OutFile) {
    $report = [ordered]@{
        format = "forensic-mcp/lab-logging-check/1"; host = $env:COMPUTERNAME
        checked_utc = $utc; fails = $fails; results = $Results
    }
    $json = $report | ConvertTo-Json -Depth 4
    [IO.File]::WriteAllText($OutFile, $json, (New-Object Text.UTF8Encoding($false)))
    Write-Host "Report written: $OutFile"
}
Write-Host ""
if ($fails -eq 0) { Write-Host "RESULT: OK - logging ready"; exit 0 }
Write-Host "RESULT: $fails FAIL - run lab\prepare_victim.ps1 as administrator, then check again"
exit 1
