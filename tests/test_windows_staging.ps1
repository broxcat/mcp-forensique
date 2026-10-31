$ErrorActionPreference = 'Stop'
$source = Get-Content -Raw (Join-Path $PSScriptRoot '..\scripts\run_ez_windows.ps1')
$start = $source.IndexOf('$root = [IO.Path]')
$end = $source.IndexOf('$inputFull = Resolve-UnderRoot', $start)
$guard = [scriptblock]::Create($source.Substring($start, $end - $start))
$EvidenceRoot = Join-Path $env:TEMP 'forensic-test-evidence'
foreach ($StagingRoot in @($EvidenceRoot, (Join-Path $EvidenceRoot 'child'), $env:TEMP)) {
    $refused = $false
    try { . $guard } catch { $refused = $true }
    if (-not $refused) { throw 'Nested staging root accepted' }
}
$StagingRoot = Join-Path $env:TEMP 'forensic-test-staging'
. $guard
if ($staging -eq $root) { throw 'Roots are not separated' }
Write-Output 'Windows staging guard: 4 checks passed; no writes performed'
