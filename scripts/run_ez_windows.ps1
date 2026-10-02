#Requires -Version 5.1
<#
.SYNOPSIS
  Run one Eric Zimmerman CLI tool on Windows for forensic-mcp (option A, Decision J3) and write
  an export that the server imports with ez_import.

.DESCRIPTION
  For the tools that do not run in the Linux container (PECmd, SQLECmd, WxTCmd, SrumECmd,
  SumECmd). Same registry as the server: rules/ez_registry.json (tool list, input flags, output
  format, fixed flags, TYPED options). No free-form argument: -Options keys must be options of
  the tool in the registry, each value is checked against its kind (bool, int, ids, date,
  enum_batch, regpath, evidence_path). The input and every path option must be under the
  evidence root (no symlink / junction). The output folder is chosen by the script:
    <EvidenceRoot>\<CaseHost>\ez_out\<Tool>_<yyyyMMddTHHmmssZ>\out\
  plus manifest.json (tool, version, exe SHA-256, input SHA-256, argv, UTC times, outputs).
  Input digest: file = SHA-256; folder = SHA-256 of the sorted (ordinal) lines
  "relative/path<NUL>sha256<LF>" of its files (dot files and case.toml skipped), as in
  src/forensic_mcp/import_ops.py.

.EXAMPLE
  .\scripts\run_ez_windows.ps1 -Tool PECmd -CaseHost WS-042 `
      -InputPath WS-042\kape\C\Windows\prefetch -EzDir C:\Tools\ZimmermanTools\net9
.EXAMPLE
  .\scripts\run_ez_windows.ps1 -Tool SrumECmd -CaseHost WS-042 -EzDir C:\Tools\EZ `
      -InputPath WS-042\kape\C\Windows\System32\sru\SRUDB.dat `
      -Options @{ software_hive = 'WS-042\kape\C\Windows\System32\config\SOFTWARE' }
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Tool,
    [Parameter(Mandatory = $true)][string]$InputPath,
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9_.-]{1,64}$')][string]$CaseHost,
    [Parameter(Mandatory = $true)][string]$EzDir,
    [string]$EvidenceRoot = '',
    [hashtable]$Options = @{},
    [string]$Registry = '',
    [ValidateRange(1, 1440)][int]$TimeoutMinutes = 120,
    [switch]$DryRun
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# $PSScriptRoot is empty in param() defaults under Windows PowerShell 5.1: resolve them here.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $EvidenceRoot) { $EvidenceRoot = Join-Path $here '..\evidence' }
if (-not $Registry) { $Registry = Join-Path $here '..\rules\ez_registry.json' }

function Get-Prop($Object, [string]$Name) {
    # Property lookup that returns $null when absent (StrictMode would throw).
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null } else { return $p.Value }
}
$ScriptVersion = '1'
$ExportFormat = 'forensic-mcp/ez-windows-export/1'

function Get-Sha256Hex([string]$Path) { (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() }

function Resolve-UnderRoot([string]$Path, [string]$Root) {
    # Full path under $Root, no reparse point (symlink / junction) on the way (like the server jail).
    $full = if ([IO.Path]::IsPathRooted($Path)) { [IO.Path]::GetFullPath($Path) }
            else { [IO.Path]::GetFullPath((Join-Path $Root $Path)) }
    $prefix = $Root.TrimEnd('\') + '\'
    if (-not ($full -eq $Root.TrimEnd('\') -or $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase))) {
        throw "Path outside the evidence root: $Path"
    }
    if (-not (Test-Path -LiteralPath $full)) { throw "Not found: $full" }
    $p = $full
    while ($p.Length -gt $Root.TrimEnd('\').Length) {
        if ((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Symlink / junction refused: $p"
        }
        $p = Split-Path -Parent $p
    }
    return $full
}

function Get-RelativePosix([string]$Full, [string]$Base) {
    return $Full.Substring($Base.TrimEnd('\').Length + 1).Replace('\', '/')
}

function Get-ContentDigest([string]$Path) {
    if (Test-Path -LiteralPath $Path -PathType Leaf) { return (Get-Sha256Hex $Path) }
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($f in Get-ChildItem -LiteralPath $Path -Recurse -File -Force) {
        $rel = Get-RelativePosix $f.FullName $Path
        if ($f.Name -eq 'case.toml' -or ($rel.Split('/') | Where-Object { $_.StartsWith('.') })) { continue }
        $lines.Add($rel + [char]0 + (Get-Sha256Hex $f.FullName) + "`n")
    }
    $arr = $lines.ToArray()
    [Array]::Sort($arr, [StringComparer]::Ordinal)
    $bytes = (New-Object Text.UTF8Encoding $false).GetBytes(($arr -join ''))
    $sha = [Security.Cryptography.SHA256]::Create()
    return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
}

function ConvertTo-ArgString([string[]]$Argv) {
    # Quote each argument for CommandLineToArgvW (paths with spaces, trailing backslashes).
    $out = foreach ($a in $Argv) {
        if ($a -notmatch '[\s"]' -and $a.Length -gt 0) { $a; continue }
        $s = '"'; $bs = 0
        foreach ($c in $a.ToCharArray()) {
            if ($c -eq '\') { $bs++ ; continue }
            if ($c -eq '"') { $s += ('\' * (2 * $bs + 1)) + '"' } else { $s += ('\' * $bs) + $c }
            $bs = 0
        }
        $s + ('\' * (2 * $bs)) + '"'
    }
    return ($out -join ' ')
}

# ---- registry and tool -------------------------------------------------------------------
$reg = Get-Content -LiteralPath $Registry -Raw -Encoding UTF8 | ConvertFrom-Json
if ($reg.format -ne 'forensic-mcp/ez-registry/1') { throw "Unknown registry format in $Registry" }
$spec = Get-Prop $reg.tools $Tool
if ($null -eq $spec) { throw "Unknown tool '$Tool'. Registry tools: $($reg.tools.PSObject.Properties.Name -join ', ')" }
$root = [IO.Path]::GetFullPath($EvidenceRoot).TrimEnd('\')
$inputFull = Resolve-UnderRoot $InputPath $root
$isDir = Test-Path -LiteralPath $inputFull -PathType Container
$inFlag = if ($isDir) { '-d' } else { '-f' }
if (@($spec.inputs) -notcontains $inFlag) {
    throw "$Tool takes $(@($spec.inputs) -join ' or ') ($($spec.artefacts))"
}
$exe = Get-ChildItem -LiteralPath $EzDir -Recurse -File -Filter "$Tool.exe" |
       Sort-Object { $_.FullName.Length } | Select-Object -First 1
if ($null -eq $exe) { throw "$Tool.exe not found under $EzDir" }

# ---- typed options ------------------------------------------------------------------------
$optArgv = New-Object System.Collections.Generic.List[string]
foreach ($name in $Options.Keys) {
    $o = Get-Prop $spec.options $name
    if ($null -eq $o) { throw "$Tool has no option '$name'. Allowed: $((@($spec.options.PSObject.Properties | ForEach-Object { $_.Name }) -join ', ')) (none = no option)" }
    $v = $Options[$name]
    switch ($o.kind) {
        'bool' { if ($v -isnot [bool]) { throw "$name must be `$true or `$false" }
                 if ($v) { $optArgv.Add($o.flag) }; continue }
        'int' { if ($v -isnot [int] -or $v -lt -1 -or $v -gt 1000000) { throw "$name must be an integer" }
                $optArgv.Add($o.flag); $optArgv.Add([string]$v); continue }
        'ids' { $ids = @($v)
                if ($ids.Count -eq 0 -or ($ids | Where-Object { $_ -isnot [int] -or $_ -lt 0 -or $_ -gt 65535 })) {
                    throw "$name must be a list of event IDs (0-65535)" }
                $optArgv.Add($o.flag); $optArgv.Add(($ids -join ',')); continue }
        'date' { $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
                 $d = [datetime]::Parse([string]$v, [Globalization.CultureInfo]::InvariantCulture, $styles)
                 $optArgv.Add($o.flag); $optArgv.Add($d.ToString('yyyy-MM-dd HH:mm:ss.fffffff', [Globalization.CultureInfo]::InvariantCulture)); continue }
        'enum_batch' { $b = Join-Path (Join-Path $exe.DirectoryName 'BatchExamples') ([string]$v)
                       if (([string]$v) -notmatch '^[A-Za-z0-9_.-]+\.reb$' -or -not (Test-Path -LiteralPath $b -PathType Leaf)) {
                           throw "Unknown RECmd batch '$v' (must be shipped in BatchExamples)" }
                       $optArgv.Add($o.flag); $optArgv.Add($b); continue }
        'regpath' { if (([string]$v) -notmatch $reg.regpath_pattern -or ([string]$v).Length -gt 512) { throw "$name must be a registry path" }
                    $optArgv.Add($o.flag); $optArgv.Add([string]$v); continue }
        'evidence_path' { $optArgv.Add($o.flag); $optArgv.Add((Resolve-UnderRoot ([string]$v) $root)); continue }
        default { throw "Unsupported option kind '$($o.kind)'" }
    }
}
if ($Tool -eq 'RECmd' -and $optArgv -notcontains '--bn' -and $optArgv -notcontains '--kn') { throw 'RECmd needs batch or key' }
$oflag = if ($Tool -eq 'RECmd' -and $optArgv -contains '--bn') { '--csv' } else { [string]$spec.output }

# ---- output folder, argv ------------------------------------------------------------------
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$exportDir = Join-Path $root (Join-Path $CaseHost (Join-Path 'ez_out' "$($Tool)_$stamp"))
$outDir = Join-Path $exportDir 'out'
$target = if ($oflag -eq '-o') { Join-Path $outDir 'strings.txt' } else { $outDir }
$argv = @($inFlag, $inputFull) + $optArgv.ToArray() + @($oflag, $target) + @($spec.fixed)
$bad = @($argv | Where-Object { @($reg.forbidden) -contains $_ })
if ($bad.Count -gt 0) { throw "Forbidden flag(s): $($bad -join ', ')" }
$inputRel = Get-RelativePosix $inputFull $root
Write-Host "Tool    : $($exe.FullName) ($($exe.VersionInfo.FileVersion))"
Write-Host "Input   : $inputRel"
Write-Host "Command : $Tool $(ConvertTo-ArgString $argv)"
Write-Host "Export  : $exportDir"
$inputDigest = Get-ContentDigest $inputFull
if ($DryRun) { Write-Host "Input digest: $inputDigest"; Write-Host 'Dry run: nothing executed, nothing written.'; return }

# ---- run ----------------------------------------------------------------------------------
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$stdout = Join-Path $exportDir 'stdout.txt'; $stderr = Join-Path $exportDir 'stderr.txt'
$started = (Get-Date).ToUniversalTime()
$p = Start-Process -FilePath $exe.FullName -ArgumentList (ConvertTo-ArgString $argv) -NoNewWindow `
        -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
$null = $p.Handle  # PS 5.1: without reading the handle now, ExitCode stays $null after exit
if (-not $p.WaitForExit($TimeoutMinutes * 60000)) { $p.Kill(); throw "Timeout after $TimeoutMinutes min" }
$p.WaitForExit()   # flush the redirected streams
if ($null -eq $p.ExitCode) { throw 'Exit code unavailable: the export would be unverifiable' }
$finished = (Get-Date).ToUniversalTime()
$outputs = @(foreach ($f in Get-ChildItem -LiteralPath $outDir -Recurse -File) {
    [ordered]@{ file = (Get-RelativePosix $f.FullName $outDir); sha256 = (Get-Sha256Hex $f.FullName); size = $f.Length } })
function Get-Tail([string]$Path) { if (Test-Path -LiteralPath $Path) { $t = Get-Content -LiteralPath $Path -Raw; if ($t) { return $t.Substring([Math]::Max(0, $t.Length - 2000)) } }; return '' }
$manifest = [ordered]@{
    format = $ExportFormat; tool = $Tool; tool_version = $exe.VersionInfo.FileVersion
    tool_exe_sha256 = (Get-Sha256Hex $exe.FullName)
    tool_signature = (Get-AuthenticodeSignature -LiteralPath $exe.FullName).Status.ToString()
    host = $CaseHost
    input = [ordered]@{ path = $inputRel; kind = $(if ($isDir) { 'folder' } else { 'file' }); sha256 = $inputDigest }
    argv = @($Tool) + $argv; output_format = $oflag; outputs = $outputs
    started_utc = $started.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'); finished_utc = $finished.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    exit_code = $p.ExitCode; stdout_tail = (Get-Tail $stdout); stderr_tail = (Get-Tail $stderr)
    script = 'run_ez_windows.ps1'; script_version = $ScriptVersion; registry_sha256 = (Get-Sha256Hex $Registry)
    analyst = $env:USERNAME; workstation = $env:COMPUTERNAME
}
[IO.File]::WriteAllText((Join-Path $exportDir 'manifest.json'), ($manifest | ConvertTo-Json -Depth 6),
                        (New-Object Text.UTF8Encoding $false))
Write-Host "Done: exit $($p.ExitCode), $($outputs.Count) output file(s). Import it with ez_import(tool='$Tool', path='$(Get-RelativePosix $exportDir $root)')."
