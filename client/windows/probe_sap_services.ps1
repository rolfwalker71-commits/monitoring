#Requires -Version 5.1
<#!
.SYNOPSIS
  Probe SAP B1 servertools services on Windows and map ports.

.DESCRIPTION
  - Finds services with Name starting with sapb1servertools
  - Reads DisplayName, State/Status, StartMode, ProcessId
  - Tries to map listening TCP ports by ProcessId
  - Writes a compact table and JSON output

.USAGE
  powershell.exe -ExecutionPolicy Bypass -File .\probe_sap_services.ps1
#>

[CmdletBinding()]
param(
    [string[]]$NamePrefixes = @('sap', 'sbo', 'b1'),
    [string[]]$ContainsKeywords = @('sap business one', 'service layer', 'servertools', 'workflow', 'di proxy', 'di server', 'integration service', 'remote support platform for sap business one'),
    [string]$OutFile = '.\sap_service_probe_result.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ListeningPortsByPid {
    $map = @{}

    try {
        $netTcpCmd = Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue
        if ($null -ne $netTcpCmd) {
            $rows = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)
            foreach ($row in $rows) {
                $procId = [int]$row.OwningProcess
                if ($procId -le 0) { continue }
                if (-not $map.ContainsKey($procId)) {
                    $map[$procId] = New-Object 'System.Collections.Generic.HashSet[string]'
                }
                [void]$map[$procId].Add([string]$row.LocalPort)
            }
            return $map
        }
    } catch {
        # fallback below
    }

    try {
        $lines = @(netstat -ano -p tcp 2>$null)
        foreach ($line in $lines) {
            if ($line -notmatch '^\s*TCP\s+') { continue }
            if ($line -notmatch '\s+LISTENING\s+') { continue }

            $parts = ($line -replace '^\s+', '') -split '\s+'
            if ($parts.Count -lt 5) { continue }

            $localAddress = [string]$parts[1]
            $pidRaw = [string]$parts[4]
            if ($pidRaw -notmatch '^\d+$') { continue }

            $port = ''
            if ($localAddress -match ':([0-9]+)$') {
                $port = $Matches[1]
            }
            if (-not $port) { continue }

            $procId = [int]$pidRaw
            if ($procId -le 0) { continue }
            if (-not $map.ContainsKey($procId)) {
                $map[$procId] = New-Object 'System.Collections.Generic.HashSet[string]'
            }
            [void]$map[$procId].Add($port)
        }
    } catch {
        # leave map empty
    }

    return $map
}

function Sort-Ports {
    param([string[]]$Ports)

    $nums = @()
    foreach ($p in @($Ports)) {
        if ($p -match '^\d+$') {
            $n = [int]$p
            if ($n -ge 1 -and $n -le 65535) {
                $nums += $n
            }
        }
    }

    return @($nums | Sort-Object -Unique | ForEach-Object { [string]$_ })
}

$timestampUtc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
$hostname = $env:COMPUTERNAME

function Test-SapServiceMatch {
    param(
        [string]$Name,
        [string]$DisplayName,
        [string]$PathName,
        [string[]]$Prefixes
    )

    $n = [string]$Name
    $d = [string]$DisplayName
    $pname = [string]$PathName
    if ($n -eq 'AppXSvc' -or $d -like 'AppX Deployment Service*') {
        return $false
    }

    foreach ($prefix in @($Prefixes)) {
        $p = [string]$prefix
        if (-not $p) { continue }
        if ($n.StartsWith($p, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
        if ($d.StartsWith($p, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }

    if ($n -match '^(?i)b1s\d+$') { return $true }
    if ($n -match '^(?i)(B1ServerTools|B1Workflow|SAPB1|SBODI_|SBOMail|SBOWF|SBOClient)') { return $true }
    if ($d -match '(?i)SAP\s+Business\s+One') { return $true }

    foreach ($kw in @($ContainsKeywords)) {
        $k = [string]$kw
        if (-not $k) { continue }
        if ($n.IndexOf($k, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
        if ($d.IndexOf($k, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
        if ($pname.IndexOf($k, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    }

    if ($pname.IndexOf('\\SAP\\', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    if ($pname.IndexOf('SAP Business One', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }

    return $false
}

function Test-SapB1Candidate {
    param(
        [string]$Name,
        [string]$DisplayName,
        [string]$PathName
    )

    $n = [string]$Name
    $d = [string]$DisplayName
    $p = [string]$PathName

    if ($n -match '^(?i)(AppXSvc|COMSysApp)$') { return $false }
    if ($d -match '^(?i)(AppX Deployment Service|COM\+ System Application)') { return $false }
    if ($n -match '^(?i)PPSOne_') { return $false }
    if ($d -match '^(?i)PPSOne_') { return $false }
    if ($n -match '^(?i)PrintWorkflow(_|UserSvc_)') { return $false }
    if ($d -match '^(?i)PrintWorkflow(UserSvc)?_') { return $false }

    if ($n -match '^(?i)b1s\d+$') { return $true }
    if ($n -match '^(?i)(B1ServerTools|B1Workflow|SAPB1|SBODI_|SBOMail|SBOWF|SBOClient)') { return $true }

    if ($d -match '(?i)SAP\s+Business\s+One') { return $true }
    if ($d -match '(?i)(Service\s*Layer|Server\s*Tools|Workflow|DI\s*Proxy|DI\s*Server|Integration\s*Service|RSP\s*Agent)') { return $true }

    if ($p -match '(?i)\\SAP\\') { return $true }
    if ($p -match '(?i)(ServiceLayer|ServerTools|DIProxy|IntegrationServer|Remote support platform for SAP Business One)') { return $true }

    return $false
}

function Get-PortHintsForService {
    param(
        [string]$Name,
        [string]$DisplayName
    )

    $hints = @()
    $n = [string]$Name
    $d = [string]$DisplayName

    if ($n -match '^(?i)b1s(\d{4,5})$') {
        $hints += [string]$Matches[1]
    }

    if ($d -match '\((\d{4,5})\)') {
        $hints += [string]$Matches[1]
    }

    if ($n -match '^(?i)B1ServerToolsAuthentication$') {
        $hints += '40020'
    }

    return Sort-Ports -Ports @($hints)
}

function Get-PortsForProcess {
    param(
        [hashtable]$PortsByPid,
        [int]$ProcessId
    )

    if ($ProcessId -le 0 -or -not $PortsByPid.ContainsKey($ProcessId)) {
        return @()
    }

    $raw = $PortsByPid[$ProcessId]
    if ($null -eq $raw) {
        return @()
    }

    if ($raw -is [string]) {
        return @([string]$raw)
    }

    if ($raw -is [System.Collections.IEnumerable]) {
        $result = @()
        foreach ($entry in $raw) {
            if ($null -eq $entry) { continue }
            $result += [string]$entry
        }
        return $result
    }

    return @([string]$raw)
}

$services = @()
$allServices = @()
$diagnosticCandidates = @()
try {
    $allServices = @(Get-CimInstance Win32_Service -ErrorAction Stop)
    foreach ($svc in $allServices) {
        if (Test-SapB1Candidate -Name ([string]$svc.Name) -DisplayName ([string]$svc.DisplayName) -PathName ([string]$svc.PathName)) {
            $services += $svc
        }

        $diagName = [string]$svc.Name
        $diagDisplay = [string]$svc.DisplayName
        if ($diagName -match '(?i)(sap|sbo|b1)' -or $diagDisplay -match '(?i)(sap|sbo|b1)') {
            $diagnosticCandidates += [PSCustomObject]@{
                name = $diagName
                display_name = $diagDisplay
                state = [string]$svc.State
                path_name = [string]$svc.PathName
            }
        }
    }
} catch {
    # fallback for older/stricter hosts
    $services = @()
    try {
        $allServices = @(Get-Service -ErrorAction SilentlyContinue)
        foreach ($svc in $allServices) {
            if (-not (Test-SapB1Candidate -Name ([string]$svc.Name) -DisplayName ([string]$svc.DisplayName) -PathName '')) {
                continue
            }
            $services += [PSCustomObject]@{
                Name = [string]$svc.Name
                DisplayName = [string]$svc.DisplayName
                State = [string]$svc.Status
                Status = [string]$svc.Status
                StartMode = ''
                ProcessId = 0
            }
        }

        foreach ($svc in $allServices) {
            $diagName = [string]$svc.Name
            $diagDisplay = [string]$svc.DisplayName
            if ($diagName -match '(?i)(sap|sbo|b1)' -or $diagDisplay -match '(?i)(sap|sbo|b1)') {
                $diagnosticCandidates += [PSCustomObject]@{
                    name = $diagName
                    display_name = $diagDisplay
                    state = [string]$svc.Status
                    path_name = ''
                }
            }
        }
    } catch {
        $services = @()
    }
}

$portsByPid = Get-ListeningPortsByPid

$items = @()
foreach ($svc in $services) {
    $name = [string]$svc.Name
    $displayName = [string]$svc.DisplayName

    # Defensive final filter: never include known non-SAP noise services.
    if ($name -match '^(?i)(PPSOne_|PrintWorkflow(UserSvc)?_)') { continue }
    if ($displayName -match '^(?i)(PPSOne_|PrintWorkflow(UserSvc)?_)') { continue }

    $state = [string]$svc.State
    if (-not $state) { $state = [string]$svc.Status }
    $startMode = [string]$svc.StartMode

    $procId = 0
    try { $procId = [int]$svc.ProcessId } catch { $procId = 0 }

    $ports = @()
    if ($procId -gt 0 -and $portsByPid.ContainsKey($procId)) {
        $ports = Sort-Ports -Ports (Get-PortsForProcess -PortsByPid $portsByPid -ProcessId $procId)
    }

    $portsCsv = '-'
    $protocol = '-'
    if (@($ports).Count -gt 0) {
        $portsCsv = ($ports -join ',')
        $protocol = 'tcp'
    } else {
        $hintPorts = Get-PortHintsForService -Name $name -DisplayName $displayName
        if (@($hintPorts).Count -gt 0) {
            $portsCsv = ($hintPorts -join ',')
            $protocol = 'tcp-hint'
        }
    }

    $items += [PSCustomObject]@{
        description = $(if ($displayName) { $displayName } else { $name })
        name = $name
        status = $state
        live = $(if ($state -match '^(Running|active)$') { 'Live' } else { 'Nicht Live' })
        prot = $protocol
        ports = $portsCsv
        process_id = $procId
        start_mode = $startMode
    }
}

$ordered = @($items | Sort-Object description, name)

$result = [PSCustomObject]@{
    timestamp_utc = $timestampUtc
    host = $hostname
    available = (@($ordered).Count -gt 0)
    reason = $(if (@($ordered).Count -gt 0) { '' } else { 'Keine SAPServices gefunden' })
    service_count = @($ordered).Count
    services = $ordered
    diagnostic_candidates = @($diagnosticCandidates | Sort-Object name, display_name | Select-Object -First 40)
}

Write-Host ""
Write-Host "=== SAP Service Probe ==="
Write-Host ("Host: {0}" -f $hostname)
Write-Host ("Timestamp UTC: {0}" -f $timestampUtc)
Write-Host ("Found services: {0}" -f @($ordered).Count)
Write-Host ""

if (@($ordered).Count -gt 0) {
    $ordered |
        Select-Object description, name, status, live, ports, process_id, start_mode |
        Format-Table -AutoSize
} else {
    Write-Host "Keine passenden Dienste gefunden."
    if (@($diagnosticCandidates).Count -gt 0) {
        Write-Host ""
        Write-Host "Diagnose: Dienste mit sap/sbo/b1 im Namen oder Anzeigenamen:"
        $diagnosticCandidates |
            Sort-Object name, display_name |
            Select-Object -First 20 name, display_name, state |
            Format-Table -AutoSize
    }
}

$json = $result | ConvertTo-Json -Depth 6

$resolvedOutFile = ''
if ([System.IO.Path]::IsPathRooted($OutFile)) {
    $resolvedOutFile = [System.IO.Path]::GetFullPath($OutFile)
} else {
    $resolvedOutFile = Join-Path -Path ((Resolve-Path .\).Path) -ChildPath $OutFile
}

$outDir = Split-Path -Path $resolvedOutFile -Parent
if (-not [string]::IsNullOrWhiteSpace($outDir)) {
    [System.IO.Directory]::CreateDirectory($outDir) | Out-Null
}

$writeOk = $false
$writeError = ''

Write-Host ("Versuche JSON zu schreiben nach: {0}" -f $resolvedOutFile)

try {
    [System.IO.File]::WriteAllText($resolvedOutFile, $json, [System.Text.Encoding]::UTF8)
    $writeOk = Test-Path -LiteralPath $resolvedOutFile
} catch {
    $writeError = $_.Exception.Message
}

if (-not $writeOk) {
    try {
        $json | Set-Content -LiteralPath $resolvedOutFile -Encoding UTF8 -Force
        $writeOk = Test-Path -LiteralPath $resolvedOutFile
    } catch {
        if ($writeError) {
            $writeError = $writeError + ' | ' + $_.Exception.Message
        } else {
            $writeError = $_.Exception.Message
        }
    }
}

if ($writeOk) {
    Write-Host ""
    Write-Host ("JSON output: {0}" -f $resolvedOutFile)
    Write-Host ""
} else {
    $fallbackPath = Join-Path -Path $env:TEMP -ChildPath ('sap_service_probe_result_' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmss') + '.json')
    try {
        $json | Set-Content -LiteralPath $fallbackPath -Encoding UTF8 -Force
        Write-Warning ("Primary output failed. Fallback JSON output: " + $fallbackPath)
        if ($writeError) {
            Write-Warning ("Primary write error: " + $writeError)
        }
    } catch {
        Write-Error ("Konnte JSON-Datei weder primär noch per Fallback schreiben. Fehler: " + $_.Exception.Message)
        if ($writeError) {
            Write-Error ("Primary write error: " + $writeError)
        }
        throw
    }
}
