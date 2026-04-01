#Requires -Version 7.2
#Requires -Modules @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.0.0' }
#Requires -Modules @{ ModuleName = 'Microsoft.Graph.Groups';         ModuleVersion = '2.0.0' }

# ================================
# PURPOSE
# ================================
# Enumerate ALL security groups in the current Microsoft Entra ID tenant and
# output the groups that have serviceProvisioningErrors, using Microsoft Graph.
#
# ================================
# Microsoft Graph – Security Group serviceProvisioningErrors Scan
# Parallel + Adaptive Throttling + Per-Runspace Backoff + Progress/ETA + File Output
# v6.3 – security and correctness fixes:
#   - Move Start-Transcript inside try block so finally always closes it
#   - Replace non-atomic Throttles429++ with [Interlocked]::Increment (race-free counter)
#   - Fix null $statusCode producing misleading "Error_HTTP" reason; now "NetworkError"
#   - Remove redundant [datetime] cast on StartTimeUtc when writing $ScanStartLocal
#   - Add output-directory ACL guardrail (warns if directory is world-writable/group-writable)
#   - Add $CertificateThumbprint hex-format validation for ServicePrincipal mode
# v6.2 – enhancements applied:
#   - Capture errorDetail field in error records (key diagnostic data previously omitted)
#   - Write full per-error detail rows to output CSV (previously only summary counts)
#   - try/finally ensures Disconnect-MgGraph + Stop-Transcript on all exit paths
#   - Replace exit 0 with return so finally block runs on zero-groups early-out
#   - Remove individual Stop-Transcript calls before throw (superseded by finally)
#   - Remove redundant [datetime] cast on StartTime (already datetime)
# v6.1 – corrections applied:
#   - Fix invalid PowerShell syntax (no :Min/:Max/:Synchronized tokens)
#   - Remove manual CSV quote escaping (Export-Csv already escapes)
#   - Clarify prereqs: no install/update; #Requires may auto-import modules
# ================================

# ⚠️ AS-IS DISCLAIMER
# PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.
# NOT A SUPPORTED MICROSOFT PRODUCT. USE AT YOUR OWN RISK.
# EXECUTION OF HIGH-VOLUME MICROSOFT GRAPH QUERIES MAY RESULT IN THROTTLING (HTTP 429)
# OR TEMPORARY SERVICE IMPACT IF MISUSED.
# THE AUTHOR ASSUMES NO RESPONSIBILITY FOR DATA LOSS, SERVICE DISRUPTION,
# OR TENANT-WIDE THROTTLING CAUSED BY EXECUTION OF THIS SCRIPT.

# ================================================================
# CONFIGURATION — edit this section before running
# ================================================================

# Authentication mode: 'ServicePrincipal' | 'ManagedIdentity' | 'Interactive'
$AuthMode = 'Interactive'

# Mode A — Service Principal credentials (only used when $AuthMode = 'ServicePrincipal')
$AppId                 = ''   # Application (client) ID
$TenantId              = ''   # Directory (tenant) ID
$CertificateThumbprint = ''   # Thumbprint in Cert:\CurrentUser\My (or LocalMachine\My for services)

# Scan tuning
$MaxParallel       = 6
$InitialBackoffSec = 3
$MaxBackoffSec     = 60
$MaxRetries        = 5

# Required Graph delegated scopes (used only for Interactive auth mode)
$RequiredScopes = @(
    'Group.Read.All'
    'Directory.Read.All'
)

# Output directory — timestamped files are written here; created if absent.
# ⚠️ SECURITY: Output may contain sensitive group/error data. Restrict Access Control Lists (ACLs) on this directory.
$OutDir = 'C:\Temp'

# ================================================================
# PREFLIGHT: MODULE PRESENCE CHECK (no install/update performed)
# NOTE: #Requires -Modules may auto-import modules if available. 
# ================================================================

$requiredModules = @(
    @{ Name = 'Microsoft.Graph.Authentication'; MinVersion = [version]'2.0.0'
       Gallery  = 'https://www.powershellgallery.com/packages/Microsoft.Graph.Authentication'
       Install  = 'Install-Module Microsoft.Graph.Authentication -MinimumVersion 2.0.0 -Scope CurrentUser' }
    @{ Name = 'Microsoft.Graph.Groups';         MinVersion = [version]'2.0.0'
       Gallery  = 'https://www.powershellgallery.com/packages/Microsoft.Graph.Groups'
       Install  = 'Install-Module Microsoft.Graph.Groups -MinimumVersion 2.0.0 -Scope CurrentUser' }
)

$moduleErrors = [System.Collections.Generic.List[string]]::new()

foreach ($req in $requiredModules) {
    $found = Get-Module -ListAvailable -Name $req.Name |
             Sort-Object Version -Descending |
             Select-Object -First 1

    if (-not $found) {
        $moduleErrors.Add(
            "  MISSING  : $($req.Name) (minimum version $($req.MinVersion))`n" +
            "  Install  : $($req.Install)`n" +
            "  Gallery  : $($req.Gallery)"
        )
    }
    elseif ($found.Version -lt $req.MinVersion) {
        $moduleErrors.Add(
            "  OUTDATED : $($req.Name) — installed $($found.Version), need >= $($req.MinVersion)`n" +
            "  Update   : Update-Module $($req.Name)`n" +
            "  Gallery  : $($req.Gallery)"
        )
    }
}

if ($moduleErrors.Count -gt 0) {
    Write-Host ''
    Write-Host '============================================================' -ForegroundColor Red
    Write-Host '  ABORT: Required modules are missing or outdated.'           -ForegroundColor Red
    Write-Host '  This script will NOT install or update modules.'            -ForegroundColor Red
    Write-Host '  Resolve all items below, then re-run.'                      -ForegroundColor Red
    Write-Host '============================================================' -ForegroundColor Red
    foreach ($msg in $moduleErrors) {
        Write-Host ''
        Write-Host $msg -ForegroundColor Yellow
    }
    Write-Host ''
    Write-Host '  PowerShell download  : https://aka.ms/powershell'                                         -ForegroundColor Cyan
    Write-Host '  SDK release notes    : https://github.com/microsoftgraph/msgraph-sdk-powershell/releases' -ForegroundColor Cyan
    Write-Host ''
    exit 1
}

Write-Host "Module pre-flight passed (Microsoft.Graph.Authentication, Microsoft.Graph.Groups >= 2.0.0)." -ForegroundColor Green

# ================================================================
# OUTPUT DIRECTORY + TRANSCRIPT
# ================================================================

$null     = New-Item -ItemType Directory -Path $OutDir -Force
$RunStamp = Get-Date -Format 'yyyyMMdd_HHmmss'

$OutFile        = Join-Path $OutDir "sg_errors_$RunStamp.csv"
$SkippedFile    = Join-Path $OutDir "sg_errors_skipped_$RunStamp.csv"
$TranscriptFile = Join-Path $OutDir "sg_errors_transcript_$RunStamp.log"

try {

# ================================================================
# OUTPUT DIRECTORY ACL GUARDRAIL
# ================================================================
# Warn if the output directory grants write access to accounts other than
# the current user/SYSTEM (e.g. world-writable or group-writable).
# Output files may contain sensitive serviceProvisioningErrors data.
# ⚠️ SECURITY: Restrict ACLs on $OutDir before running in production.

if ($IsWindows -or (-not $IsLinux -and -not $IsMacOS)) {
    try {
        $acl = Get-Acl -Path $OutDir -ErrorAction Stop
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $sensitiveAccess = $acl.Access | Where-Object {
            ($_.FileSystemRights -band (
                [System.Security.AccessControl.FileSystemRights]::Write -bor
                [System.Security.AccessControl.FileSystemRights]::Modify -bor
                [System.Security.AccessControl.FileSystemRights]::FullControl
            )) -and
            $_.AccessControlType -eq 'Allow' -and
            $_.IdentityReference.Value -notin @(
                $currentUser,
                'NT AUTHORITY\SYSTEM',
                'BUILTIN\Administrators'
            )
        }
        if ($sensitiveAccess) {
            $identities = $sensitiveAccess.IdentityReference.Value -join ', '
            Write-Warning "OUTPUT DIRECTORY ACL WARNING: '$OutDir' grants write access to: $identities. Output files may contain sensitive data. Restrict ACLs before running in production."
        }
    }
    catch {
        Write-Warning "Could not check ACLs on '$OutDir': $_"
    }
}

# ================================================================
# TRANSCRIPT
# ================================================================

Start-Transcript -Path $TranscriptFile -Append
Write-Host "Transcript : $TranscriptFile" -ForegroundColor DarkGray

# ================================================================
# CONNECT TO GRAPH
# ================================================================

Write-Host "Connecting to Microsoft Graph (mode: $AuthMode)..." -ForegroundColor Cyan

switch ($AuthMode) {
    'ServicePrincipal' {
        if (-not $AppId -or -not $TenantId -or -not $CertificateThumbprint) {
            throw "AuthMode is 'ServicePrincipal' but one or more credentials are empty. Populate `$AppId, `$TenantId, and `$CertificateThumbprint."
        }
        # Validate thumbprint format: must be exactly 40 hex characters.
        if ($CertificateThumbprint -notmatch '^[0-9A-Fa-f]{40}$') {
            throw "CertificateThumbprint '$CertificateThumbprint' is not a valid certificate thumbprint (expected 40 hex characters)."
        }
        Connect-MgGraph -ClientId $AppId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ContextScope Process
    }
    'ManagedIdentity' {
        Connect-MgGraph -Identity -NoWelcome -ContextScope Process
    }
    'Interactive' {
        Write-Warning "AuthMode is 'Interactive'. NOT suitable for production or unattended runs."
        Connect-MgGraph -Scopes $RequiredScopes -NoWelcome -ContextScope Process
    }
    default {
        throw "Unknown AuthMode '$AuthMode'. Valid values: ServicePrincipal | ManagedIdentity | Interactive"
    }
}

Write-Host "Connected to Microsoft Graph." -ForegroundColor Green

# ================================================================
# PREFLIGHT: PERMISSION CHECK
# ================================================================

$ctx = Get-MgContext

if ($ctx.AuthType -eq 'AppOnly') {
    Write-Host "AppOnly auth — probing Graph permissions..." -ForegroundColor Cyan
    try {
        $null = Get-MgGroup -Top 1 -Property id -ErrorAction Stop
        Write-Host "Permission probe passed." -ForegroundColor Green
    }
    catch {
        throw "Pre-flight permission probe failed. Verify the app has Group.Read.All and Directory.Read.All APPLICATION permissions with admin consent. Error: $_"
    }
}
else {
    $missingScopes = $RequiredScopes | Where-Object { $_ -notin $ctx.Scopes }
    if ($missingScopes) {
        throw "Missing required delegated scopes: $($missingScopes -join ', '). Re-run Connect-MgGraph with the correct -Scopes."
    }
    Write-Host "Delegated scopes confirmed: $($RequiredScopes -join ', ')" -ForegroundColor Green
}

# ================================================================
# STEP 1: LOAD ALL SECURITY GROUPS
# ================================================================

Write-Host "Loading Security Groups into memory..." -ForegroundColor Cyan

$SecurityGroups =
    Get-MgGroup -All `
        -Filter "securityEnabled eq true" `
        -Property "id,displayName,groupTypes" |
    Where-Object { $_.GroupTypes -notcontains 'Unified' } |
    Select-Object Id, DisplayName

$TotalGroups = $SecurityGroups.Count
Write-Host "Loaded $TotalGroups security groups." -ForegroundColor Green

if ($TotalGroups -eq 0) {
    Write-Warning "No security groups found. Verify your filter, permissions, and tenant."
    return
}

# ================================================================
# STEP 2: PARALLEL SCAN
# ================================================================

$Shared = [hashtable]::Synchronized(@{
    Throttles429 = [ref]0
    StartTimeUtc = (Get-Date).ToUniversalTime()
})

$Results  = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
$Skipped  = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
$ProcessedMarkers = [System.Collections.Concurrent.ConcurrentBag[int]]::new()

Write-Host "Scanning groups for serviceProvisioningErrors (parallel, throttle-safe)..." -ForegroundColor Cyan

$job = $SecurityGroups | ForEach-Object -Parallel {

    $Group   = $_
    $Backoff = $using:InitialBackoffSec
    $Uri     = "https://graph.microsoft.com/v1.0/groups/$($Group.Id)?`$select=serviceProvisioningErrors"
    $Aborted = $false

    do {
        $Retry    = 0
        $PageDone = $false

        while (-not $PageDone -and $Retry -le $using:MaxRetries) {
            try {
                # Invoke-MgGraphRequest issues raw REST calls to Graph. [2](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.authentication/invoke-mggraphrequest?view=graph-powershell-1.0)
                $resp   = Invoke-MgGraphRequest -Method GET -Uri $Uri
                $errors = $resp['serviceProvisioningErrors']

                if ($errors -and $errors.Count -gt 0) {
                    foreach ($err in $errors) {
                        ($using:Results).Add([pscustomobject]@{
                            GroupId         = $Group.Id
                            GroupName       = $Group.DisplayName
                            ServiceInstance = $err['serviceInstance']
                            CreatedDateTime = $err['createdDateTime']
                            IsResolved      = $err['isResolved']
                            ErrorDetail     = $err['errorDetail']
                        })
                    }
                }

                $Uri      = $resp['@odata.nextLink']
                $PageDone = $true
            }
            catch {
                $statusCode = $null
                try { $statusCode = $_.Exception.Response.StatusCode.Value__ } catch { }

                if ($statusCode -eq 429 -and $Retry -lt $using:MaxRetries) {
                    # Throttling: honor Retry-After when present; otherwise backoff. [1](https://learn.microsoft.com/en-us/graph/throttling)
                    # Interlocked.Increment ensures atomic counter update across runspaces.
                    [System.Threading.Interlocked]::Increment(($using:Shared).Throttles429)

                    $retryAfter = $null
                    try { $retryAfter = [int]$_.Exception.Response.Headers["Retry-After"] } catch { }

                    $waitSec  = if ($retryAfter) { $retryAfter } else { $Backoff }
                    $waitSec += Get-Random -Minimum 1 -Maximum 4

                    Start-Sleep -Seconds $waitSec

                    $Backoff = [Math]::Min(($Backoff * 2), $using:MaxBackoffSec)
                    $Retry++
                }
                else {
                    $reason = switch ($statusCode) {
                        401     { 'AuthExpired_401' }
                        403     { 'Forbidden_403' }
                        429     { 'RetryBudgetExhausted_429' }
                        $null   { 'NetworkError' }
                        default { "Error_HTTP$statusCode" }
                    }

                    ($using:Skipped).Add([pscustomobject]@{
                        GroupId   = $Group.Id
                        GroupName = $Group.DisplayName
                        Reason    = $reason
                        Detail    = $_.ToString()
                    })

                    $Aborted  = $true
                    $PageDone = $true
                    $Uri      = $null
                }
            }
        }

    } while ($Uri -and -not $Aborted)

    # Mark one group processed (thread-safe)
    ($using:ProcessedMarkers).Add(1)

} -ThrottleLimit $MaxParallel -AsJob

# ================================================================
# PROGRESS BAR + ETA
# ================================================================

$StartTime = $Shared.StartTimeUtc

while ($job.State -eq 'Running') {

    $processed = [Math]::Max(0, [Math]::Min([int]$ProcessedMarkers.Count, $TotalGroups))
    $elapsed   = [Math]::Max(1, ((Get-Date).ToUniversalTime() - $StartTime).TotalSeconds)
    $rate      = $processed / $elapsed
    $remaining = $TotalGroups - $processed

    $etaSeconds = if ($rate -gt 0) { [int][Math]::Ceiling($remaining / $rate) } else { -1 }
    $percent    = [Math]::Max(0, [Math]::Min(100, [int][Math]::Floor(($processed / $TotalGroups) * 100)))

    Write-Progress -Activity "Scanning Security Groups for serviceProvisioningErrors" `
                   -Status   "Processed $processed / $TotalGroups | 429s: $($Shared.Throttles429.Value) | Skipped: $($Skipped.Count)" `
                   -PercentComplete  $percent `
                   -SecondsRemaining $etaSeconds

    Start-Sleep -Milliseconds 750
}

Receive-Job -Job $job -Wait | Out-Null
Remove-Job  -Job $job -Force

Write-Progress -Activity "Scanning Security Groups for serviceProvisioningErrors" -Completed

$finalProcessed = [int]$ProcessedMarkers.Count
Write-Host "Scan complete. Scanned $finalProcessed of $TotalGroups groups." -ForegroundColor Green
Write-Host "Error records found : $($Results.Count)" -ForegroundColor Yellow
Write-Host "Groups skipped      : $($Skipped.Count)" -ForegroundColor $(if ($Skipped.Count -gt 0) { 'Red' } else { 'Green' })

# ================================================================
# WRITE OUTPUT FILES
# ================================================================

$ScanStartLocal = $Shared.StartTimeUtc.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')

# Derive distinct-group count for the CSV header; full detail rows go into the file.
$groupsWithErrors = ($Results | Select-Object -ExpandProperty GroupId -Unique | Measure-Object).Count

@(
    "# Security Groups with serviceProvisioningErrors — full error detail"
    "# ScanStarted:        $ScanStartLocal"
    "# TotalGroupsScanned: $finalProcessed"
    "# GroupsWithErrors:   $groupsWithErrors"
    "# GroupsSkipped:      $($Skipped.Count)"
    "# Transcript:         $TranscriptFile"
    "# Columns: GroupId, GroupName, ServiceInstance, CreatedDateTime, IsResolved, ErrorDetail"
    "#"
) | Set-Content -Path $OutFile -Encoding UTF8

$Results |
    Sort-Object GroupName, CreatedDateTime |
    Export-Csv -Path $OutFile -Encoding UTF8 -NoTypeInformation -Append

Write-Host "Results    : $OutFile" -ForegroundColor Green

if ($Skipped.Count -gt 0) {
    @(
        "# Groups skipped during scan"
        "# ScanStarted:  $ScanStartLocal"
        "# Reason codes: AuthExpired_401 | Forbidden_403 | RetryBudgetExhausted_429 | NetworkError | Error_HTTPNNN"
        "#"
    ) | Set-Content -Path $SkippedFile -Encoding UTF8

    $Skipped |
        Sort-Object GroupName |
        Export-Csv -Path $SkippedFile -Encoding UTF8 -NoTypeInformation -Append

    Write-Warning "$($Skipped.Count) group(s) skipped. See: $SkippedFile"

    if ($Skipped | Where-Object { $_.Reason -eq 'AuthExpired_401' }) {
        Write-Warning "One or more groups failed with AuthExpired_401. Re-authenticate and re-run targeting the skipped groups CSV to recover."
    }
}
else {
    Write-Host "No groups skipped." -ForegroundColor Green
}

Write-Host "Transcript : $TranscriptFile" -ForegroundColor DarkGray

# Return full error records to pipeline — caller can pipe to Export-Csv / ConvertTo-Json
$Results

}
finally {
    # Always disconnect from Microsoft Graph and stop the transcript, regardless of how the script exits.
    try { Disconnect-MgGraph | Out-Null } catch { }
    Stop-Transcript
}