###############################################################################
# Find-DuplicateDefenderDevices.ps1
#
# Scan Microsoft Defender for Endpoint for devices with duplicate
# registrations. Identifies stale/orphaned device records caused by
# hostname changes, reimaging, or offboard/re-onboard cycles and
# provides tagging recommendations.
#
# Supports: macOS, Windows, iOS, Android, Linux (or all platforms)
#
# APPROACH:
#   Uses HardwareUuid from Advanced Hunting as the stable hardware identifier
#   to group device records by physical device. MDE creates new device records
#   when hostnames change — this script finds duplicates that MDE's built-in
#   dedup may have missed, and helps admins tag stale entries for cleanup.
#
# Author:  Oktay Sari (allthingscloud.blog)
# Date:    2026-02-14
# Version: 2.4
#
# REQUIREMENTS:
#   - PowerShell 7+
#   - Azure App Registration with WindowsDefenderATP permissions:
#     - Machine.Read.All (read device records)
#     - AdvancedQuery.Read.All (Advanced Hunting for HardwareUuid + logon activity)
#     - Machine.ReadWrite.All (optional, for tagging stale devices)
#   - Microsoft Graph permissions (for Intune cross-reference, enabled by default):
#     - DeviceManagementManagedDevices.Read.All (read Intune managed devices)
#     - If not available, Intune data is skipped automatically
#
# USAGE:
#   .\Find-DuplicateDefenderDevices.ps1 -TenantId "<id>" -AppId "<id>" -AppSecret "<secret>"
#   .\Find-DuplicateDefenderDevices.ps1 -TenantId "<id>" -AppId "<id>" -CertificateThumbprint "<thumbprint>"
#   .\Find-DuplicateDefenderDevices.ps1 -TenantId "<id>" -AppId "<id>" -CertificatePath "cert.pfx"
#   .\Find-DuplicateDefenderDevices.ps1 -TenantId "<id>" -AppId "<id>" -AppSecret "<secret>" -Platform Windows
#   .\Find-DuplicateDefenderDevices.ps1 -TenantId "<id>" -AppId "<id>" -AppSecret "<secret>" -Platform All
#   .\Find-DuplicateDefenderDevices.ps1 -TenantId "<id>" -AppId "<id>" -AppSecret "<secret>" -StaleThresholdDays 60
#   .\Find-DuplicateDefenderDevices.ps1 -TenantId "<id>" -AppId "<id>" -AppSecret "<secret>" -TagStaleDevices
#   .\Find-DuplicateDefenderDevices.ps1 -TenantId "<id>" -AppId "<id>" -AppSecret "<secret>" -SkipIntune
#
# CODE QUALITY:
#   This script passes PSScriptAnalyzer static analysis.
#   Run: Invoke-ScriptAnalyzer -Path Find-DuplicateDefenderDevices.ps1
#
#   Intentional suppressions:
#   - PSAvoidUsingWriteHost: Interactive script requires colored console output
#   - PSAvoidUsingPlainTextForPassword: OAuth client credentials requires plain text
#   - PSReviewUnusedParameter: Script-level params accessed via implicit scoping
#
# KNOWN LIMITATIONS (LARGE TENANTS):
#   - Advanced Hunting returns a maximum of 10,000 rows per query (API hard limit).
#     In tenants with more than 10,000 devices, the excess devices will have no
#     HardwareUuid data and cannot be grouped by physical hardware. Duplicate
#     detection for those devices falls back to staleness-only analysis.
#     There is no pagination support for Advanced Hunting queries.
#   - Rate limit retries are capped at 3 attempts (60s + 120s + 180s = 6 min max).
#     In very large tenants that hit HTTP 429 repeatedly during a paginated scan,
#     a 4th consecutive throttle failure will abort the scan. Increase
#     -ThrottleDelayMs (e.g. 500-1000) to reduce the likelihood of hitting this.
#   - Intune pagination uses 1,000 records per page (conservative default).
#     In large tenants this increases the number of Graph API calls. Use
#     -SkipIntune if Intune cross-referencing is not needed and speed matters.
#   - When using -Platform All, the combined device count across all platforms
#     can be very large. Consider using -ThrottleDelayMs 500 or higher and
#     running the scan during off-peak hours to avoid rate limiting.
#
# DISCLAIMER:
#   This script is provided "AS IS", without warranty of any kind, express or
#   implied. The author and contributors are not liable for any damage, data
#   loss, or unintended changes resulting from its use. Scanning is read-only
#   by default; the -TagStaleDevices switch adds tags but does NOT delete or
#   offboard devices (macOS/mobile offboarding is not supported via the MDE API).
#   Review every flagged record before taking manual action in the portal.
#   The -GenerateExclusionScript option produces a helper script that calls
#   undocumented Defender XDR portal APIs via the XDRInternals module. These
#   internal APIs may change without notice. Use at your own discretion.
#   ALWAYS TEST in a controlled environment before deploying to production.
#   You are solely responsible for any actions taken using this script.
#   USE AT YOUR OWN RISK.
#
###############################################################################

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'Interactive script requires colored console output')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '',
    Justification = 'OAuth client credentials flow requires plain text for token endpoint; certificate password protects local file only')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
    Justification = 'Script-level params accessed via implicit scoping in nested functions')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
    Justification = 'Get-MdeDevices returns a collection; plural noun is intentional')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseBOMForUnicodeEncodedFile', '',
    Justification = 'File is pure ASCII; BOM not required')]
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Platform to scan (macOS, Windows, iOS, Android, Linux, or All)")]
    [ValidateSet("macOS", "Windows", "iOS", "Android", "Linux", "All")]
    [string]$Platform = "macOS",

    [Parameter(Mandatory = $false, HelpMessage = "Azure AD tenant ID")]
    [string]$TenantId,

    [Parameter(Mandatory = $false, HelpMessage = "App registration application (client) ID")]
    [string]$AppId,

    [Parameter(Mandatory = $false, HelpMessage = "App registration client secret (use this OR certificate auth)")]
    [string]$AppSecret,

    [Parameter(Mandatory = $false, HelpMessage = "Certificate thumbprint (loads from local certificate store)")]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory = $false, HelpMessage = "Path to .pfx certificate file")]
    [string]$CertificatePath,

    [Parameter(Mandatory = $false, HelpMessage = "Password for .pfx certificate file (omit if no password)")]
    [string]$CertificatePassword,

    [Parameter(Mandatory = $false, HelpMessage = "Days since last seen to consider a record stale")]
    [int]$StaleThresholdDays = 30,

    [Parameter(Mandatory = $false, HelpMessage = "Output directory for CSV results (auto-detected if not specified)")]
    [string]$OutputPath,

    [Parameter(Mandatory = $false, HelpMessage = "Tag stale/orphan devices in MDE portal")]
    [switch]$TagStaleDevices,

    [Parameter(Mandatory = $false, HelpMessage = "Tag text to apply to stale devices")]
    [string]$TagValue = "StaleOrphan",

    [Parameter(Mandatory = $false, HelpMessage = "Minimum orphan score to tag a device (default 5 = TAG only, lower to include REVIEW devices)")]
    [ValidateRange(1, 15)]
    [int]$TagThreshold = 5,

    [Parameter(Mandatory = $false, HelpMessage = "Delay in milliseconds between API requests")]
    [ValidateRange(0, 5000)]
    [int]$ThrottleDelayMs = 100,

    [Parameter(Mandatory = $false, HelpMessage = "Maximum items shown per console section (full data always in CSV)")]
    [ValidateRange(1, 1000)]
    [int]$MaxDisplayItems = 25,

    [Parameter(Mandatory = $false, HelpMessage = "Skip Intune cross-reference (enabled by default when Graph permissions are available)")]
    [switch]$SkipIntune,

    [Parameter(Mandatory = $false, HelpMessage = "Generate a helper script to exclude TAG/REVIEW devices from MDVM")]
    [switch]$GenerateExclusionScript
)

#region --- Platform Detection & Output Path ---
function Get-PlatformInfo {
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        if ($IsMacOS) {
            return @{ Platform = "macOS"; Desktop = "$HOME/Desktop" }
        }
        elseif ($IsLinux) {
            return @{ Platform = "Linux"; Desktop = "$HOME/Desktop" }
        }
    }
    return @{
        Platform = "Windows"
        Desktop  = [Environment]::GetFolderPath('Desktop')
    }
}

$platformInfo = Get-PlatformInfo
if ([string]::IsNullOrEmpty($OutputPath)) {
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $OutputPath = Join-Path $platformInfo.Desktop "MDE_DuplicateReport_${Platform}_$timestamp"
}

# Map MDE osPlatform API values to friendly platform names for tagging
$script:OsPlatformTagMap = @{
    "macOS"     = "macOS"
    "MacOsX"    = "macOS"
    "Windows10" = "Windows"
    "Windows11" = "Windows"
    "iOS"       = "iOS"
    "iPadOS"    = "iOS"
    "Android"   = "Android"
    "Linux"     = "Linux"
}
#endregion

#region --- Configuration ---
$ErrorActionPreference = "Continue"

# Platform-to-API value mapping
# MDE REST, KQL Advanced Hunting, and Intune each use different OS identifiers
$script:PlatformMap = @{
    macOS   = @{ Rest = @("macOS", "MacOsX"); Kql = @("macOS", "MacOsX"); Intune = @("macOS") }
    Windows = @{ Rest = @("Windows10"); Kql = @("Windows10", "Windows11"); Intune = @("Windows") }
    iOS     = @{ Rest = @("iOS"); Kql = @("iOS", "iPadOS"); Intune = @("iOS", "iPadOS") }
    Android = @{ Rest = @("Android"); Kql = @("Android"); Intune = @("Android") }
    Linux   = @{ Rest = @("Linux"); Kql = @("Linux"); Intune = @("Linux") }
}

# Compute filter values for the selected platform
if ($Platform -eq "All") {
    $script:RestPlatformValues = $null
    $script:KqlPlatformValues = $null
    $script:IntunePlatformValues = $null
}
else {
    $script:RestPlatformValues = $script:PlatformMap[$Platform].Rest
    $script:KqlPlatformValues = $script:PlatformMap[$Platform].Kql
    $script:IntunePlatformValues = $script:PlatformMap[$Platform].Intune
}

$script:Stats = @{
    TotalMdeDevices         = 0
    AdvancedHuntingDevices  = 0
    UniqueHardwareUuids     = 0
    DevicesWithDuplicates   = 0
    OrphanRecords           = 0
    StaleRecords            = 0
    RecommendedForTagging   = 0
    UnresolvedDevices       = 0
    DevicesTagged           = 0
    TaggingFailed           = 0
    IntuneDevicesTotal      = 0
    IntuneDevicesMatched    = 0
}

# Auth state — MDE
$script:AccessToken = $null
$script:TokenExpiry = [DateTime]::MinValue

# Auth state — Microsoft Graph (Intune)
$script:GraphAccessToken = $null
$script:GraphTokenExpiry = [DateTime]::MinValue

# Certificate auth state
$script:Certificate = $null
$script:AuthMethod = "Secret"

# Results for Ctrl+C handling
$script:allResults = @()
$script:unresolvedResults = @()
$script:scanCompleted = $false
$script:advancedHuntingAvailable = $true
$script:logonActivityAvailable = $false
$script:intuneAvailable = $false
#endregion

#region --- Helper Functions ---
function Write-Step {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] " -ForegroundColor Blue -NoNewline
    Write-Host "[OK] " -ForegroundColor Green -NoNewline
    Write-Host $Message
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] " -ForegroundColor Blue -NoNewline
    Write-Host "[!!] " -ForegroundColor Yellow -NoNewline
    Write-Host $Message -ForegroundColor Yellow
}

function Write-Info {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] " -ForegroundColor Blue -NoNewline
    Write-Host ">> " -ForegroundColor Cyan -NoNewline
    Write-Host $Message
}

function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Green
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
}

function Show-DutchCowboyBanner {
    param(
        [Parameter(Mandatory = $false)]
        [string]$Subtitle
    )

    $delay = 40  # milliseconds per line

    $art = @(
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$XXX$$$$$$$$$$$$$X++X$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$;::::;x$$$$$$$X+::::::X$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$;::::::::::::.........::x$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$X:::::::::................:+$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$X:::..:.::...................;$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$+:.:::::.:.....................:X$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$x::.::..:::......................::;$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$;:....:............................:::x$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$X::..:..::....:......................::::;$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$X:::........:..........................::::+$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$+::.....................................:::;$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$+:............................... .......:::$$$$$$$$$$$$$$$$$$$$+:::;X$$'
        '$$$$x:::::X$$$$$$$$$$$$$$$$$;...............................   ......:::X$$$$$$$$$$$$$$$$x::::::x$$$'
        '$$$$X:::::::;X$$$$$$$$$$$$$$::................................ .......:::$$$$$$$$$$$$$$+:::::::+$$$$'
        '$$$$$+:::::::::X$$$$$$$$$$$$:..............................  . ........::X$$$$$$$$$$$+::::::::+$$$$$'
        '$$$$$$;::::::::::+$$$$$$$$$x:...............................  . ........:x$$$$$$$$$x:::::::::+$$$$$$'
        '$$$$$$X;:::::::::::x$$$$$$$;:.......................... .       .........:;$$$$$$X::::::::::x$$$$$$$'
        '$$$$$$$$+::::::::::::X$$$$+...........................  .  ... ....  ..  .;xX$$X::::::::::+X$$$$$$$$'
        '$$$$$$$$$$x;:::::::::::Xx;::......    .             .  ............:::::::::::.:::::::;x$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$x::::::::::::::::....:..............::..::..::.:...::..:.::.....:::::x$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$x::::::::::::::....:...:....:::..:.:.........:..:.........::::x$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$X;:::::..:::..::.:::::::::..::........................::x$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$X+:::::::::::::.::.:.:::..:::..::................:+XX$$X$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$XXXXX+::::::::::.::.::.::::.:::....:.......:...:+XXXXXXXXXX$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$XXXXXXXXXXXXXXXXXx;::::::::::::::.::..:.::::::::::::;+XXXXXXXXXXXXXXXXXX$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$XXXXXXXXXXxxxxxxxxxxx+++++++++++++xxxxxxxxxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXX$$$$$$$$$$$'
        '$$$$$$$$$$$$XXXXXxxx++++++++++++;;;;;;;;;;;;;;;+++++++++++++++++++++++xxxxxxxxXXXXXXXXXXXXX$$$$$$$$$'
    )

    Write-Host ""
    Write-Host ("=" * 100) -ForegroundColor Cyan
    Start-Sleep -Milliseconds $delay

    foreach ($artLine in $art) {
        Write-Host $artLine -ForegroundColor Cyan
        Start-Sleep -Milliseconds $delay
    }

    Write-Host ""

    # Blink #DutchCowboy text 4 times
    $brandText = '                                          #DutchCowboy'
    $cursorUp = "`e[1A`e[2K"

    for ($blink = 0; $blink -lt 4; $blink++) {
        Write-Host $brandText -ForegroundColor Green
        if ($Subtitle) {
            Write-Host "                                    $Subtitle" -ForegroundColor Green
        }
        Start-Sleep -Milliseconds 300
        if ($Subtitle) {
            Write-Host "$cursorUp$cursorUp" -NoNewline
        }
        else {
            Write-Host $cursorUp -NoNewline
        }
        Start-Sleep -Milliseconds 200
    }

    # Final print (stays visible)
    Write-Host $brandText -ForegroundColor Green
    if ($Subtitle) {
        Write-Host "                                    $Subtitle" -ForegroundColor Green
    }

    Write-Host ("=" * 100) -ForegroundColor Cyan
    Write-Host ""
}
#endregion

#region --- Token Management ---
function Build-ClientAssertion {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    # Base64Url encode helper
    $toBase64Url = {
        param([byte[]]$Bytes)
        [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    }

    # Certificate thumbprint as base64url for x5t header
    $thumbprintBytes = [byte[]]::new($Certificate.Thumbprint.Length / 2)
    for ($i = 0; $i -lt $thumbprintBytes.Length; $i++) {
        $thumbprintBytes[$i] = [Convert]::ToByte($Certificate.Thumbprint.Substring($i * 2, 2), 16)
    }
    $x5t = & $toBase64Url $thumbprintBytes

    # JWT Header
    $header = @{ alg = "RS256"; typ = "JWT"; x5t = $x5t } | ConvertTo-Json -Compress

    # JWT Payload
    $now = [DateTimeOffset]::UtcNow
    $payload = @{
        aud = $tokenEndpoint
        iss = $AppId
        sub = $AppId
        jti = [Guid]::NewGuid().ToString()
        nbf = $now.ToUnixTimeSeconds()
        exp = $now.AddMinutes(10).ToUnixTimeSeconds()
    } | ConvertTo-Json -Compress

    # Sign with RSA-SHA256
    $headerB64 = & $toBase64Url ([System.Text.Encoding]::UTF8.GetBytes($header))
    $payloadB64 = & $toBase64Url ([System.Text.Encoding]::UTF8.GetBytes($payload))
    $dataToSign = [System.Text.Encoding]::UTF8.GetBytes("$headerB64.$payloadB64")

    $rsa = $Certificate.GetRSAPrivateKey()
    $signature = $rsa.SignData(
        $dataToSign,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $signatureB64 = & $toBase64Url $signature

    return "$headerB64.$payloadB64.$signatureB64"
}

function Get-TokenRequestBody {
    param([string]$Scope)

    if ($script:AuthMethod -eq "Certificate") {
        $assertion = Build-ClientAssertion -Certificate $script:Certificate
        return @{
            client_id             = $AppId
            client_assertion      = $assertion
            client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            scope                 = $Scope
            grant_type            = "client_credentials"
        }
    }
    else {
        return @{
            client_id     = $AppId
            client_secret = $AppSecret
            scope         = $Scope
            grant_type    = "client_credentials"
        }
    }
}

function Get-MdeAccessToken {
    $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $body = Get-TokenRequestBody -Scope "https://api.securitycenter.microsoft.com/.default"

    try {
        $tokenResponse = Invoke-RestMethod -Method Post -Uri $tokenEndpoint `
            -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop

        $script:AccessToken = $tokenResponse.access_token
        $script:TokenExpiry = (Get-Date).AddSeconds($tokenResponse.expires_in)
        Write-Step "Authenticated to MDE API via $($script:AuthMethod) (token valid for $($tokenResponse.expires_in)s)"
    }
    catch {
        Write-Host ""
        Write-Host "[FAIL] Authentication failed." -ForegroundColor Red
        Write-Host ""
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Verify:" -ForegroundColor Yellow
        Write-Host "    1. TenantId and AppId are correct" -ForegroundColor White
        if ($script:AuthMethod -eq "Certificate") {
            Write-Host "    2. Certificate is uploaded to the app registration in Azure" -ForegroundColor White
            Write-Host "    3. Certificate has a valid private key" -ForegroundColor White
        }
        else {
            Write-Host "    2. AppSecret is correct and not expired" -ForegroundColor White
        }
        Write-Host "    3. App registration has WindowsDefenderATP API permissions" -ForegroundColor White
        Write-Host "    4. Admin consent has been granted" -ForegroundColor White
        Write-Host ""
        exit 1
    }
}

function Confirm-TokenValidity {
    if ($null -eq $script:AccessToken -or (Get-Date) -ge $script:TokenExpiry.AddMinutes(-5)) {
        Write-Info "Refreshing access token..."
        Get-MdeAccessToken
    }
}

function Get-GraphAccessToken {
    $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $body = Get-TokenRequestBody -Scope "https://graph.microsoft.com/.default"

    try {
        $tokenResponse = Invoke-RestMethod -Method Post -Uri $tokenEndpoint `
            -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop

        $script:GraphAccessToken = $tokenResponse.access_token
        $script:GraphTokenExpiry = (Get-Date).AddSeconds($tokenResponse.expires_in)
        Write-Step "Authenticated to Microsoft Graph (token valid for $($tokenResponse.expires_in)s)"
    }
    catch {
        Write-Warn "Graph authentication failed: $($_.Exception.Message)"
        Write-Warn "Intune cross-reference will be skipped."
        Write-Warn "Ensure the app registration has Microsoft Graph > DeviceManagementManagedDevices.Read.All"
        throw
    }
}

function Confirm-GraphTokenValidity {
    if ($null -eq $script:GraphAccessToken -or (Get-Date) -ge $script:GraphTokenExpiry.AddMinutes(-5)) {
        Write-Info "Refreshing Graph access token..."
        Get-GraphAccessToken
    }
}
#endregion

#region --- API Request Wrapper ---
function Invoke-MdeApiRequest {
    param(
        [string]$Uri,
        [string]$Method = "Get",
        [object]$Body = $null
    )

    Confirm-TokenValidity

    $headers = @{
        Authorization  = "Bearer $($script:AccessToken)"
        'Content-Type' = 'application/json'
    }

    $retryDelays = @(60, 120, 180)
    $attempt = 0

    while ($true) {
        try {
            $params = @{
                Uri         = $Uri
                Method      = $Method
                Headers     = $headers
                ErrorAction = 'Stop'
            }

            if ($null -ne $Body) {
                $params.Body = ($Body | ConvertTo-Json -Depth 10)
            }

            $response = Invoke-RestMethod @params

            if ($ThrottleDelayMs -gt 0) {
                Start-Sleep -Milliseconds $ThrottleDelayMs
            }

            return $response
        }
        catch {
            $statusCode = $null
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            if ($statusCode -in @(429, 503, 504) -and $attempt -lt $retryDelays.Count) {
                $delay = $retryDelays[$attempt]

                # Check for Retry-After header
                $retryAfter = $_.Exception.Response.Headers |
                    Where-Object { $_.Key -eq 'Retry-After' } |
                    Select-Object -ExpandProperty Value -First 1
                if ($retryAfter) {
                    $delay = [Math]::Max($delay, [int]$retryAfter)
                }

                Write-Warn "HTTP $statusCode - retrying in ${delay}s (attempt $($attempt + 1)/$($retryDelays.Count))..."
                Start-Sleep -Seconds $delay
                Confirm-TokenValidity
                $headers.Authorization = "Bearer $($script:AccessToken)"
                $attempt++
            }
            else {
                throw
            }
        }
    }
}
#endregion

#region --- Graph API Request Wrapper ---
function Invoke-GraphApiRequest {
    param(
        [string]$Uri,
        [string]$Method = "Get"
    )

    Confirm-GraphTokenValidity

    $headers = @{
        Authorization  = "Bearer $($script:GraphAccessToken)"
        'Content-Type' = 'application/json'
    }

    $retryDelays = @(60, 120, 180)
    $attempt = 0

    while ($true) {
        try {
            $response = Invoke-RestMethod -Uri $Uri -Method $Method -Headers $headers -ErrorAction Stop

            if ($ThrottleDelayMs -gt 0) {
                Start-Sleep -Milliseconds $ThrottleDelayMs
            }

            return $response
        }
        catch {
            $statusCode = $null
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            if ($statusCode -in @(429, 503, 504) -and $attempt -lt $retryDelays.Count) {
                $delay = $retryDelays[$attempt]

                $retryAfter = $_.Exception.Response.Headers |
                    Where-Object { $_.Key -eq 'Retry-After' } |
                    Select-Object -ExpandProperty Value -First 1
                if ($retryAfter) {
                    $delay = [Math]::Max($delay, [int]$retryAfter)
                }

                Write-Warn "Graph HTTP $statusCode - retrying in ${delay}s (attempt $($attempt + 1)/$($retryDelays.Count))..."
                Start-Sleep -Seconds $delay
                Confirm-GraphTokenValidity
                $headers.Authorization = "Bearer $($script:GraphAccessToken)"
                $attempt++
            }
            else {
                throw
            }
        }
    }
}
#endregion

#region --- Data Collection ---
function Get-MdeDevices {
    Write-Info "Collecting $Platform devices from MDE REST API..."

    $baseUrl = "https://api.security.microsoft.com/api/machines"

    if ($null -ne $script:RestPlatformValues) {
        $filterParts = $script:RestPlatformValues | ForEach-Object { "osPlatform eq '$_'" }
        $filter = $filterParts -join " or "
        $encodedFilter = [System.Uri]::EscapeDataString($filter)
        $uri = "${baseUrl}?`$filter=${encodedFilter}&`$top=10000"
    }
    else {
        $uri = "${baseUrl}?`$top=10000"
    }

    $allDevices = [System.Collections.ArrayList]::new()
    $pageCount = 0

    while ($null -ne $uri) {
        $response = Invoke-MdeApiRequest -Uri $uri
        $pageCount++

        if ($null -ne $response.value) {
            foreach ($device in $response.value) {
                [void]$allDevices.Add($device)
            }
            Write-Info "  Page $pageCount : $($response.value.Count) devices (total: $($allDevices.Count))"
        }

        # Follow pagination
        $uri = $response.'@odata.nextLink'
    }

    Write-Step "Collected $($allDevices.Count) $Platform devices from REST API"
    return $allDevices
}

function Invoke-AdvancedHuntingQuery {
    Write-Info "Running Advanced Hunting query for HardwareUuid..."

    # HardwareUuid may be a direct column or inside AdditionalFields depending on
    # tenant configuration. Try both with coalesce. SerialNumber is often empty for
    # macOS but grab it when available — it's the best stable identifier.
    $kqlPlatformFilter = if ($null -ne $script:KqlPlatformValues) {
        $quoted = $script:KqlPlatformValues | ForEach-Object { "`"$_`"" }
        "| where OSPlatform in ($($quoted -join ', '))"
    } else { "" }

    $kqlQuery = @"
DeviceInfo
$kqlPlatformFilter
| summarize arg_max(Timestamp, *) by DeviceId
| extend ParsedFields = parse_json(AdditionalFields)
| extend ResolvedHardwareUuid = coalesce(
    tostring(column_ifexists("HardwareUuid", "")),
    tostring(ParsedFields.HardwareUuid))
| extend ResolvedModel = coalesce(
    tostring(column_ifexists("Model", "")),
    tostring(ParsedFields.Model))
| extend SerialNumber = tostring(ParsedFields.SerialNumber)
| project DeviceId, DeviceName,
    HardwareUuid = ResolvedHardwareUuid,
    Model = ResolvedModel,
    SerialNumber,
    MergedToDeviceId, MergedDeviceIds,
    AadDeviceId, OnboardingStatus, SensorHealthState
"@

    $uri = "https://api.security.microsoft.com/api/advancedqueries/run"
    $body = @{ Query = $kqlQuery }

    try {
        $response = Invoke-MdeApiRequest -Uri $uri -Method "Post" -Body $body

        if ($null -eq $response.Results -or $response.Results.Count -eq 0) {
            Write-Warn "Advanced Hunting returned no results"
            return @()
        }

        if ($response.Results.Count -ge 10000) {
            Write-Warn "Advanced Hunting returned 10,000 rows (API hard limit)."
            Write-Warn "Devices beyond this limit will have no HardwareUuid and cannot be grouped by hardware."
            Write-Warn "Duplicate detection for those devices falls back to staleness-only analysis."
            Write-Warn "This is a known limitation. See script header (KNOWN LIMITATIONS) for details."
        }

        Write-Step "Advanced Hunting returned $($response.Results.Count) device records"
        return $response.Results
    }
    catch {
        Write-Warn "Advanced Hunting query failed: $($_.Exception.Message)"
        Write-Warn "Falling back to staleness-only analysis (no HardwareUuid grouping)"
        $script:advancedHuntingAvailable = $false
        return @()
    }
}

function Invoke-DeviceActivityQuery {
    Write-Info "Running Advanced Hunting query for device logon activity..."

    $actPlatformFilter = if ($null -ne $script:KqlPlatformValues) {
        $quoted = $script:KqlPlatformValues | ForEach-Object { "`"$_`"" }
        "| where OSPlatform in ($($quoted -join ', '))"
    } else { "" }

    $kqlQuery = @"
DeviceLogonEvents
| where Timestamp > ago(30d)
| join kind=inner (
    DeviceInfo
    $actPlatformFilter
    | distinct DeviceId
) on DeviceId
| summarize LastLogon = max(Timestamp), LogonCount = count() by DeviceId
"@

    $uri = "https://api.security.microsoft.com/api/advancedqueries/run"
    $body = @{ Query = $kqlQuery }

    try {
        $response = Invoke-MdeApiRequest -Uri $uri -Method "Post" -Body $body

        if ($null -eq $response.Results -or $response.Results.Count -eq 0) {
            Write-Warn "Device activity query returned no results (no logon events in last 30 days)"
            return @()
        }

        $script:logonActivityAvailable = $true
        Write-Step "Device activity query returned $($response.Results.Count) devices with logon events"
        return $response.Results
    }
    catch {
        Write-Warn "Device activity query failed: $($_.Exception.Message)"
        Write-Warn "Logon activity scoring will be skipped."
        return @()
    }
}

function Get-IntuneDevices {
    Write-Info "Collecting $Platform devices from Intune via Microsoft Graph..."

    $baseUrl = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"
    $select = "id,azureADDeviceId,serialNumber,imei,deviceName,complianceState,lastSyncDateTime,operatingSystem,managementAgent"

    if ($null -ne $script:IntunePlatformValues) {
        $filterParts = $script:IntunePlatformValues | ForEach-Object { "operatingSystem eq '$_'" }
        $intuneFilter = $filterParts -join " or "
        $encodedFilter = [System.Uri]::EscapeDataString($intuneFilter)
        $uri = "${baseUrl}?`$filter=${encodedFilter}&`$select=${select}&`$top=1000"
    }
    else {
        $uri = "${baseUrl}?`$select=${select}&`$top=1000"
    }

    $allDevices = [System.Collections.ArrayList]::new()
    $pageCount = 0

    try {
        Get-GraphAccessToken

        while ($null -ne $uri) {
            $response = Invoke-GraphApiRequest -Uri $uri
            $pageCount++

            if ($null -ne $response.value) {
                foreach ($device in $response.value) {
                    [void]$allDevices.Add($device)
                }
                Write-Info "  Page $pageCount : $($response.value.Count) Intune devices (total: $($allDevices.Count))"
            }

            $uri = $response.'@odata.nextLink'
        }

        $script:intuneAvailable = $true
        $script:Stats.IntuneDevicesTotal = $allDevices.Count
        Write-Step "Collected $($allDevices.Count) $Platform devices from Intune"
        return $allDevices
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }

        if ($statusCode -eq 403) {
            Write-Warn "Access denied to Intune API. Add Microsoft Graph > DeviceManagementManagedDevices.Read.All"
            Write-Warn "to the app registration and grant admin consent."
        }
        else {
            Write-Warn "Intune collection failed: $($_.Exception.Message)"
        }
        Write-Warn "Intune cross-reference will be skipped."
        return @()
    }
}
#endregion

#region --- Correlation ---
function Build-MdeCorrelationMap {
    param(
        [array]$RestDevices,
        [array]$AhResults,
        [array]$ActivityResults,
        [array]$IntuneDevices
    )

    Write-Info "Correlating REST API, Advanced Hunting, and enrichment data..."

    # Build AH lookup by DeviceId
    $ahLookup = @{}
    foreach ($ahRecord in $AhResults) {
        if (-not [string]::IsNullOrEmpty($ahRecord.DeviceId)) {
            $ahLookup[$ahRecord.DeviceId] = $ahRecord
        }
    }

    # Build logon activity lookup by DeviceId
    $activityLookup = @{}
    foreach ($actRecord in $ActivityResults) {
        if (-not [string]::IsNullOrEmpty($actRecord.DeviceId)) {
            $activityLookup[$actRecord.DeviceId] = $actRecord
        }
    }

    # Build Intune lookup by AadDeviceId (primary), SerialNumber (fallback), and IMEI (mobile fallback)
    $intuneByAadId = @{}
    $intuneBySerial = @{}
    $intuneByImei = @{}
    foreach ($intuneDevice in $IntuneDevices) {
        if (-not [string]::IsNullOrEmpty($intuneDevice.azureADDeviceId)) {
            $intuneByAadId[$intuneDevice.azureADDeviceId] = $intuneDevice
        }
        if (-not [string]::IsNullOrEmpty($intuneDevice.serialNumber)) {
            $intuneBySerial[$intuneDevice.serialNumber] = $intuneDevice
        }
        if (-not [string]::IsNullOrEmpty($intuneDevice.imei)) {
            $intuneByImei[$intuneDevice.imei] = $intuneDevice
        }
    }

    Write-Info "  AH lookup: $($ahLookup.Count) device mappings"
    if ($activityLookup.Count -gt 0) {
        Write-Info "  Activity lookup: $($activityLookup.Count) devices with logon events"
    }
    if ($intuneByAadId.Count -gt 0) {
        Write-Info "  Intune lookup: $($intuneByAadId.Count) by AadDeviceId, $($intuneBySerial.Count) by serial"
    }

    # Enrich REST devices with AH data
    $enrichedDevices = [System.Collections.ArrayList]::new()
    $staleThreshold = (Get-Date).AddDays(-$StaleThresholdDays)

    foreach ($device in $RestDevices) {
        $ahData = $ahLookup[$device.id]

        $lastSeenDate = if ($null -ne $device.lastSeen) {
            [DateTime]$device.lastSeen
        } else {
            [DateTime]::MinValue
        }

        $firstSeenDate = if ($null -ne $device.firstSeen) {
            [DateTime]$device.firstSeen
        } else {
            [DateTime]::MinValue
        }

        $daysSinceLastSeen = if ($lastSeenDate -ne [DateTime]::MinValue) {
            [Math]::Round(((Get-Date) - $lastSeenDate).TotalDays, 1)
        } else {
            -1
        }

        $isStale = $lastSeenDate -ne [DateTime]::MinValue -and $lastSeenDate -lt $staleThreshold

        if ($isStale) {
            $script:Stats.StaleRecords++
        }

        $tagsString = if ($null -ne $device.machineTags -and $device.machineTags.Count -gt 0) {
            $device.machineTags -join "; "
        } else {
            ""
        }

        # Logon activity enrichment
        $actData = $activityLookup[$device.id]
        $lastLogonDate = if ($null -ne $actData -and $null -ne $actData.LastLogon) {
            [DateTime]$actData.LastLogon
        } else {
            [DateTime]::MinValue
        }
        $logonCount = if ($null -ne $actData) { [int]$actData.LogonCount } else { 0 }

        # Intune enrichment — match by AadDeviceId first, then serial number
        $intuneMatch = $null
        if (-not [string]::IsNullOrEmpty($device.aadDeviceId)) {
            $intuneMatch = $intuneByAadId[$device.aadDeviceId]
        }
        if ($null -eq $intuneMatch -and $null -ne $ahData -and -not [string]::IsNullOrEmpty($ahData.SerialNumber)) {
            $intuneMatch = $intuneBySerial[$ahData.SerialNumber]
        }

        $intuneLastSync = if ($null -ne $intuneMatch -and $null -ne $intuneMatch.lastSyncDateTime) {
            [DateTime]$intuneMatch.lastSyncDateTime
        } else {
            [DateTime]::MinValue
        }

        if ($null -ne $intuneMatch) {
            $script:Stats.IntuneDevicesMatched++
        }

        $record = [PSCustomObject]@{
            MdeDeviceId       = $device.id
            ComputerDnsName   = $device.computerDnsName
            HardwareUuid      = if ($null -ne $ahData) { $ahData.HardwareUuid } else { "" }
            SerialNumber      = if ($null -ne $ahData) { $ahData.SerialNumber } else { "" }
            AadDeviceId       = $device.aadDeviceId
            OsPlatform        = $device.osPlatform
            OsVersion         = $device.osVersion
            Model             = if ($null -ne $ahData) { $ahData.Model } else { "" }
            HealthStatus      = $device.healthStatus
            OnboardingStatus  = if ($null -ne $ahData) { $ahData.OnboardingStatus } else { $device.onboardingStatus }
            DefenderAvStatus  = $device.defenderAvStatus
            AgentVersion      = $device.agentVersion
            RiskScore         = $device.riskScore
            ExposureLevel     = $device.exposureLevel
            FirstSeen         = $firstSeenDate
            LastSeen          = $lastSeenDate
            DaysSinceLastSeen = $daysSinceLastSeen
            IsStale           = $isStale
            MachineTags       = $tagsString
            MergedToDeviceId  = if ($null -ne $ahData) { $ahData.MergedToDeviceId } else { "" }
            MergedDeviceIds   = if ($null -ne $ahData) { $ahData.MergedDeviceIds } else { "" }
            LastIpAddress     = $device.lastIpAddress
            ManagedBy         = $device.managedBy
            LastLogonDate     = $lastLogonDate
            RecentLogonCount  = $logonCount
            IMEI              = if ($null -ne $intuneMatch -and -not [string]::IsNullOrEmpty($intuneMatch.imei)) { $intuneMatch.imei } else { "" }
            IntuneDeviceId    = if ($null -ne $intuneMatch) { $intuneMatch.id } else { "" }
            IntuneCompliance  = if ($null -ne $intuneMatch) { $intuneMatch.complianceState } else { "" }
            IntuneLastSync    = $intuneLastSync
            IntuneEnrolled    = ($null -ne $intuneMatch)
            GroupSize         = 0
            IsDuplicate       = $false
            OrphanScore       = 0
            Recommendation    = ""
            RecommendReason   = ""
            ExclusionAdvice   = ""
            WasTagged         = $false
        }

        [void]$enrichedDevices.Add($record)
    }

    # Separate devices with and without HardwareUuid
    $resolved = [System.Collections.ArrayList]::new()
    $unresolvedRaw = [System.Collections.ArrayList]::new()

    foreach ($device in $enrichedDevices) {
        if ([string]::IsNullOrEmpty($device.HardwareUuid)) {
            [void]$unresolvedRaw.Add($device)
        }
        else {
            [void]$resolved.Add($device)
        }
    }

    # Group resolved devices by HardwareUuid
    $uuidGroups = @{}
    foreach ($device in $resolved) {
        if (-not $uuidGroups.ContainsKey($device.HardwareUuid)) {
            $uuidGroups[$device.HardwareUuid] = [System.Collections.ArrayList]::new()
        }
        [void]$uuidGroups[$device.HardwareUuid].Add($device)
    }

    # IMEI fallback: group unresolved mobile devices by IMEI (requires Intune data)
    $unresolved = [System.Collections.ArrayList]::new()
    $imeiGrouped = 0

    foreach ($device in $unresolvedRaw) {
        if (-not [string]::IsNullOrEmpty($device.IMEI)) {
            $imeiKey = "IMEI:$($device.IMEI)"
            if (-not $uuidGroups.ContainsKey($imeiKey)) {
                $uuidGroups[$imeiKey] = [System.Collections.ArrayList]::new()
            }
            [void]$uuidGroups[$imeiKey].Add($device)
            $imeiGrouped++
        }
        else {
            [void]$unresolved.Add($device)
        }
    }

    if ($imeiGrouped -gt 0) {
        Write-Info "  IMEI fallback: $imeiGrouped device(s) grouped by IMEI (mobile)"
    }

    # Set group metadata
    foreach ($uuid in $uuidGroups.Keys) {
        $group = $uuidGroups[$uuid]
        $groupSize = $group.Count
        $hasDuplicates = $groupSize -gt 1

        foreach ($device in $group) {
            $device.GroupSize = $groupSize
            $device.IsDuplicate = $hasDuplicates
        }

        if ($hasDuplicates) {
            $script:Stats.DevicesWithDuplicates++
        }
    }

    $script:Stats.UniqueHardwareUuids = $uuidGroups.Count
    $script:Stats.UnresolvedDevices = $unresolved.Count

    Write-Step "Correlation complete: $($uuidGroups.Count) unique IDs, $($unresolved.Count) unresolved"

    return @{
        UuidGroups = $uuidGroups
        Unresolved = $unresolved
    }
}
#endregion

#region --- Analysis & Scoring ---
function Get-GroupRecommendation {
    param(
        [System.Collections.ArrayList]$GroupDevices
    )

    # Pre-compute group-level signals
    $newestLastSeen = ($GroupDevices | ForEach-Object { $_.LastSeen } | Measure-Object -Maximum).Maximum
    $newestFirstSeen = ($GroupDevices | ForEach-Object { $_.FirstSeen } | Measure-Object -Maximum).Maximum
    $anyHasTags = ($GroupDevices | Where-Object { $_.MachineTags -ne "" } | Measure-Object).Count -gt 0

    # Group leader = device with most recent lastSeen
    $leader = $GroupDevices | Where-Object { $_.LastSeen -eq $newestLastSeen } | Select-Object -First 1
    $leaderIsRecentlyActive = $leader.LastSeen -ne [DateTime]::MinValue -and $leader.LastSeen -gt (Get-Date).AddDays(-7)
    $leaderAadDeviceId = $leader.AadDeviceId

    # Agent version comparison (oldest vs newest in group)
    $oldestAgentVersion = $null
    $newestAgentVersion = $null
    $parsedVersions = [System.Collections.ArrayList]::new()
    foreach ($d in $GroupDevices) {
        if (-not [string]::IsNullOrEmpty($d.AgentVersion)) {
            try {
                [void]$parsedVersions.Add([PSCustomObject]@{
                    DeviceId = $d.MdeDeviceId
                    Version  = [version]$d.AgentVersion
                })
            }
            catch {
                Write-Verbose "Skipping unparseable agent version: $($d.AgentVersion)"
            }
        }
    }
    if ($parsedVersions.Count -gt 1) {
        $sortedVersions = $parsedVersions | Sort-Object -Property Version
        $oldestAgentVersion = $sortedVersions[0].Version
        $newestAgentVersion = $sortedVersions[-1].Version
    }

    # Tier 2: logon activity group signals
    $anyHasLogonActivity = $script:logonActivityAvailable -and
        ($GroupDevices | Where-Object { $_.RecentLogonCount -gt 0 } | Measure-Object).Count -gt 0

    # Tier 3: Intune enrollment group signals
    $anyHasIntuneEnrollment = $script:intuneAvailable -and
        ($GroupDevices | Where-Object { $_.IntuneEnrolled } | Measure-Object).Count -gt 0

    foreach ($device in $GroupDevices) {
        $score = 0
        $reasons = [System.Collections.ArrayList]::new()

        # Graduated inactivity scoring (replaces binary Inactive + Stale signals)
        # A device Inactive for 8 days (holiday) is not the same as 180 days (ghost)
        $longTermThreshold = $StaleThresholdDays * 3
        $daysSince = $device.DaysSinceLastSeen
        if ($daysSince -ge 0) {
            if ($daysSince -gt $longTermThreshold) {
                $score += 4
                [void]$reasons.Add("Long-term inactive ($([Math]::Round($daysSince))d, >${longTermThreshold}d)")
            }
            elseif ($daysSince -gt $StaleThresholdDays) {
                $score += 3
                [void]$reasons.Add("Stale ($([Math]::Round($daysSince))d, >${StaleThresholdDays}d)")
            }
            elseif ($daysSince -gt 14) {
                $score += 2
                [void]$reasons.Add("Extended absence ($([Math]::Round($daysSince))d)")
            }
            elseif ($daysSince -gt 7) {
                $score += 1
                [void]$reasons.Add("Recently inactive ($([Math]::Round($daysSince))d)")
            }
        }

        # +3: Already merged by MDE
        if (-not [string]::IsNullOrEmpty($device.MergedToDeviceId)) {
            $score += 3
            [void]$reasons.Add("Merged to $($device.MergedToDeviceId)")
        }

        # +2: Onboarding status InsufficientInfo
        if ($device.OnboardingStatus -eq "InsufficientInfo") {
            $score += 2
            [void]$reasons.Add("Onboarding: InsufficientInfo")
        }

        # +2: No sensor data or impaired communication
        if ($device.HealthStatus -in @("NoSensorData", "NoSensorDataImpairedCommunication", "ImpairedCommunication")) {
            $score += 2
            [void]$reasons.Add("Health: $($device.HealthStatus)")
        }

        # +1: Older firstSeen (not the newest in group)
        if ($device.FirstSeen -ne $newestFirstSeen) {
            $score += 1
            [void]$reasons.Add("Older record (not newest firstSeen)")
        }

        # +1: No tags while sibling has tags
        if ($anyHasTags -and [string]::IsNullOrEmpty($device.MachineTags)) {
            $score += 1
            [void]$reasons.Add("No tags (sibling has tags)")
        }

        # +3: Confirmed ghost — leader active within 7d and this record has >7d gap
        if ($leaderIsRecentlyActive -and $device.LastSeen -ne $newestLastSeen) {
            $gapDays = ($newestLastSeen - $device.LastSeen).TotalDays
            if ($gapDays -gt 7) {
                $score += 3
                [void]$reasons.Add("Ghost: leader active, $([Math]::Round($gapDays))d gap")
            }
        }

        # +2: No AadDeviceId (no Entra registration)
        if ([string]::IsNullOrEmpty($device.AadDeviceId)) {
            $score += 2
            [void]$reasons.Add("No AadDeviceId (no Entra link)")
        }
        # +1: Same AadDeviceId as group leader (ghost shares Entra identity with real device)
        elseif ($device.LastSeen -ne $newestLastSeen -and
                -not [string]::IsNullOrEmpty($leaderAadDeviceId) -and
                $device.AadDeviceId -eq $leaderAadDeviceId) {
            $score += 1
            [void]$reasons.Add("Same AadDeviceId as group leader")
        }

        # +1: Oldest agent version / -1: Newest agent version
        if ($null -ne $oldestAgentVersion -and $null -ne $newestAgentVersion -and
            $oldestAgentVersion -ne $newestAgentVersion -and
            -not [string]::IsNullOrEmpty($device.AgentVersion)) {
            try {
                $thisVersion = [version]$device.AgentVersion
                if ($thisVersion -eq $oldestAgentVersion) {
                    $score += 1
                    [void]$reasons.Add("Oldest agent version ($($device.AgentVersion))")
                }
                elseif ($thisVersion -eq $newestAgentVersion) {
                    $score -= 1
                    [void]$reasons.Add("Newest agent version ($($device.AgentVersion))")
                }
            }
            catch {
                Write-Verbose "Skipping unparseable agent version: $($device.AgentVersion)"
            }
        }

        # +1: Defender AV not updated or disabled
        if ($device.DefenderAvStatus -in @("notUpdated", "disabled")) {
            $score += 1
            [void]$reasons.Add("DefenderAV: $($device.DefenderAvStatus)")
        }

        # --- Tier 2: Logon activity signals ---
        # +2: No recent logon activity while sibling has logons
        if ($anyHasLogonActivity -and $device.RecentLogonCount -eq 0) {
            $score += 2
            [void]$reasons.Add("No logon activity (sibling has logons)")
        }
        # -1: Has recent logon activity
        if ($script:logonActivityAvailable -and $device.RecentLogonCount -gt 0) {
            $score -= 1
            [void]$reasons.Add("Has logon activity ($($device.RecentLogonCount) events)")
        }

        # --- Tier 3: Intune cross-reference signals ---
        # +2: No Intune enrollment while sibling is enrolled
        if ($anyHasIntuneEnrollment -and -not $device.IntuneEnrolled) {
            $score += 2
            [void]$reasons.Add("No Intune enrollment (sibling is enrolled)")
        }
        # -2: Active Intune enrollment with recent sync (within 30 days)
        if ($device.IntuneEnrolled -and $device.IntuneLastSync -ne [DateTime]::MinValue -and
            $device.IntuneLastSync -gt (Get-Date).AddDays(-30)) {
            $score -= 2
            [void]$reasons.Add("Intune enrolled, synced $([Math]::Round(((Get-Date) - $device.IntuneLastSync).TotalDays))d ago")
        }
        # +1: Intune non-compliant
        if ($device.IntuneEnrolled -and $device.IntuneCompliance -eq "noncompliant") {
            $score += 1
            [void]$reasons.Add("Intune: non-compliant")
        }

        # -2: Survivor record (has MergedDeviceIds — other records merged INTO this one)
        if (-not [string]::IsNullOrEmpty($device.MergedDeviceIds)) {
            $score -= 2
            [void]$reasons.Add("Survivor record (has MergedDeviceIds)")
        }

        # -1: Active health
        if ($device.HealthStatus -eq "Active") {
            $score -= 1
            [void]$reasons.Add("Health: Active")
        }

        # -1: Most recent lastSeen in group
        if ($device.LastSeen -eq $newestLastSeen) {
            $score -= 1
            [void]$reasons.Add("Most recent lastSeen in group")
        }

        $device.OrphanScore = $score
        $device.RecommendReason = $reasons -join "; "
    }

    # Assign recommendations: lowest score = KEEP, others by threshold
    $minScore = ($GroupDevices | Measure-Object -Property OrphanScore -Minimum).Minimum

    foreach ($device in $GroupDevices) {
        if ($device.OrphanScore -eq $minScore -and ($GroupDevices | Where-Object { $_.OrphanScore -eq $minScore } | Measure-Object).Count -eq 1) {
            $device.Recommendation = "KEEP (Primary)"
        }
        elseif ($device.OrphanScore -ge 5) {
            $device.Recommendation = "TAG (High confidence)"
            $device.ExclusionAdvice = "Exclude in portal: Justification='Inactive device', Notes='Stale or Orphan device'"
            $script:Stats.OrphanRecords++
            $script:Stats.RecommendedForTagging++
        }
        elseif ($device.OrphanScore -ge 3) {
            $device.Recommendation = "REVIEW (Moderate confidence)"
            $device.ExclusionAdvice = "Review, then exclude in portal: Justification='Duplicate device', Notes='Stale or Orphan device'"
            $script:Stats.OrphanRecords++
        }
        else {
            $device.Recommendation = "REVIEW (Low confidence)"
        }
    }
}

function Get-UnresolvedAnalysis {
    param(
        [System.Collections.ArrayList]$UnresolvedDevices
    )

    $staleThreshold = (Get-Date).AddDays(-$StaleThresholdDays)

    foreach ($device in $UnresolvedDevices) {
        $reasons = [System.Collections.ArrayList]::new()

        $isStale = $device.LastSeen -ne [DateTime]::MinValue -and $device.LastSeen -lt $staleThreshold
        $isInactive = $device.HealthStatus -in @("Inactive", "NoSensorData", "NoSensorDataImpairedCommunication", "ImpairedCommunication")

        if ($isStale) { [void]$reasons.Add("Stale (>$StaleThresholdDays days)") }
        if ($isInactive) { [void]$reasons.Add("Health: $($device.HealthStatus)") }

        if (-not $script:advancedHuntingAvailable) {
            [void]$reasons.Add("Advanced Hunting unavailable")
        }
        else {
            [void]$reasons.Add("No HardwareUuid in Advanced Hunting")
        }

        $device.Recommendation = if ($isStale -or $isInactive) {
            "REVIEW (Stale, no HardwareUuid)"
        }
        else {
            "OK (No HardwareUuid available)"
        }

        $device.RecommendReason = $reasons -join "; "
        $device.GroupSize = 1
    }
}
#endregion

#region --- Device Tagging ---
function Set-MdeDeviceTag {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$DeviceId,
        [string]$DeviceName,
        [string]$Tag
    )

    $uri = "https://api.security.microsoft.com/api/machines/$DeviceId/tags"
    $body = @{
        Value  = $Tag
        Action = "Add"
    }

    if (-not $PSCmdlet.ShouldProcess($DeviceName, "Add tag '$Tag'")) {
        return $false
    }

    try {
        Invoke-MdeApiRequest -Uri $uri -Method "Post" -Body $body | Out-Null
        Write-Step "  Tagged: $DeviceName -> '$Tag'"
        $script:Stats.DevicesTagged++
        return $true
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }

        if ($statusCode -eq 403) {
            Write-Warn "  Permission denied tagging $DeviceName (Machine.ReadWrite.All required)"
        }
        else {
            Write-Warn "  Failed to tag $DeviceName : $($_.Exception.Message)"
        }
        $script:Stats.TaggingFailed++
        return $false
    }
}
#endregion

#region --- Exclusion Script Generator ---
function New-ExclusionHelperScript {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [array]$TagCandidates,
        [string]$ScriptOutputPath,
        [string]$CsvSourcePath
    )

    $deviceCount = $TagCandidates.Count
    $generatedTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $scriptContent = @'
<#
.SYNOPSIS
    Exclude flagged devices from Microsoft Defender Vulnerability Management.

.DESCRIPTION
    Auto-generated by Find-DuplicateDefenderDevices.ps1 on {TIMESTAMP}.
    Source scan: {CSVPATH}
    Devices:    {DEVICECOUNT} TAG/REVIEW candidates

    This script uses the XDRInternals module to call undocumented Defender XDR
    portal APIs. These internal APIs may change without notice.
    Microsoft does not provide a public API for device exclusions (as of 2026).

    IMPORTANT SECURITY NOTICE:
    Authentication requires pasting a browser session cookie. This cookie grants
    full portal-level access to your Defender XDR tenant. The script handles
    cookies in plain text (SecureString truncates long values), but scrubs all
    sensitive variables from memory when finished. For maximum safety:
      - Use an InPrivate/Incognito browser session to obtain the cookie
      - Close the browser session after copying the cookie
      - Run this script in a dedicated PowerShell window and close it after

    DISCLAIMER:
    This is an unofficial, community-driven tool. It is NOT affiliated with,
    endorsed by, or supported by Microsoft. The undocumented portal APIs used
    may change or break without notice. THE SOFTWARE IS PROVIDED "AS IS",
    WITHOUT WARRANTY OF ANY KIND. The authors are not responsible for any data
    loss, security incidents, or unintended changes resulting from its use.
    ALWAYS TEST in a non-production environment first.
    YOU ARE SOLELY RESPONSIBLE FOR ANY ACTIONS TAKEN. USE AT YOUR OWN RISK.

.PARAMETER CsvPath
    Path to the tag recommendations CSV from the scan.

.PARAMETER Action
    Exclude: Exclude devices from Vulnerability Management.
    GetStatus: Check current exclusion status of devices.

.PARAMETER Justification
    Reason for exclusion. Default: DuplicateMachine.

.PARAMETER Notes
    Free-text notes attached to each exclusion.

.PARAMETER BatchSize
    Number of devices per API call. Default: 20.

.PARAMETER ThrottleDelayMs
    Delay in milliseconds between batches. Default: 500.

.PARAMETER MinOrphanScore
    Minimum OrphanScore from the scan to include a device. Default: 5.

.EXAMPLE
    .\Invoke-ExcludeDevices.ps1
    # Excludes devices with OrphanScore >= 5 from the scan CSV

.EXAMPLE
    .\Invoke-ExcludeDevices.ps1 -MinOrphanScore 3
    # Include moderate-confidence devices too

.EXAMPLE
    .\Invoke-ExcludeDevices.ps1 -Action GetStatus
    # Check exclusion status without making changes

.NOTES
    Requires: XDRInternals module (Install-Module XDRInternals -Scope CurrentUser)
    Credits:  XDRInternals by Fabian Bader (@f-bader) and Nathan McNulty (@nathanmcnulty)
              https://github.com/MSCloudInternals/XDRInternals
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'Interactive script requires colored console output')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
    Justification = 'Set-DeviceExclusionState is an internal helper; confirmation is handled in the main flow')]
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$CsvPath = "{CSVPATH}",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Exclude", "GetStatus")]
    [string]$Action = "Exclude",

    [Parameter(Mandatory = $false)]
    [ValidateSet("InactiveDevice", "DuplicateMachine", "DeviceDoesntExist", "OutOfScope", "Other")]
    [string]$Justification = "DuplicateMachine",

    [Parameter(Mandatory = $false)]
    [string]$Notes = "Stale/orphan device flagged by duplicate scanner",

    [Parameter(Mandatory = $false)]
    [int]$BatchSize = 20,

    [Parameter(Mandatory = $false)]
    [int]$ThrottleDelayMs = 500,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 15)]
    [int]$MinOrphanScore = 5
)

$baseUri = "https://security.microsoft.com"
$updateEndpoint = "$baseUri/apiproxy/mtp/k8s/machines/UpdateExclusionState"
$statusEndpoint = "$baseUri/apiproxy/mtp/ndr/machines"

#region --- Security Cleanup Helper ---
function Clear-SensitiveState {
    # Remove any cookie/token variables that may linger in the session
    foreach ($varName in @('cookie', 'sccAuth', 'xsrf')) {
        if (Get-Variable -Name $varName -Scope 1 -ErrorAction SilentlyContinue) {
            Remove-Variable -Name $varName -Scope 1 -Force -ErrorAction SilentlyContinue
        }
    }

    # Clear clipboard in case cookie data lingers
    Set-Clipboard -Value " " -ErrorAction SilentlyContinue

    # Clear PSReadLine command history so pasted cookies are not recoverable
    try {
        Clear-History -ErrorAction SilentlyContinue
        if (Get-Module PSReadLine -ErrorAction SilentlyContinue) {
            [Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory()
        }
    }
    catch {
        # PSReadLine may not be loaded in non-interactive sessions - safe to ignore
        $null = $_.Exception
    }

    # Force garbage collection to release string references
    [System.GC]::Collect()
}
#endregion

#region --- Prerequisites ---
if (-not (Get-Module -ListAvailable -Name XDRInternals)) {
    Write-Host "[!] XDRInternals module not found." -ForegroundColor Yellow
    $installChoice = Read-Host "    Install from PSGallery? [Y/n]"
    if ($installChoice -match '^[Nn]') {
        Write-Host "    Install manually: Install-Module XDRInternals -Scope CurrentUser" -ForegroundColor Cyan
        exit 1
    }
    try {
        Install-Module XDRInternals -Scope CurrentUser -Force -AllowClobber
    }
    catch {
        Write-Error "Failed to install XDRInternals: $_"
        exit 1
    }
}
Import-Module XDRInternals -ErrorAction Stop
#endregion

#region --- Functions ---
function Initialize-XdrConnection {
    try {
        $null = Get-XdrTenantContext -ErrorAction Stop
        Write-Host "[+] Active XDR session detected." -ForegroundColor Green
        return
    }
    catch {
        Write-Host "[*] No active XDR session. Starting authentication..." -ForegroundColor Cyan
    }

    Write-Host ""
    Write-Host "    Choose authentication method:" -ForegroundColor Yellow
    Write-Host "    [1] ESTSAUTHPERSISTENT cookie" -ForegroundColor Gray
    Write-Host "    [2] sccauth + XSRF tokens (recommended)" -ForegroundColor Gray
    Write-Host ""

    $choice = Read-Host "    Enter choice (1 or 2)"

    switch ($choice) {
        "1" {
            Write-Host ""
            Write-Host "    How to get the ESTSAUTHPERSISTENT cookie:" -ForegroundColor Yellow
            Write-Host "    1. Open an InPrivate/Incognito window in Edge or Chrome" -ForegroundColor Gray
            Write-Host "    2. Open DevTools FIRST (F12) before navigating" -ForegroundColor Gray
            Write-Host "    3. Go to https://security.microsoft.com and sign in" -ForegroundColor Gray
            Write-Host "    4. In DevTools > Application > Cookies, click login.microsoftonline.com" -ForegroundColor Gray
            Write-Host "    5. Copy the ESTSAUTHPERSISTENT value (long string starting with 0.A...)" -ForegroundColor Gray
            Write-Host ""
            Write-Host "    NOTE: If you don't see the login.microsoftonline.com cookie, you must" -ForegroundColor DarkYellow
            Write-Host "          use InPrivate/Incognito with DevTools open BEFORE signing in." -ForegroundColor DarkYellow
            Write-Host "          The cookie is only set during the authentication redirect." -ForegroundColor DarkYellow
            Write-Host ""
            Write-Host "    TROUBLESHOOTING: ESTSAUTHPERSISTENT can be tricky to capture." -ForegroundColor DarkYellow
            Write-Host "    If auth fails, re-run the script and choose option [2] instead." -ForegroundColor DarkYellow
            Write-Host "    The XDRay extension can capture sccauth + XSRF reliably:" -ForegroundColor DarkYellow
            Write-Host "    https://github.com/MSCloudInternals/XDRInternals/tree/main/XDRay" -ForegroundColor DarkYellow
            Write-Host ""

            Write-Host "    >> Copy the cookie value to your clipboard now." -ForegroundColor White
            Write-Host "    >> Do NOT paste it here. Just press any key when ready." -ForegroundColor White
            Write-Host ""
            $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Write-Host ""
            $cookie = Get-Clipboard
            Set-Clipboard -Value " "

            if ([string]::IsNullOrWhiteSpace($cookie)) {
                Write-Error "Clipboard is empty. Copy the cookie value first."
                exit 1
            }

            Write-Host "    [+] Read $($cookie.Length) characters from clipboard." -ForegroundColor Green
            Write-Host "    [*] Connecting to XDR portal..." -ForegroundColor Cyan
            try {
                Connect-XdrByEstsCookie -EstsAuthCookieValue $cookie *> $null
                Write-Host "    [+] XDR connection established." -ForegroundColor Green
            }
            catch {
                Write-Host "    [FAIL] XDR connection failed: $($_.Exception.Message)" -ForegroundColor Red
                throw
            }
            finally {
                Remove-Variable cookie -Force -ErrorAction SilentlyContinue
            }
        }
        "2" {
            Write-Host ""
            Write-Host "    How to get sccauth and XSRF tokens:" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "    Option A - XDRay extension (easiest):" -ForegroundColor Gray
            Write-Host "    1. Install XDRay: https://github.com/MSCloudInternals/XDRInternals/tree/main/XDRay" -ForegroundColor Gray
            Write-Host "    2. Sign in to security.microsoft.com" -ForegroundColor Gray
            Write-Host "    3. Click the XDRay extension icon - it captures both cookies" -ForegroundColor Gray
            Write-Host ""
            Write-Host "    Option B - Manual via DevTools:" -ForegroundColor Gray
            Write-Host "    1. Open security.microsoft.com in Edge/Chrome and sign in" -ForegroundColor Gray
            Write-Host "    2. Open DevTools (F12) > Application > Cookies > security.microsoft.com" -ForegroundColor Gray
            Write-Host "    3. Copy the 'sccauth' cookie value" -ForegroundColor Gray
            Write-Host "    4. Copy the 'XSRF-TOKEN' cookie value" -ForegroundColor Gray
            Write-Host ""

            Write-Host "    >> Copy the 'sccauth' value to your clipboard now." -ForegroundColor White
            Write-Host "    >> Do NOT paste it here. Just press any key when ready." -ForegroundColor White
            Write-Host ""
            $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Write-Host ""
            $sccAuth = Get-Clipboard
            Set-Clipboard -Value " "

            if ([string]::IsNullOrWhiteSpace($sccAuth)) {
                Write-Error "Clipboard is empty. Copy the sccauth value first."
                exit 1
            }
            Write-Host "    [+] Read sccauth ($($sccAuth.Length) chars)" -ForegroundColor Green

            Write-Host "    >> Now copy the 'XSRF-TOKEN' value to your clipboard." -ForegroundColor White
            Write-Host "    >> Do NOT paste it here. Just press any key when ready." -ForegroundColor White
            Write-Host ""
            $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Write-Host ""
            $xsrf = Get-Clipboard
            Set-Clipboard -Value " "

            if ([string]::IsNullOrWhiteSpace($xsrf)) {
                Write-Error "Clipboard is empty. Copy the XSRF-TOKEN value first."
                exit 1
            }
            Write-Host "    [+] Read XSRF-TOKEN ($($xsrf.Length) chars)" -ForegroundColor Green
            Write-Host "    [*] Connecting to XDR portal..." -ForegroundColor Cyan

            try {
                Set-XdrConnectionSettings -SccAuth $sccAuth -Xsrf $xsrf *> $null
                Write-Host "    [+] XDR connection established." -ForegroundColor Green
            }
            catch {
                Write-Host "    [FAIL] XDR connection failed: $($_.Exception.Message)" -ForegroundColor Red
                throw
            }
            finally {
                Remove-Variable sccAuth, xsrf -Force -ErrorAction SilentlyContinue
            }
        }
        default {
            Write-Error "Invalid choice. Exiting."
            exit 1
        }
    }
}

function Set-DeviceExclusionState {
    param(
        [string[]]$MachineIds,
        [string]$ExclusionState,
        [string]$ExclusionJustification,
        [string]$ExclusionNotes
    )

    $body = @{
        SenseMachineIds = $MachineIds
        ExclusionState  = $ExclusionState
        Justification   = $ExclusionJustification
        Notes           = $ExclusionNotes
    } | ConvertTo-Json -Depth 3

    try {
        $response = Invoke-XdrRestMethod -Uri $updateEndpoint -Method POST -Body $body -ErrorAction Stop
        return $response
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $errorBody  = $_.ErrorDetails.Message
        Write-Error "Failed to update exclusion state (HTTP $statusCode): $errorBody"
        return $null
    }
}

function Get-DeviceExclusionStatus {
    param(
        [string]$MachineId
    )

    $uri = "$statusEndpoint/$MachineId/exclusionDetails?senseMachineId=$MachineId"

    try {
        $response = Invoke-XdrRestMethod -Uri $uri -Method GET -ErrorAction Stop
        return $response
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -eq 404) {
            Write-Warning "Device $($MachineId.Substring(0,12))... not found or no exclusion data."
            return $null
        }
        Write-Warning "Failed to get status for $($MachineId.Substring(0,12))...: $_"
        return $null
    }
}
#endregion

#region --- Main ---
Write-Host ""
Write-Host "================================================================" -ForegroundColor Red
Write-Host "  MDVM Device Exclusion Helper" -ForegroundColor Yellow
Write-Host "  Generated by Find-DuplicateDefenderDevices.ps1" -ForegroundColor Gray
Write-Host "================================================================" -ForegroundColor Red
Write-Host ""
Write-Host "  WARNING: UNDOCUMENTED APIs + BROWSER SESSION COOKIES" -ForegroundColor Red
Write-Host ""
Write-Host "  This script is NOT affiliated with or supported by Microsoft." -ForegroundColor Yellow
Write-Host "  It calls internal Defender XDR portal APIs that may change or" -ForegroundColor Yellow
Write-Host "  break without notice. Authentication requires pasting a browser" -ForegroundColor Yellow
Write-Host "  session cookie that grants full portal-level access to your" -ForegroundColor Yellow
Write-Host "  tenant. Handle it like a password." -ForegroundColor Yellow
Write-Host ""
Write-Host "  THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND." -ForegroundColor DarkGray
Write-Host "  You are solely responsible for any actions taken." -ForegroundColor DarkGray
Write-Host "  USE AT YOUR OWN RISK." -ForegroundColor DarkGray
Write-Host ""
Write-Host "================================================================" -ForegroundColor Red
Write-Host ""

$acceptRisk = Read-Host "  Type 'YES' to accept the risk and continue"
if ($acceptRisk -ne 'YES') {
    Write-Host "  Aborted." -ForegroundColor Yellow
    exit 0
}
Write-Host ""

$logPath = Join-Path (Split-Path $CsvPath) "exclusion_transcript_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

try {

# Load CSV
if (-not (Test-Path $CsvPath)) {
    Write-Error "CSV file not found: $CsvPath"
    Write-Host "  Specify the path: .\Invoke-ExcludeDevices.ps1 -CsvPath 'path\to\tag_<platform>_recommendations.csv'" -ForegroundColor Cyan
    exit 1
}

$csvData = Import-Csv -Path $CsvPath
Write-Host "[*] Loaded $($csvData.Count) record(s) from CSV." -ForegroundColor Cyan

# Filter by OrphanScore
$devices = @($csvData | Where-Object {
    $score = 0
    if ([int]::TryParse($_.OrphanScore, [ref]$score)) { $score -ge $MinOrphanScore } else { $false }
})

if ($devices.Count -eq 0) {
    Write-Host "[*] No devices with OrphanScore >= $MinOrphanScore found." -ForegroundColor Yellow
    Write-Host "    Try lowering the threshold: -MinOrphanScore 3" -ForegroundColor Cyan
    exit 0
}

Write-Host "[*] $($devices.Count) device(s) with OrphanScore >= $MinOrphanScore selected." -ForegroundColor Cyan
Write-Host ""

# Show preview
$preview = $devices | Select-Object -First 10
foreach ($d in $preview) {
    $idShort = if ($d.MdeDeviceId.Length -gt 15) { $d.MdeDeviceId.Substring(0, 12) + "..." } else { $d.MdeDeviceId }
    Write-Host "    $idShort  $($d.ComputerDnsName)  Score=$($d.OrphanScore)  $($d.Recommendation)" -ForegroundColor Gray
}
if ($devices.Count -gt 10) {
    Write-Host "    ... and $($devices.Count - 10) more" -ForegroundColor DarkGray
}
Write-Host ""

# Authenticate (before transcript starts - no sensitive data logged)
Initialize-XdrConnection

# Start transcript AFTER auth so cookies are never logged
Start-Transcript -Path $logPath -Append | Out-Null
Write-Host "[*] Transcript log: $logPath" -ForegroundColor DarkGray
Write-Host ""

# Extract machine IDs (MdeDeviceId = senseMachineId in portal API)
$machineIds = @($devices | Select-Object -ExpandProperty MdeDeviceId)

switch ($Action) {
    "GetStatus" {
        Write-Host ""
        Write-Host "[*] Checking exclusion status for $($machineIds.Count) device(s)..." -ForegroundColor Cyan

        $results = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($id in $machineIds) {
            $status = Get-DeviceExclusionStatus -MachineId $id
            $results.Add([PSCustomObject]@{
                MachineId     = $id
                Status        = if ($status) { $status.exclusionState } else { "Unknown" }
                Justification = if ($status) { $status.justification } else { "N/A" }
                ExcludedBy    = if ($status) { $status.excludedBy } else { "" }
                ExcludedOn    = if ($status) { $status.excludedOn } else { "" }
            })
            Start-Sleep -Milliseconds $ThrottleDelayMs
        }

        $results | Format-Table -AutoSize
    }

    "Exclude" {
        Write-Host ""
        Write-Host "[*] Pre-flight: checking current exclusion status for $($machineIds.Count) device(s)..." -ForegroundColor Cyan

        # Build a lookup from CSV for device names
        $deviceLookup = @{}
        foreach ($d in $devices) { $deviceLookup[$d.MdeDeviceId] = $d }

        # Check which devices are already excluded
        $alreadyExcluded = [System.Collections.Generic.List[string]]::new()
        $toExclude = [System.Collections.Generic.List[string]]::new()
        $statusUnknown = [System.Collections.Generic.List[string]]::new()

        foreach ($id in $machineIds) {
            $status = Get-DeviceExclusionStatus -MachineId $id
            $idShort = $id.Substring(0, 12) + "..."
            $name = $deviceLookup[$id].ComputerDnsName

            if ($null -ne $status -and $status.exclusionState -eq "Excluded") {
                $alreadyExcluded.Add($id)
                Write-Host "    [SKIP] $idShort  $name  (already excluded)" -ForegroundColor DarkGray
            }
            elseif ($null -eq $status) {
                $statusUnknown.Add($id)
                $toExclude.Add($id)
                Write-Host "    [    ] $idShort  $name  (status unknown - will attempt)" -ForegroundColor Gray
            }
            else {
                $toExclude.Add($id)
                Write-Host "    [    ] $idShort  $name  (not excluded)" -ForegroundColor Gray
            }
            Start-Sleep -Milliseconds $ThrottleDelayMs
        }

        Write-Host ""
        Write-Host "[*] Pre-flight summary:" -ForegroundColor Cyan
        Write-Host "    Already excluded (skipped): $($alreadyExcluded.Count)" -ForegroundColor DarkGray
        Write-Host "    To exclude:                 $($toExclude.Count)" -ForegroundColor White

        if ($toExclude.Count -eq 0) {
            Write-Host ""
            Write-Host "[+] All devices are already excluded. Nothing to do." -ForegroundColor Green
            # Still export full report below
        }
        else {
            Write-Host "    Justification:              $Justification" -ForegroundColor Gray
            Write-Host "    Notes:                      $Notes" -ForegroundColor Gray
            Write-Host ""
            Write-Host "[!] Exclusion takes up to 10 hours to fully apply." -ForegroundColor Yellow
            Write-Host ""

            $confirm = Read-Host "    Proceed with $($toExclude.Count) device(s)? [y/N]"
            if ($confirm -notmatch '^[Yy]') {
                Write-Host "    Aborted." -ForegroundColor Yellow
                exit 0
            }

            Write-Host ""
            $totalBatches = [math]::Ceiling($toExclude.Count / $BatchSize)
            $batchNumber = 0

            for ($i = 0; $i -lt $toExclude.Count; $i += $BatchSize) {
                $batchNumber++
                $batch = $toExclude[$i..([math]::Min($i + $BatchSize - 1, $toExclude.Count - 1))]

                Write-Host "    Batch $batchNumber/$totalBatches ($($batch.Count) devices)..." -ForegroundColor Gray

                $response = Set-DeviceExclusionState `
                    -MachineIds $batch `
                    -ExclusionState "Excluded" `
                    -ExclusionJustification $Justification `
                    -ExclusionNotes $Notes

                foreach ($id in $batch) {
                    $dev = $deviceLookup[$id]
                    $dev | Add-Member -NotePropertyName ExcludeResult -NotePropertyValue $(
                        if ($null -ne $response) { "Excluded" } else { "Failed" }
                    ) -Force
                    $dev | Add-Member -NotePropertyName ExcludeTimestamp -NotePropertyValue (
                        Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
                    ) -Force
                }

                if ($batchNumber -lt $totalBatches) {
                    Start-Sleep -Milliseconds $ThrottleDelayMs
                }
            }

            Write-Host ""
            Write-Host "[+] Exclusion complete." -ForegroundColor Green
        }

        # Mark skipped devices in the lookup
        foreach ($id in $alreadyExcluded) {
            $dev = $deviceLookup[$id]
            $dev | Add-Member -NotePropertyName ExcludeResult -NotePropertyValue "AlreadyExcluded" -Force
            $dev | Add-Member -NotePropertyName ExcludeTimestamp -NotePropertyValue "" -Force
        }

        # Build final report for all devices
        $allResults = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($id in $machineIds) {
            $dev = $deviceLookup[$id]
            $allResults.Add([PSCustomObject]@{
                MdeDeviceId      = $id
                ComputerDnsName  = $dev.ComputerDnsName
                OrphanScore      = $dev.OrphanScore
                Recommendation   = $dev.Recommendation
                ExcludeResult    = if ($dev.PSObject.Properties['ExcludeResult']) { $dev.ExcludeResult } else { "NotProcessed" }
                ExcludeTimestamp = if ($dev.PSObject.Properties['ExcludeTimestamp']) { $dev.ExcludeTimestamp } else { "" }
                Justification    = if ($dev.PSObject.Properties['ExcludeResult'] -and $dev.ExcludeResult -eq "Excluded") { $Justification } else { "" }
                Notes            = if ($dev.PSObject.Properties['ExcludeResult'] -and $dev.ExcludeResult -eq "Excluded") { $Notes } else { "" }
            })
        }

        # Console summary
        Write-Host ""
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host "  EXCLUSION REPORT" -ForegroundColor Green
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host ""

        $allResults | Format-Table -AutoSize -Property MdeDeviceId, ComputerDnsName, OrphanScore, ExcludeResult

        $countExcluded = @($allResults | Where-Object { $_.ExcludeResult -eq "Excluded" }).Count
        $countSkipped  = @($allResults | Where-Object { $_.ExcludeResult -eq "AlreadyExcluded" }).Count
        $countFailed   = @($allResults | Where-Object { $_.ExcludeResult -eq "Failed" }).Count

        Write-Host "  Newly excluded:     $countExcluded" -ForegroundColor $(if ($countExcluded -gt 0) { "Green" } else { "White" })
        Write-Host "  Already excluded:   $countSkipped" -ForegroundColor $(if ($countSkipped -gt 0) { "DarkGray" } else { "White" })
        Write-Host "  Failed:             $countFailed" -ForegroundColor $(if ($countFailed -gt 0) { "Red" } else { "White" })
        Write-Host "  Total devices:      $($allResults.Count)" -ForegroundColor White
        Write-Host ""

        # Export full report
        $resultPath = Join-Path (Split-Path $CsvPath) "exclusion_results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $allResults | Export-Csv -Path $resultPath -NoTypeInformation -Encoding UTF8
        Write-Host "[+] Full report exported to: $resultPath" -ForegroundColor Green
        Write-Host ""
        if ($countExcluded -gt 0) {
            Write-Host "[i] It can take up to 10 hours for devices to be fully excluded from MDVM views." -ForegroundColor Yellow
        }
    }
}

}
finally {
    # Scrub sensitive data from memory regardless of how the script exits
    Clear-SensitiveState
    try { Stop-Transcript | Out-Null } catch { $null = $_.Exception }
    Write-Host ""
    Write-Host "[*] Session cleanup complete. Sensitive variables scrubbed from memory." -ForegroundColor DarkGray
    if (Test-Path $logPath -ErrorAction SilentlyContinue) {
        Write-Host "[*] Log saved to: $logPath" -ForegroundColor DarkGray
    }
    Write-Host "    Close this PowerShell window for maximum security." -ForegroundColor DarkGray
}
#endregion
'@

    # Replace placeholders in the template
    $scriptContent = $scriptContent.Replace('{TIMESTAMP}', $generatedTimestamp)
    $scriptContent = $scriptContent.Replace('{CSVPATH}', $CsvSourcePath)
    $scriptContent = $scriptContent.Replace('{DEVICECOUNT}', $deviceCount.ToString())

    if (-not $PSCmdlet.ShouldProcess($ScriptOutputPath, "Generate exclusion helper script")) {
        return
    }

    $scriptContent | Out-File -FilePath $ScriptOutputPath -Encoding UTF8 -Force

    Write-Step "Generated exclusion helper script: $ScriptOutputPath"
    Write-Info "  Devices eligible: $deviceCount (TAG/REVIEW candidates)"
    Write-Info "  Default filter: OrphanScore >= 5 (override with -MinOrphanScore)"
    Write-Info "  Usage: .\Invoke-ExcludeDevices.ps1"
    Write-Info "  Usage: .\Invoke-ExcludeDevices.ps1 -Action GetStatus"
}
#endregion

#region --- Console Output ---
function Write-ConsoleSummary {
    param(
        [array]$AllResults,
        [array]$DuplicatesOnly,
        [array]$UnresolvedDevices
    )

    Write-Header "SCAN RESULTS SUMMARY"

    Write-Host "  MDE $Platform devices scanned:     " -NoNewline
    Write-Host "$($script:Stats.TotalMdeDevices)" -ForegroundColor White
    Write-Host "  Advanced Hunting records:          " -NoNewline
    Write-Host "$($script:Stats.AdvancedHuntingDevices)" -ForegroundColor White
    Write-Host "  Unique HardwareUuids:              " -NoNewline
    Write-Host "$($script:Stats.UniqueHardwareUuids)" -ForegroundColor White
    Write-Host ""
    Write-Host "  Devices with duplicate records:    " -NoNewline
    Write-Host "$($script:Stats.DevicesWithDuplicates)" -ForegroundColor $(if ($script:Stats.DevicesWithDuplicates -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Orphan/stale records identified:   " -NoNewline
    Write-Host "$($script:Stats.OrphanRecords)" -ForegroundColor $(if ($script:Stats.OrphanRecords -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Stale records (>$StaleThresholdDays days):       " -NoNewline
    Write-Host "$($script:Stats.StaleRecords)" -ForegroundColor $(if ($script:Stats.StaleRecords -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Recommended for tagging:           " -NoNewline
    Write-Host "$($script:Stats.RecommendedForTagging)" -ForegroundColor $(if ($script:Stats.RecommendedForTagging -gt 0) { "Red" } else { "Green" })
    Write-Host "  Unresolved (no HardwareUuid):      " -NoNewline
    Write-Host "$($script:Stats.UnresolvedDevices)" -ForegroundColor $(if ($script:Stats.UnresolvedDevices -gt 0) { "Yellow" } else { "Green" })

    if ($script:logonActivityAvailable) {
        Write-Host ""
        Write-Host "  Logon activity data:               " -NoNewline
        Write-Host "Available (30-day lookback)" -ForegroundColor Green
    }

    if ($script:intuneAvailable) {
        Write-Host ""
        Write-Host "  Intune $Platform devices:           " -NoNewline
        Write-Host "$($script:Stats.IntuneDevicesTotal)" -ForegroundColor White
        Write-Host "  MDE devices with Intune match:     " -NoNewline
        Write-Host "$($script:Stats.IntuneDevicesMatched)" -ForegroundColor $(if ($script:Stats.IntuneDevicesMatched -gt 0) { "Green" } else { "Yellow" })
    }

    if ($TagStaleDevices) {
        Write-Host ""
        Write-Host "  Devices tagged:                    " -NoNewline
        Write-Host "$($script:Stats.DevicesTagged)" -ForegroundColor $(if ($script:Stats.DevicesTagged -gt 0) { "Cyan" } else { "White" })
        Write-Host "  Tagging failures:                  " -NoNewline
        Write-Host "$($script:Stats.TaggingFailed)" -ForegroundColor $(if ($script:Stats.TaggingFailed -gt 0) { "Red" } else { "Green" })
    }

    # Show duplicate details
    if ($DuplicatesOnly.Count -gt 0) {
        Write-Header "DUPLICATE DEVICE DETAILS"

        $dupGroups = $DuplicatesOnly | Group-Object -Property HardwareUuid
        $shownCount = 0

        foreach ($group in $dupGroups) {
            if ($shownCount -ge $MaxDisplayItems) {
                Write-Host ""
                Write-Warn "Showing $MaxDisplayItems of $($dupGroups.Count) HardwareUuids with duplicates. Check duplicate_$($Platform.ToLower())_records.csv for full details."
                break
            }

            Write-Host ""
            Write-Host "  HardwareUuid: " -NoNewline -ForegroundColor Cyan
            Write-Host "$($group.Name)" -ForegroundColor White
            Write-Host "  Records: $($group.Group.Count)" -ForegroundColor Cyan
            Write-Host ""

            foreach ($record in ($group.Group | Sort-Object -Property Recommendation)) {
                $color = switch -Wildcard ($record.Recommendation) {
                    "KEEP*"     { "Green" }
                    "TAG*"      { "Red" }
                    "REVIEW*"   { "Yellow" }
                    default     { "Gray" }
                }

                Write-Host "    [$($record.Recommendation)]" -ForegroundColor $color -NoNewline
                Write-Host " $($record.ComputerDnsName) | " -NoNewline
                Write-Host "Health: $($record.HealthStatus) | " -NoNewline
                Write-Host "Last seen: $($record.DaysSinceLastSeen) days | " -NoNewline
                Write-Host "Score: $($record.OrphanScore)"

                if ($record.MergedToDeviceId) {
                    Write-Host "      Merged to: $($record.MergedToDeviceId)" -ForegroundColor DarkGray
                }

                if ($record.RecommendReason) {
                    Write-Host "      Reason: $($record.RecommendReason)" -ForegroundColor DarkGray
                }
                Write-Host "      MDE ID: $($record.MdeDeviceId)" -ForegroundColor DarkGray

                if ($record.WasTagged) {
                    $recSuffix = $script:OsPlatformTagMap[$record.OsPlatform]
                    $recTag = if ($recSuffix) { "${TagValue}_${recSuffix}" } else { $TagValue }
                    Write-Host "      Tagged: '$recTag'" -ForegroundColor Cyan
                }
            }

            $shownCount++
        }
    }

    # Show unresolved devices
    $reviewUnresolved = @($UnresolvedDevices | Where-Object { $_.Recommendation -match "REVIEW" })
    if ($reviewUnresolved.Count -gt 0) {
        Write-Header "UNRESOLVED DEVICES (No HardwareUuid)"

        if (-not $script:advancedHuntingAvailable) {
            Write-Warn "Advanced Hunting was unavailable. All devices analyzed by staleness only."
        }
        else {
            Write-Warn "These devices had no HardwareUuid in Advanced Hunting data."
        }
        Write-Host ""

        $shownCount = 0
        foreach ($record in $reviewUnresolved) {
            if ($shownCount -ge $MaxDisplayItems) {
                Write-Host ""
                Write-Warn "Showing $MaxDisplayItems of $($reviewUnresolved.Count) unresolved devices. Check unresolved_$($Platform.ToLower())_devices.csv for full details."
                break
            }

            $color = switch -Wildcard ($record.Recommendation) {
                "REVIEW*"   { "Yellow" }
                default     { "Gray" }
            }

            Write-Host "    [$($record.Recommendation)]" -ForegroundColor $color -NoNewline
            Write-Host " $($record.ComputerDnsName) | " -NoNewline
            Write-Host "Health: $($record.HealthStatus) | " -NoNewline
            Write-Host "Last seen: $($record.DaysSinceLastSeen) days"
            Write-Host "      MDE ID: $($record.MdeDeviceId)" -ForegroundColor DarkGray

            $shownCount++
        }
    }
}
#endregion

#region --- CSV Export ---
function Export-ScanResult {
    param(
        [array]$AllResults,
        [array]$UnresolvedDevices
    )

    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    # Format DateTime fields to ISO 8601 to avoid Unicode mojibake from .NET 7+ ICU
    $formatDateTime = {
        param($record)
        $clone = $record.PSObject.Copy()
        if ($null -ne $clone.FirstSeen -and $clone.FirstSeen -ne [DateTime]::MinValue) {
            $clone.FirstSeen = ([DateTime]$clone.FirstSeen).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        }
        else {
            $clone.FirstSeen = ""
        }
        if ($null -ne $clone.LastSeen -and $clone.LastSeen -ne [DateTime]::MinValue) {
            $clone.LastSeen = ([DateTime]$clone.LastSeen).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        }
        else {
            $clone.LastSeen = ""
        }
        if ($null -ne $clone.LastLogonDate -and $clone.LastLogonDate -ne [DateTime]::MinValue) {
            $clone.LastLogonDate = ([DateTime]$clone.LastLogonDate).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        }
        else {
            $clone.LastLogonDate = ""
        }
        if ($null -ne $clone.IntuneLastSync -and $clone.IntuneLastSync -ne [DateTime]::MinValue) {
            $clone.IntuneLastSync = ([DateTime]$clone.IntuneLastSync).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        }
        else {
            $clone.IntuneLastSync = ""
        }
        return $clone
    }

    $formattedResults = @($AllResults | ForEach-Object { & $formatDateTime $_ })
    $formattedUnresolved = @($UnresolvedDevices | ForEach-Object { & $formatDateTime $_ })

    # Combine all for the full export
    $allFormatted = $formattedResults + $formattedUnresolved

    # 1. All devices (full detail)
    $pfx = $Platform.ToLower()
    $allPath = Join-Path $OutputPath "all_mde_${pfx}_devices.csv"
    $allFormatted | Export-Csv -Path $allPath -NoTypeInformation
    Write-Step "Exported all records: $allPath"

    # 2. Duplicates only
    $duplicates = @($formattedResults | Where-Object { $_.IsDuplicate })
    if ($duplicates.Count -gt 0) {
        $dupPath = Join-Path $OutputPath "duplicate_${pfx}_records.csv"
        $duplicates | Export-Csv -Path $dupPath -NoTypeInformation
        Write-Step "Exported duplicate records: $dupPath"
    }

    # 3. Tag recommendations (actionable: TAG or REVIEW)
    $tagCandidates = @($formattedResults | Where-Object { $_.Recommendation -match "TAG|REVIEW" })
    if ($tagCandidates.Count -gt 0) {
        $tagPath = Join-Path $OutputPath "tag_${pfx}_recommendations.csv"
        $tagCandidates | Select-Object HardwareUuid, SerialNumber, IMEI, ComputerDnsName, MdeDeviceId,
            OsPlatform, OsVersion, HealthStatus, OnboardingStatus, DefenderAvStatus,
            AgentVersion, LastSeen, DaysSinceLastSeen, IsStale,
            LastLogonDate, RecentLogonCount,
            MachineTags, AadDeviceId, MergedToDeviceId, MergedDeviceIds,
            IntuneDeviceId, IntuneCompliance, IntuneLastSync, IntuneEnrolled,
            GroupSize, OrphanScore, Recommendation, RecommendReason,
            ExclusionAdvice, WasTagged |
            Export-Csv -Path $tagPath -NoTypeInformation
        Write-Step "Exported tag recommendations: $tagPath"
    }

    # 4. Unresolved devices
    if ($formattedUnresolved.Count -gt 0) {
        $unresolvedPath = Join-Path $OutputPath "unresolved_${pfx}_devices.csv"
        $formattedUnresolved | Select-Object MdeDeviceId, ComputerDnsName,
            OsPlatform, OsVersion, HealthStatus, OnboardingStatus,
            LastSeen, DaysSinceLastSeen, IsStale,
            MachineTags, Recommendation, RecommendReason |
            Export-Csv -Path $unresolvedPath -NoTypeInformation
        Write-Step "Exported unresolved devices: $unresolvedPath"
    }
}
#endregion

#region --- Main Execution ---

# Pre-flight check: PowerShell 7+
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host ""
    Write-Host "[FAIL] PowerShell 7+ is required. Current version: $($PSVersionTable.PSVersion)" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Install PowerShell 7:" -ForegroundColor Yellow
    Write-Host "    https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell" -ForegroundColor Cyan
    Write-Host ""
    exit 1
}

# Pre-flight check: validate credentials
$hasSecret = -not [string]::IsNullOrEmpty($AppSecret)
$hasCertThumb = -not [string]::IsNullOrEmpty($CertificateThumbprint)
$hasCertPath = -not [string]::IsNullOrEmpty($CertificatePath)

if ([string]::IsNullOrEmpty($TenantId) -or [string]::IsNullOrEmpty($AppId) -or
    (-not $hasSecret -and -not $hasCertThumb -and -not $hasCertPath)) {

    Show-DutchCowboyBanner -Subtitle "MDE Duplicate Device Scanner"

    Write-Host "  This script scans Microsoft Defender for Endpoint for devices with" -ForegroundColor White
    Write-Host "  duplicate registrations caused by hostname changes, reimaging, or" -ForegroundColor White
    Write-Host "  offboard/re-onboard cycles." -ForegroundColor White
    Write-Host ""
    Write-Host "  Prerequisites (one-time setup, ~2 minutes):" -ForegroundColor Cyan
    Write-Host "    1. Go to portal.azure.com > App registrations > New registration" -ForegroundColor White
    Write-Host "    2. Name it (e.g. 'MDE Duplicate Scanner'), register it" -ForegroundColor White
    Write-Host "    3. Copy the 'Application (client) ID' -> that is your AppId" -ForegroundColor White
    Write-Host "    4. Create a client secret or upload a certificate" -ForegroundColor White
    Write-Host "    5. Add API permissions: Machine.Read.All, AdvancedQuery.Read.All" -ForegroundColor White
    Write-Host "       Optional: Machine.ReadWrite.All (tagging), DeviceManagementManagedDevices.Read.All (Intune)" -ForegroundColor DarkGray
    Write-Host "    6. Click 'Grant admin consent'" -ForegroundColor White
    Write-Host ""

    $guidedChoice = Read-Host "  Start guided setup? [Y/n]"
    if ($guidedChoice -match '^[Nn]') {
        Write-Host ""
        Write-Host "  Run with parameters:" -ForegroundColor Cyan
        Write-Host "    .\Find-DuplicateDefenderDevices.ps1 -TenantId '<id>' -AppId '<id>' -AppSecret '<secret>'" -ForegroundColor White
        Write-Host "    .\Find-DuplicateDefenderDevices.ps1 -TenantId '<id>' -AppId '<id>' -CertificatePath 'cert.pfx'" -ForegroundColor White
        Write-Host "    Add -Platform Windows|iOS|Android|Linux|All to scan other platforms" -ForegroundColor DarkGray
        Write-Host ""
        exit 0
    }

    # --- Guided Setup ---
    Write-Host ""
    Write-Host "  --- Platform ---" -ForegroundColor Cyan
    Write-Host "    1. macOS" -ForegroundColor White
    Write-Host "    2. Windows" -ForegroundColor White
    Write-Host "    3. iOS" -ForegroundColor White
    Write-Host "    4. Android" -ForegroundColor White
    Write-Host "    5. Linux" -ForegroundColor White
    Write-Host "    6. All platforms" -ForegroundColor White
    Write-Host ""
    $platformChoice = Read-Host "  Select platform [1-6, default=1]"
    $Platform = switch ($platformChoice) {
        "2" { "Windows" }
        "3" { "iOS" }
        "4" { "Android" }
        "5" { "Linux" }
        "6" { "All" }
        default { "macOS" }
    }

    Write-Host ""
    Write-Host "  --- Authentication ---" -ForegroundColor Cyan
    Write-Host ""

    do {
        $TenantId = Read-Host "  Tenant ID"
        if ([string]::IsNullOrEmpty($TenantId)) {
            Write-Host "  [!!] Tenant ID cannot be empty." -ForegroundColor Yellow
        }
    } while ([string]::IsNullOrEmpty($TenantId))

    do {
        $AppId = Read-Host "  App ID (client ID)"
        if ([string]::IsNullOrEmpty($AppId)) {
            Write-Host "  [!!] App ID cannot be empty." -ForegroundColor Yellow
        }
    } while ([string]::IsNullOrEmpty($AppId))

    Write-Host ""
    Write-Host "    1. Client secret" -ForegroundColor White
    Write-Host "    2. Certificate thumbprint (from local store)" -ForegroundColor White
    Write-Host "    3. Certificate file (.pfx)" -ForegroundColor White
    Write-Host ""
    $authChoice = Read-Host "  Auth method [1-3, default=1]"

    switch ($authChoice) {
        "2" {
            do {
                $CertificateThumbprint = Read-Host "  Certificate thumbprint"
                if ([string]::IsNullOrEmpty($CertificateThumbprint)) {
                    Write-Host "  [!!] Thumbprint cannot be empty." -ForegroundColor Yellow
                }
            } while ([string]::IsNullOrEmpty($CertificateThumbprint))
        }
        "3" {
            do {
                $CertificatePath = Read-Host "  Path to .pfx file"
                if ([string]::IsNullOrEmpty($CertificatePath)) {
                    Write-Host "  [!!] Path cannot be empty." -ForegroundColor Yellow
                }
            } while ([string]::IsNullOrEmpty($CertificatePath))
            Write-Host "  Copy .pfx password to clipboard (or press any key to skip if none)." -ForegroundColor White
            $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Write-Host ""
            $pfxPw = Get-Clipboard
            Set-Clipboard -Value " "
            if (-not [string]::IsNullOrWhiteSpace($pfxPw)) {
                $CertificatePassword = $pfxPw
                Write-Host "  [+] Read password from clipboard." -ForegroundColor Green
            } else {
                Write-Host "  [*] No password - continuing without." -ForegroundColor DarkGray
            }
            Remove-Variable pfxPw -Force -ErrorAction SilentlyContinue
        }
        default {
            do {
                Write-Host "  Copy the client secret to your clipboard, then press any key." -ForegroundColor White
                $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                Write-Host ""
                $AppSecret = Get-Clipboard
                Set-Clipboard -Value " "
                if ([string]::IsNullOrWhiteSpace($AppSecret)) {
                    Write-Host "  [!!] Clipboard is empty. Copy the secret first." -ForegroundColor Yellow
                    $AppSecret = ""
                } else {
                    Write-Host "  [+] Read secret from clipboard ($($AppSecret.Length) chars)." -ForegroundColor Green
                }
            } while ([string]::IsNullOrEmpty($AppSecret))
        }
    }

    Write-Host ""
    Write-Host "  --- Options ---" -ForegroundColor Cyan
    Write-Host ""

    $tagChoice = Read-Host "  Tag orphan devices in MDE portal? [y/N]"
    if ($tagChoice -match '^[Yy]') {
        $TagStaleDevices = [switch]::new($true)
        $customTag = Read-Host "  Custom tag base name (Enter for default 'StaleOrphan')"
        if (-not [string]::IsNullOrEmpty($customTag)) {
            $TagValue = $customTag
        }
        Write-Host ""
        Write-Host "    Score >= 5 = TAG (high confidence)" -ForegroundColor DarkGray
        Write-Host "    Score >= 3 = TAG + REVIEW moderate" -ForegroundColor DarkGray
        Write-Host "    Score >= 1 = TAG + all REVIEW" -ForegroundColor DarkGray
        Write-Host ""
        $threshInput = Read-Host "  Minimum score to tag (Enter for default 5)"
        if (-not [string]::IsNullOrEmpty($threshInput)) {
            $parsedThresh = 0
            if ([int]::TryParse($threshInput, [ref]$parsedThresh) -and $parsedThresh -ge 1 -and $parsedThresh -le 15) {
                $TagThreshold = $parsedThresh
            }
            else {
                Write-Host "  [!!] Invalid number (1-15), using default (5)." -ForegroundColor Yellow
            }
        }
    }

    $exclusionChoice = Read-Host "  Generate exclusion helper script? [y/N]"
    if ($exclusionChoice -match '^[Yy]') {
        $GenerateExclusionScript = [switch]::new($true)
    }

    $thresholdInput = Read-Host "  Stale threshold in days (Enter for default 30)"
    if (-not [string]::IsNullOrEmpty($thresholdInput)) {
        $parsed = 0
        if ([int]::TryParse($thresholdInput, [ref]$parsed) -and $parsed -gt 0) {
            $StaleThresholdDays = $parsed
        }
        else {
            Write-Host "  [!!] Invalid number, using default (30 days)." -ForegroundColor Yellow
        }
    }

    # Rebuild output path with updated platform
    if ($OutputPath -match 'MDE_DuplicateReport_') {
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $OutputPath = Join-Path $platformInfo.Desktop "MDE_DuplicateReport_${Platform}_$timestamp"
    }

    # Recalculate credential flags
    $hasSecret = -not [string]::IsNullOrEmpty($AppSecret)
    $hasCertThumb = -not [string]::IsNullOrEmpty($CertificateThumbprint)
    $hasCertPath = -not [string]::IsNullOrEmpty($CertificatePath)

    # Recalculate platform filter values
    if ($Platform -eq "All") {
        $script:RestPlatformValues = $null
        $script:KqlPlatformValues = $null
        $script:IntunePlatformValues = $null
    }
    else {
        $script:RestPlatformValues = $script:PlatformMap[$Platform].Rest
        $script:KqlPlatformValues = $script:PlatformMap[$Platform].Kql
        $script:IntunePlatformValues = $script:PlatformMap[$Platform].Intune
    }

    # Show recap and equivalent command
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  Configuration Summary" -ForegroundColor Green
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Platform:        $Platform" -ForegroundColor White
    Write-Host "  Tenant ID:       $TenantId" -ForegroundColor White
    Write-Host "  App ID:          $AppId" -ForegroundColor White
    $authDisplay = if ($hasSecret) { "Client secret" } elseif ($hasCertThumb) { "Certificate (thumbprint)" } else { "Certificate (.pfx)" }
    Write-Host "  Auth:            $authDisplay" -ForegroundColor White
    Write-Host "  Tag devices:     $(if ($TagStaleDevices) { "Yes (tag: '$TagValue', threshold: >= $TagThreshold)" } else { 'No' })" -ForegroundColor White
    Write-Host "  Stale threshold: $StaleThresholdDays days" -ForegroundColor White
    Write-Host "  Intune xref:     Automatic" -ForegroundColor White
    Write-Host ""

    # Build equivalent command line for future use
    $cmdParts = [System.Collections.ArrayList]::new()
    [void]$cmdParts.Add(".\Find-DuplicateDefenderDevices.ps1")
    [void]$cmdParts.Add("-TenantId '$TenantId'")
    [void]$cmdParts.Add("-AppId '$AppId'")
    if ($hasSecret) { [void]$cmdParts.Add("-AppSecret '<secret>'") }
    elseif ($hasCertThumb) { [void]$cmdParts.Add("-CertificateThumbprint '$CertificateThumbprint'") }
    else { [void]$cmdParts.Add("-CertificatePath '$CertificatePath'") }
    if ($Platform -ne "macOS") { [void]$cmdParts.Add("-Platform $Platform") }
    if ($TagStaleDevices) {
        [void]$cmdParts.Add("-TagStaleDevices")
        if ($TagThreshold -ne 5) { [void]$cmdParts.Add("-TagThreshold $TagThreshold") }
    }
    if ($StaleThresholdDays -ne 30) { [void]$cmdParts.Add("-StaleThresholdDays $StaleThresholdDays") }
    if ($GenerateExclusionScript) { [void]$cmdParts.Add("-GenerateExclusionScript") }

    Write-Host "  Equivalent command (for next time):" -ForegroundColor Cyan
    Write-Host "    $($cmdParts -join " ```n      ")" -ForegroundColor DarkGray
    Write-Host ""

    $confirm = Read-Host "  Start scan? [Y/n]"
    if ($confirm -match '^[Nn]') {
        Write-Host ""
        Write-Host "  Aborted." -ForegroundColor Yellow
        Write-Host ""
        exit 0
    }
    Write-Host ""
}

# Load certificate if certificate auth is requested
if ($hasCertThumb -or $hasCertPath) {
    try {
        if ($hasCertPath) {
            if (-not (Test-Path $CertificatePath)) {
                Write-Host ""
                Write-Host "[FAIL] Certificate file not found: $CertificatePath" -ForegroundColor Red
                Write-Host ""
                exit 1
            }

            if (-not [string]::IsNullOrEmpty($CertificatePassword)) {
                $script:Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                    (Resolve-Path $CertificatePath).Path, $CertificatePassword)
            }
            else {
                $script:Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                    (Resolve-Path $CertificatePath).Path)
            }
        }
        else {
            $store = [System.Security.Cryptography.X509Certificates.X509Store]::new("My", "CurrentUser")
            $store.Open("ReadOnly")
            $script:Certificate = $store.Certificates | Where-Object { $_.Thumbprint -eq $CertificateThumbprint } | Select-Object -First 1
            $store.Close()

            if ($null -eq $script:Certificate) {
                Write-Host ""
                Write-Host "[FAIL] Certificate with thumbprint '$CertificateThumbprint' not found in CurrentUser\My store." -ForegroundColor Red
                Write-Host ""
                Write-Host "  Verify the certificate is installed:" -ForegroundColor Yellow
                Write-Host "    Get-ChildItem Cert:\CurrentUser\My | Where-Object Thumbprint -eq '$CertificateThumbprint'" -ForegroundColor Cyan
                Write-Host ""
                exit 1
            }
        }

        if (-not $script:Certificate.HasPrivateKey) {
            Write-Host ""
            Write-Host "[FAIL] Certificate does not contain a private key." -ForegroundColor Red
            Write-Host "  Certificate auth requires the private key to sign the JWT assertion." -ForegroundColor Yellow
            Write-Host ""
            exit 1
        }

        $script:AuthMethod = "Certificate"
    }
    catch {
        Write-Host ""
        Write-Host "[FAIL] Could not load certificate." -ForegroundColor Red
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        exit 1
    }
}

# Check if output folder already exists (warn before overwriting)
if (Test-Path $OutputPath) {
    Write-Host ""
    Write-Host "[!!] Output folder already exists: $OutputPath" -ForegroundColor Yellow
    Write-Host "     Existing files will be overwritten." -ForegroundColor Yellow
    Write-Host ""
    $response = Read-Host "     Continue? [Y/n]"
    if ($response -match '^[Nn]') {
        Write-Host ""
        Write-Host "Aborted. Use -OutputPath to specify a different location." -ForegroundColor Cyan
        exit 0
    }
    Write-Host ""
}
else {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Start transcript for audit trail
$transcriptPath = Join-Path $OutputPath "scan_transcript.log"
Start-Transcript -Path $transcriptPath -Append | Out-Null

$script:scanCompleted = $false

try {
    Show-DutchCowboyBanner -Subtitle "MDE Duplicate Device Scanner"
    Write-Host "  Platform:          $Platform" -ForegroundColor Cyan
    Write-Host "  Auth method:       $($script:AuthMethod)" -ForegroundColor Cyan
    Write-Host "  Stale threshold:   $StaleThresholdDays days" -ForegroundColor Cyan
    Write-Host "  Output path:       $OutputPath" -ForegroundColor Cyan
    Write-Host "  Host OS:           $($platformInfo.Platform)" -ForegroundColor Cyan
    Write-Host "  Throttle delay:    ${ThrottleDelayMs}ms" -ForegroundColor Cyan
    Write-Host "  Tag stale devices: $(if ($TagStaleDevices) { "Enabled (tag: '${TagValue}_<platform>', threshold: >= $TagThreshold)" } else { 'Disabled' })" -ForegroundColor Cyan
    Write-Host "  Intune xref:       $(if (-not $SkipIntune) { 'Enabled (auto — use -SkipIntune to disable)' } else { 'Disabled (-SkipIntune)' })" -ForegroundColor Cyan
    Write-Host "  Exclusion script:  $(if ($GenerateExclusionScript) { 'Enabled (will generate Invoke-ExcludeDevices.ps1)' } else { 'Disabled (use -GenerateExclusionScript to enable)' })" -ForegroundColor Cyan
    Write-Host "  Console display:   $MaxDisplayItems items per section" -ForegroundColor Cyan
    Write-Host "  Transcript:        $transcriptPath" -ForegroundColor Cyan
    Write-Host ""

    # Step 1: Authenticate
    Get-MdeAccessToken

    # Step 2: Collect macOS devices via REST API
    $restDevices = Get-MdeDevices
    $script:Stats.TotalMdeDevices = $restDevices.Count

    if ($restDevices.Count -eq 0) {
        Write-Warn "No $Platform devices found in MDE. Nothing to analyze."
        $script:scanCompleted = $true
        return
    }

    # Step 3: Collect Advanced Hunting data
    $ahResults = Invoke-AdvancedHuntingQuery
    $script:Stats.AdvancedHuntingDevices = $ahResults.Count

    # Step 3b: Collect device logon activity (Tier 2)
    $activityResults = Invoke-DeviceActivityQuery

    # Step 3c: Collect Intune data (Tier 3, automatic unless -SkipIntune)
    $intuneDevices = @()
    if (-not $SkipIntune) {
        $intuneDevices = Get-IntuneDevices
    }

    # Step 4: Correlate REST + AH + activity + Intune data
    $correlation = Build-MdeCorrelationMap -RestDevices $restDevices -AhResults $ahResults `
        -ActivityResults $activityResults -IntuneDevices $intuneDevices
    $uuidGroups = $correlation.UuidGroups
    $unresolvedDevices = $correlation.Unresolved

    # Step 5: Analyze duplicate groups
    Write-Header "Analyzing Device Records"

    $duplicateGroupCount = 0
    $allAnalyzedResults = [System.Collections.ArrayList]::new()

    foreach ($uuid in $uuidGroups.Keys) {
        $group = $uuidGroups[$uuid]

        if ($group.Count -gt 1) {
            # Duplicate group — run scoring
            Get-GroupRecommendation -GroupDevices $group
            $duplicateGroupCount++
        }
        else {
            # Single device — mark as OK
            $group[0].Recommendation = "OK (No duplicates)"
        }

        foreach ($device in $group) {
            [void]$allAnalyzedResults.Add($device)
        }
    }

    $script:allResults = @($allAnalyzedResults)
    Write-Step "Analyzed $($script:allResults.Count) resolved devices across $($uuidGroups.Count) UUIDs ($duplicateGroupCount with duplicates)"

    # Step 6: Analyze unresolved devices
    if ($unresolvedDevices.Count -gt 0) {
        Write-Info "Analyzing $($unresolvedDevices.Count) unresolved devices (no HardwareUuid)..."
        Get-UnresolvedAnalysis -UnresolvedDevices $unresolvedDevices
        $script:unresolvedResults = @($unresolvedDevices)
        Write-Step "Analyzed $($unresolvedDevices.Count) unresolved devices"
    }

    # Step 7: Tag stale devices (if requested)
    if ($TagStaleDevices) {
        $tagCandidates = @($script:allResults | Where-Object {
            $_.OrphanScore -ge $TagThreshold -and $_.Recommendation -ne "KEEP (Primary)"
        })

        if ($tagCandidates.Count -gt 0) {
            $whatIfLabel = if ($WhatIfPreference) { " (WhatIf — no changes will be made)" } else { "" }
            Write-Header "Tagging Stale Devices${whatIfLabel}"
            Write-Info "Tagging $($tagCandidates.Count) device(s) with score >= $TagThreshold..."

            foreach ($candidate in $tagCandidates) {
                $platformSuffix = $script:OsPlatformTagMap[$candidate.OsPlatform]
                $deviceTag = if ($platformSuffix) { "${TagValue}_${platformSuffix}" } else { $TagValue }
                $tagged = Set-MdeDeviceTag -DeviceId $candidate.MdeDeviceId `
                    -DeviceName $candidate.ComputerDnsName -Tag $deviceTag
                $candidate.WasTagged = $tagged
            }

            if ($WhatIfPreference) {
                Write-Step "WhatIf complete: $($tagCandidates.Count) device(s) would be tagged"
            }
            else {
                Write-Step "Tagging complete: $($script:Stats.DevicesTagged) succeeded, $($script:Stats.TaggingFailed) failed"
            }
        }
        else {
            Write-Info "No devices scored high enough for tagging (threshold: OrphanScore >= $TagThreshold)"
        }
    }

    # Step 8: Console summary
    $duplicatesOnly = @($script:allResults | Where-Object { $_.IsDuplicate })
    Write-ConsoleSummary -AllResults $script:allResults `
        -DuplicatesOnly $duplicatesOnly `
        -UnresolvedDevices $script:unresolvedResults

    # Step 9: Export CSVs
    Export-ScanResult -AllResults $script:allResults -UnresolvedDevices $script:unresolvedResults

    # Step 10: Generate exclusion helper script (if requested)
    if ($GenerateExclusionScript) {
        $exclCandidates = @($script:allResults | Where-Object { $_.Recommendation -match "TAG|REVIEW" })
        if ($exclCandidates.Count -gt 0) {
            $pfx = $Platform.ToLower()
            $csvSource = Join-Path $OutputPath "tag_${pfx}_recommendations.csv"
            $scriptPath = Join-Path $OutputPath "Invoke-ExcludeDevices.ps1"
            New-ExclusionHelperScript -TagCandidates $exclCandidates `
                -ScriptOutputPath $scriptPath -CsvSourcePath $csvSource
        }
        else {
            Write-Info "No TAG/REVIEW candidates found. Exclusion script not generated."
        }
    }

    Write-Header "Scan Complete"
    Write-Host "  Results saved to: " -NoNewline
    Write-Host "$OutputPath" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Next steps:" -ForegroundColor Cyan
    $stepNum = 1
    $pfxHint = $Platform.ToLower()
    Write-Host "    $stepNum. Review 'tag_${pfxHint}_recommendations.csv' for flagged records" -ForegroundColor White
    $stepNum++
    Write-Host "    $stepNum. Review 'duplicate_${pfxHint}_records.csv' for all duplicate groups" -ForegroundColor White
    $stepNum++
    if ($script:Stats.UnresolvedDevices -gt 0) {
        Write-Host "    $stepNum. Review 'unresolved_${pfxHint}_devices.csv' for devices without HardwareUuid" -ForegroundColor White
        $stepNum++
    }
    if ($GenerateExclusionScript -and $exclCandidates.Count -gt 0) {
        Write-Host "    $stepNum. Run the generated exclusion script to exclude flagged devices from MDVM:" -ForegroundColor White
        $stepNum++
        Write-Host "       cd '$OutputPath'" -ForegroundColor DarkGray
        Write-Host "       .\Invoke-ExcludeDevices.ps1                    # Exclude OrphanScore >= 5" -ForegroundColor DarkGray
        Write-Host "       .\Invoke-ExcludeDevices.ps1 -MinOrphanScore 3  # Include moderate-confidence" -ForegroundColor DarkGray
        Write-Host "       .\Invoke-ExcludeDevices.ps1 -Action GetStatus  # Check status only" -ForegroundColor DarkGray
    }
    else {
        Write-Host "    $stepNum. In security.microsoft.com > Device inventory, select stale devices and choose 'Exclude'" -ForegroundColor White
        $stepNum++
        Write-Host "       Use justification 'Inactive device' and notes 'Stale or Orphan device'" -ForegroundColor DarkGray
        if (-not $GenerateExclusionScript) {
            Write-Host ""
            Write-Host "  TIP: Re-run with -GenerateExclusionScript to auto-generate an exclusion helper script." -ForegroundColor Cyan
            Write-Host "       The script uses XDRInternals to bulk-exclude devices via portal APIs." -ForegroundColor Cyan
        }
    }
    Write-Host "    $stepNum. Let the 180-day retention handle final removal of excluded records" -ForegroundColor White
    if (-not $TagStaleDevices) {
        Write-Host ""
        Write-Host "  TIP: Re-run with -TagStaleDevices to auto-tag high-confidence orphans." -ForegroundColor Cyan
        Write-Host "       Use -TagThreshold 3 to also include moderate-confidence devices." -ForegroundColor Cyan
        Write-Host "       Add -WhatIf to preview what would be tagged without making changes." -ForegroundColor Cyan
    }
    Write-Host ""

    $script:scanCompleted = $true
}
finally {
    if (-not $script:scanCompleted -and $script:allResults.Count -gt 0) {
        Write-Host ""
        Write-Warn "Scan interrupted - exporting partial results..."
        Export-ScanResult -AllResults $script:allResults -UnresolvedDevices $script:unresolvedResults
    }

    Stop-Transcript | Out-Null

    # Scrub sensitive variables from memory
    foreach ($varName in @('AppSecret', 'CertificatePassword', 'pfxPw')) {
        Remove-Variable $varName -Scope Script -Force -ErrorAction SilentlyContinue
        Remove-Variable $varName -Force -ErrorAction SilentlyContinue
    }
    $script:AccessToken = $null
    $script:TokenExpiry = [DateTime]::MinValue
    $script:GraphAccessToken = $null
    $script:GraphTokenExpiry = [DateTime]::MinValue
    [System.GC]::Collect()
}
#endregion
