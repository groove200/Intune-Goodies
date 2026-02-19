###############################################################################
# New-MdeAppRegistration.ps1
#
# Creates an Azure App Registration with the required WindowsDefenderATP
# permissions for Find-DuplicateDefenderDevices.ps1.
#
# Author:  Oktay Sari (allthingscloud.blog)
# Date:    2026-02-14
# Version: 1.0
#
# REQUIREMENTS:
#   - PowerShell 7+
#   - Microsoft.Graph module (Install-Module Microsoft.Graph)
#   - Global Administrator or Application Administrator role
#
# USAGE:
#   .\New-MdeAppRegistration.ps1
#   .\New-MdeAppRegistration.ps1 -AppName "My MDE Scanner"
#   .\New-MdeAppRegistration.ps1 -IncludeWritePermission    # adds Machine.ReadWrite.All for tagging
#   .\New-MdeAppRegistration.ps1 -IncludeIntunePermission  # adds Graph permission for Intune xref (recommended, enabled by default in scanner)
#   .\New-MdeAppRegistration.ps1 -IncludeWritePermission -IncludeIntunePermission  # both
#
# CODE QUALITY:
#   This script passes PSScriptAnalyzer static analysis.
#   Run: Invoke-ScriptAnalyzer -Path New-MdeAppRegistration.ps1
#
#   Intentional suppressions:
#   - PSAvoidUsingWriteHost: Interactive script requires colored console output
#
# DISCLAIMER:
#   This script is provided "AS IS", without warranty of any kind.
#   It creates an App Registration with API permissions in your tenant.
#   Review the permissions before granting admin consent.
#   USE AT YOUR OWN RISK.
#
###############################################################################

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'Interactive script requires colored console output')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseBOMForUnicodeEncodedFile', '',
    Justification = 'File is pure ASCII; BOM not required')]
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Display name for the App Registration")]
    [string]$AppName = "MDE Duplicate Scanner",

    [Parameter(Mandatory = $false, HelpMessage = "Include Machine.ReadWrite.All for tagging devices")]
    [switch]$IncludeWritePermission,

    [Parameter(Mandatory = $false, HelpMessage = "Include Microsoft Graph DeviceManagementManagedDevices.Read.All for Intune cross-reference")]
    [switch]$IncludeIntunePermission,

    [Parameter(Mandatory = $false, HelpMessage = "Secret validity in years")]
    [ValidateRange(1, 2)]
    [int]$SecretValidityYears = 1
)

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

function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Green
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
}
#endregion

#region --- Pre-flight ---
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host ""
    Write-Host "[FAIL] PowerShell 7+ is required." -ForegroundColor Red
    Write-Host ""
    exit 1
}

$requiredModule = "Microsoft.Graph.Applications"
if (-not (Get-Module -ListAvailable -Name $requiredModule)) {
    Write-Host ""
    Write-Host "[FAIL] Required module '$requiredModule' is not installed." -ForegroundColor Red
    Write-Host ""
    Write-Host "  Install it by running:" -ForegroundColor Yellow
    Write-Host "    Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Cyan
    Write-Host ""
    exit 1
}
#endregion

#region --- Main ---
Write-Header "MDE App Registration Setup"

# Step 1: Connect to Graph with required scopes
Write-Host "  Connecting to Microsoft Graph..." -ForegroundColor Cyan
Write-Host "  You will be prompted to sign in with an admin account." -ForegroundColor DarkGray
Write-Host ""

$scopes = @(
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All"
)

try {
    Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
    $context = Get-MgContext
    Write-Step "Connected to tenant: $($context.TenantId)"
}
catch {
    Write-Host ""
    Write-Host "[FAIL] Could not connect to Microsoft Graph." -ForegroundColor Red
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "  You need Global Administrator or Application Administrator role." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

# Step 2: Look up WindowsDefenderATP service principal
$wdatpAppId = "fc780465-2017-40d4-a0c5-307022471b92"
$wdatpSp = Get-MgServicePrincipal -Filter "appId eq '$wdatpAppId'" -ErrorAction SilentlyContinue

if ($null -eq $wdatpSp) {
    Write-Host ""
    Write-Host "[FAIL] WindowsDefenderATP service principal not found in your tenant." -ForegroundColor Red
    Write-Host ""
    Write-Host "  This means Microsoft Defender for Endpoint is not provisioned." -ForegroundColor Yellow
    Write-Host "  Ensure you have an MDE P1 or P2 license assigned." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}
Write-Step "Found WindowsDefenderATP service principal"

# Step 3: Resolve required app roles
$requiredRoles = @("Machine.Read.All", "AdvancedQuery.Read.All")
if ($IncludeWritePermission) {
    $requiredRoles += "Machine.ReadWrite.All"
}

$appRoles = @()
foreach ($roleName in $requiredRoles) {
    $role = $wdatpSp.AppRoles | Where-Object { $_.Value -eq $roleName }
    if ($null -eq $role) {
        Write-Warn "App role '$roleName' not found on WindowsDefenderATP. Skipping."
        continue
    }
    $appRoles += $role
}

if ($appRoles.Count -eq 0) {
    Write-Host ""
    Write-Host "[FAIL] No valid app roles found. Cannot continue." -ForegroundColor Red
    Write-Host ""
    exit 1
}

Write-Step "Resolved $($appRoles.Count) app role(s): $($appRoles.Value -join ', ')"

# Step 3b: Resolve Microsoft Graph permissions (if Intune cross-reference requested)
$graphAppRoles = @()
if ($IncludeIntunePermission) {
    $graphAppId = "00000003-0000-0000-c000-000000000000"
    $graphSp = Get-MgServicePrincipal -Filter "appId eq '$graphAppId'" -ErrorAction SilentlyContinue

    if ($null -eq $graphSp) {
        Write-Warn "Microsoft Graph service principal not found. Skipping Intune permission."
    }
    else {
        $intuneRole = $graphSp.AppRoles | Where-Object { $_.Value -eq "DeviceManagementManagedDevices.Read.All" }
        if ($null -eq $intuneRole) {
            Write-Warn "DeviceManagementManagedDevices.Read.All role not found on Microsoft Graph. Skipping."
        }
        else {
            $graphAppRoles += $intuneRole
            Write-Step "Resolved Graph permission: DeviceManagementManagedDevices.Read.All"
        }
    }
}

# Step 4: Create the App Registration
$resourceAccess = $appRoles | ForEach-Object {
    @{ Id = $_.Id; Type = "Role" }
}

$allResourceAccess = @(
    @{
        ResourceAppId  = $wdatpAppId
        ResourceAccess = @($resourceAccess)
    }
)

if ($graphAppRoles.Count -gt 0) {
    $graphResourceAccess = $graphAppRoles | ForEach-Object {
        @{ Id = $_.Id; Type = "Role" }
    }
    $allResourceAccess += @{
        ResourceAppId  = $graphAppId
        ResourceAccess = @($graphResourceAccess)
    }
}

try {
    $app = New-MgApplication `
        -DisplayName $AppName `
        -RequiredResourceAccess $allResourceAccess `
        -SignInAudience "AzureADMyOrg" `
        -ErrorAction Stop

    Write-Step "Created App Registration: '$AppName' (AppId: $($app.AppId))"
}
catch {
    Write-Host ""
    Write-Host "[FAIL] Could not create App Registration." -ForegroundColor Red
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    exit 1
}

# Step 5: Create a client secret
try {
    $secretCredential = @{
        DisplayName = "MDE Scanner Secret"
        EndDateTime = (Get-Date).AddYears($SecretValidityYears)
    }

    $secret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential $secretCredential -ErrorAction Stop
    Write-Step "Created client secret (expires: $($secret.EndDateTime.ToString('yyyy-MM-dd')))"
}
catch {
    Write-Host ""
    Write-Host "[FAIL] Could not create client secret." -ForegroundColor Red
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  App '$AppName' was created but has no secret. Add one manually in the portal." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

# Step 6: Create service principal for the app
try {
    $sp = New-MgServicePrincipal -AppId $app.AppId -ErrorAction Stop
    Write-Step "Created service principal"
}
catch {
    Write-Host ""
    Write-Host "[FAIL] Could not create service principal." -ForegroundColor Red
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    exit 1
}

# Step 7: Grant admin consent (app role assignments)
Write-Host ""
Write-Host "  Granting admin consent for API permissions..." -ForegroundColor Cyan

$consentErrors = 0
foreach ($role in $appRoles) {
    try {
        New-MgServicePrincipalAppRoleAssignment `
            -ServicePrincipalId $sp.Id `
            -PrincipalId $sp.Id `
            -ResourceId $wdatpSp.Id `
            -AppRoleId $role.Id `
            -ErrorAction Stop | Out-Null

        Write-Step "  Granted: $($role.Value)"
    }
    catch {
        Write-Warn "  Failed to grant $($role.Value): $($_.Exception.Message)"
        $consentErrors++
    }
}

# Grant Graph permissions (Intune)
if ($graphAppRoles.Count -gt 0) {
    foreach ($role in $graphAppRoles) {
        try {
            New-MgServicePrincipalAppRoleAssignment `
                -ServicePrincipalId $sp.Id `
                -PrincipalId $sp.Id `
                -ResourceId $graphSp.Id `
                -AppRoleId $role.Id `
                -ErrorAction Stop | Out-Null

            Write-Step "  Granted: $($role.Value) (Microsoft Graph)"
        }
        catch {
            Write-Warn "  Failed to grant $($role.Value): $($_.Exception.Message)"
            $consentErrors++
        }
    }
}

if ($consentErrors -gt 0) {
    Write-Warn "$consentErrors permission(s) could not be granted. Grant them manually in the Azure portal."
}

# Step 8: Output credentials
Write-Header "App Registration Complete"

Write-Host "  App name:     $AppName" -ForegroundColor White
Write-Host "  Permissions:  $($appRoles.Value -join ', ')" -ForegroundColor White
Write-Host "  Secret valid: until $($secret.EndDateTime.ToString('yyyy-MM-dd'))" -ForegroundColor White
Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Green
Write-Host ""
Write-Host "  Copy these values to run the scanner:" -ForegroundColor Cyan
Write-Host ""
Write-Host "  TenantId:   $($context.TenantId)" -ForegroundColor Yellow
Write-Host "  AppId:      $($app.AppId)" -ForegroundColor Yellow
Write-Host "  AppSecret:  $($secret.SecretText)" -ForegroundColor Yellow
Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Green
Write-Host ""
Write-Host "  Run the scanner:" -ForegroundColor Cyan
Write-Host "  .\Find-DuplicateDefenderDevices.ps1 ``" -ForegroundColor White
Write-Host "      -TenantId '$($context.TenantId)' ``" -ForegroundColor White
Write-Host "      -AppId '$($app.AppId)' ``" -ForegroundColor White
Write-Host "      -AppSecret '$($secret.SecretText)'" -ForegroundColor White
Write-Host ""
Write-Warn "Save the AppSecret now — it cannot be retrieved again after this screen."
Write-Host ""
#endregion
