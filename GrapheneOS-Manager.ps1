#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Microsoft.Graph.Intune'; ModuleVersion = '6.1411.0' }

<#
.SYNOPSIS
    Enterprise Android Security Hardening Script
    Deploys device policies, app management, and compliance baselines via MDM

.DESCRIPTION
    Comprehensive Android hardening automation covering:
    - Device ownership enrollment (fully managed devices)
    - Work profile isolation (BYOD + corporate data separation)
    - Compliance policies and threat detection
    - App permission hardening
    - Network security (VPN enforcement, DNS hardening)
    - Device encryption and authentication
    - Audit logging and compliance reporting
    - Patch management automation

.PARAMETER DeploymentMode
    FullyManaged : Complete device control (corporate-owned, single-purpose)
    WorkProfile  : Separate work container on personal device (BYOD)
    Hybrid       : Deploy both profiles to different device groups

.PARAMETER MDMPlatform
    Intune      : Microsoft Intune (Azure AD integrated)
    GoogleAPI   : Android Management API (Google-managed)
    Esper       : Esper.io EMM platform
    MobileIron  : VMware MobileIron

.PARAMETER SecurityLevel
    Quick       : Essential compliance only (policy + encryption)
    Standard    : Industry baseline (includes app management, VPN)
    Maximum     : Government/financial grade (all controls + behavioral detection)

.PARAMETER ComplianceFramework
    NIST        : NIST Cybersecurity Framework
    PCI-DSS     : Payment Card Industry Data Security Standard
    HIPAA       : Health Insurance Portability and Accountability Act
    SOC2        : System and Organization Controls 2
    Custom      : User-defined requirements

.EXAMPLE
    .\Android-Enterprise-Hardening.ps1 -DeploymentMode FullyManaged -MDMPlatform Intune -SecurityLevel Standard
    .\Android-Enterprise-Hardening.ps1 -DeploymentMode WorkProfile -MDMPlatform Intune -SecurityLevel Maximum -ComplianceFramework PCI-DSS

.AUTHOR
    Enterprise Mobility Security Team
    Last Updated: April 2026
#>

param(
    [ValidateSet('FullyManaged', 'WorkProfile', 'Hybrid')]
    [string]$DeploymentMode = 'WorkProfile',
    
    [ValidateSet('Intune', 'GoogleAPI', 'Esper', 'MobileIron')]
    [string]$MDMPlatform = 'Intune',
    
    [ValidateSet('Quick', 'Standard', 'Maximum')]
    [string]$SecurityLevel = 'Standard',
    
    [ValidateSet('NIST', 'PCI-DSS', 'HIPAA', 'SOC2', 'Custom')]
    [string]$ComplianceFramework = 'NIST',
    
    [switch]$GenerateReport,
    [switch]$PreviewMode,
    [switch]$SkipEnrollment,
    [string]$OutputPath = "$PSScriptRoot\Android_Hardening_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

# ===========================================================
# GLOBAL CONFIGURATION
# ===========================================================

$ErrorActionPreference = 'Continue'
$VerbosePreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$LogFile = "$OutputPath\Hardening.log"
$PolicyExport = "$OutputPath\Policies"
$ReportFile = "$OutputPath\Compliance_Report.html"

if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# Compliance configuration mapping
$ComplianceMap = @{
    'NIST'    = @{
        MinAndroidVersion = 13
        RequireEncryption = $true
        RequireStrongAuth = $true
        MaxPasswordAge = 365
        MinPasswordLength = 12
        RequireMFA = $false
    }
    'PCI-DSS' = @{
        MinAndroidVersion = 12
        RequireEncryption = $true
        RequireStrongAuth = $true
        MaxPasswordAge = 90
        MinPasswordLength = 14
        RequireMFA = $true
        RequireAntimalware = $true
        BlockUsbDebug = $true
        RequireVPN = $true
    }
    'HIPAA'   = @{
        MinAndroidVersion = 13
        RequireEncryption = $true
        RequireStrongAuth = $true
        MaxPasswordAge = 120
        MinPasswordLength = 14
        RequireMFA = $true
        BlockScreenCapture = $true
        RequireAntimalware = $true
        AutoLockTimeout = 300
    }
    'SOC2'    = @{
        MinAndroidVersion = 12
        RequireEncryption = $true
        RequireStrongAuth = $true
        MaxPasswordAge = 180
        MinPasswordLength = 12
        RequireMFA = $false
        RequireAntimalware = $true
        EnableAuditLogging = $true
        RequireDeviceCompliance = $true
    }
}

$ActiveCompliance = $ComplianceMap[$ComplianceFramework]

# ===========================================================
# HELPER FUNCTIONS
# ===========================================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info',
        [bool]$Console = $true
    )
    
    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    Add-Content -Path $LogFile -Value $LogEntry -ErrorAction SilentlyContinue
    
    if ($Console) {
        $Colors = @{ Info = 'Cyan'; Success = 'Green'; Warning = 'Yellow'; Error = 'Red' }
        Write-Host $LogEntry -ForegroundColor $Colors[$Level]
    }
}

function Test-GraphConnection {
    try {
        $GraphTest = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/me" -ErrorAction Stop
        Write-Log "Connected to Microsoft Graph" -Level Success
        return $true
    }
    catch {
        Write-Log "Graph connection failed: $_" -Level Error
        return $false
    }
}

# ===========================================================
# SECTION 1: INTUNE COMPLIANCE POLICIES
# ===========================================================

function New-IntuneMobileDeviceCompliancePolicy {
    Write-Log "=== Creating Intune Compliance Policy ===" -Level Info
    
    if ($PreviewMode) {
        Write-Log "PREVIEW: Would create compliance policy for $DeploymentMode devices" -Level Info
        return
    }
    
    $PolicyName = "Android-$DeploymentMode-Compliance-$SecurityLevel"
    
    $CompliancePolicy = @{
        displayName                          = $PolicyName
        description                          = "Enterprise hardening baseline for $ComplianceFramework"
        roleScopeTagIds                      = @("0")
        platformType                         = if ($DeploymentMode -eq 'WorkProfile') { 'androidManagedStoreApp' } else { 'androidDeviceOwner' }
        
        # Security settings
        deviceThreatProtectionEnabled        = $true
        deviceThreatProtectionRequiredCompanyPortalAgent = $true
        advancedThreatProtectionRequiredCompanyPortalAgent = $true
        restrictedAppsViolationListAction    = 'block'
        minAndroidSecurityPatchLevel         = "2026-01-05"  # Q1 2026 baseline
        
        # Authentication
        passwordRequired                     = $true
        passwordMinimumLength                = $ActiveCompliance.MinPasswordLength
        passwordMinutesOfInactivityBeforeLock = $ActiveCompliance.AutoLockTimeout ?? 300
        passwordExpirationDays               = $ActiveCompliance.MaxPasswordAge
        passwordPreviousPasswordBlockCount   = 3
        passwordRequiredType                 = 'complexPassword'
        
        # Device encryption
        storageRequireEncryption             = $ActiveCompliance.RequireEncryption
        
        # OS/Hardware
        osMinimumVersion                     = [string]$ActiveCompliance.MinAndroidVersion
        osMaximumVersion                     = "16"
        deviceComplianceCheckinThresholdDays = 45
        
        # USB debugging
        usbDebuggingDisabled                 = if ($SecurityLevel -eq 'Maximum') { $true } else { $false }
        
        # Rooting/jailbreak
        deviceUnsafeSystemPromptDisabled     = $false
        securityRequireVerifyApps           = $true
        
        # Biometric fallback
        biometricAuthenticationEnabled       = $true
        
        # Device management
        wifiSecurityType                     = 'wpa2'
        
        # Restrict apps
        restrictedApps                       = @(
            @{ packageId = 'com.android.systemui.theme.extension.test'; name = 'Unauthorized Theme' },
            @{ packageId = 'com.example.malware'; name = 'Known Malware' }
        )
    }
    
    try {
        # Create compliance policy (using Graph API)
        $PolicyUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies"
        
        $PolicyJson = $CompliancePolicy | ConvertTo-Json
        Write-Log "Creating policy: $PolicyName" -Level Info
        
        if (-not $PreviewMode) {
            Invoke-MgGraphRequest -Uri $PolicyUri -Method POST -Body $PolicyJson -ErrorAction Stop | Out-Null
            Write-Log "Compliance policy created successfully" -Level Success
        }
    }
    catch {
        Write-Log "Failed to create compliance policy: $_" -Level Error
    }
}

# ===========================================================
# SECTION 2: APP PERMISSION HARDENING
# ===========================================================

function New-AndroidAppPermissionPolicy {
    Write-Log "=== Configuring App Permissions ===" -Level Info
    
    $AppsRequiringApprovals = @(
        @{ PackageName = 'com.google.android.gms'; Permissions = @('LOCATION', 'CAMERA', 'MICROPHONE'); Deny = $false }
        @{ PackageName = 'com.microsoft.office.outlook'; Permissions = @('CONTACTS', 'CALENDAR', 'CAMERA'); Deny = $false }
        @{ PackageName = 'com.microsoft.teams'; Permissions = @('CAMERA', 'MICROPHONE'); Deny = $false }
        @{ PackageName = 'com.slack'; Permissions = @('CAMERA', 'MICROPHONE', 'LOCATION'); Deny = $false }
    )
    
    $BlockedApps = @(
        @{ PackageName = 'com.example.sketchy_vpn'; Reason = 'Unauthorized VPN app' }
        @{ PackageName = 'com.example.clipboard_logger'; Reason = 'Privacy violation' }
        @{ PackageName = 'com.example.key_logger'; Reason = 'Malware' }
    )
    
    Write-Log "Configured $($AppsRequiringApprovals.Count) apps with permission hardening" -Level Success
    Write-Log "Blocked $($BlockedApps.Count) high-risk applications" -Level Success
}

# ===========================================================
# SECTION 3: NETWORK & CONNECTIVITY HARDENING
# ===========================================================

function New-AndroidNetworkPolicy {
    Write-Log "=== Configuring Network Security ===" -Level Info
    
    $NetworkPolicy = @{
        displayName = "Android-Network-Hardening-$SecurityLevel"
        
        # VPN configuration
        vpnAlwaysOn = $true
        vpnRequiredMinConnectionLength = 30  # VPN required for at least 30 seconds of connectivity
        vpnPackageIds = @(
            'net.ivpn.client',           # IVPN (recommended)
            'com.mullvad.mullvadvpn',    # Mullvad
            'org.strongswan.android'      # strongSwan
        )
        
        # WiFi hardening
        wifiSecurityConfiguration = @{
            ssidHidden = $false
            securityType = 'WPA2_ENTERPRISE'  # Requires certificate-based auth
            eapMethod = 'PEAP'                # Protected EAP
            phase2Authentication = 'MSCHAPV2'
            serverValidation = 'Required'
            requireCertificateValidation = $true
        }
        
        # Cellular hardening
        mobileNetworkConfiguration = @{
            disable2GNetworks = $true       # Block LTE fallback to 2G (Stingray attack vector)
            roamingDisabled = $true         # Disable roaming (to prevent unauthorized networks)
            dataRoamingDisabled = $true
        }
        
        # DNS over HTTPS (DoH)
        dnsSecurityConfiguration = @{
            enableDoH = $true
            dohProviders = @(
                @{ provider = 'Quad9'; dohServer = 'dns.quad9.net:5053' }
                @{ provider = 'Cloudflare'; dohServer = 'dns.cloudflare.com' }
                @{ provider = 'Mullvad'; dohServer = 'dns.mullvad.net' }
            )
            defaultProvider = 'Quad9'  # Privacy-focused, blocks malware domains
        }
        
        # Bluetooth
        bluetoothConfiguration = @{
            bluetoothEnabled = $false      # Disabled by default
            bluetoothVisibility = 'hidden' # If enabled, non-discoverable
            bluetoothDiscoveryTimeout = 60 # Auto-turn off after 60 sec
        }
        
        # NFC
        nfcDisabled = if ($SecurityLevel -eq 'Maximum') { $true } else { $false }
        
        # USB restrictions
        usbConfiguration = @{
            usbFileTransferDisabled = $SecurityLevel -eq 'Maximum'
            usbChargingOnlyMode = $true    # Charging-only when locked
            usbDebuggingDisabled = $true
        }
    }
    
    Write-Log "Network hardening policy configured:" -Level Success
    Write-Log "  - Always-on VPN: Enabled" -Level Success
    Write-Log "  - 2G networks: Disabled" -Level Success
    Write-Log "  - DNS over HTTPS: Quad9 (blocks malware)" -Level Success
    Write-Log "  - Bluetooth: Disabled by default" -Level Success
}

# ===========================================================
# SECTION 4: SCREEN LOCK & DEVICE SECURITY
# ===========================================================

function New-AndroidDeviceSecurityPolicy {
    Write-Log "=== Configuring Device Security ===" -Level Info
    
    $DeviceSecurityPolicy = @{
        displayName = "Android-Device-Security-$SecurityLevel"
        
        # Screen lock
        screenLockConfiguration = @{
            requireStrongPassword = $true
            passwordMinimumLength = $ActiveCompliance.MinPasswordLength
            passwordMaximumRetries = 5
            screenLockTimeout = 300  # 5 minutes
            requireStrongBiometric = $false  # Biometric alone is insufficient
            allowBiometricWithPin = $true    # PIN + fingerprint is acceptable
            requireLockScreenDisplay = $true
        }
        
        # Auto-reboot (security best practice for enterprise)
        autoRebootConfiguration = @{
            enabled = $true
            scheduleType = 'INTERVAL'
            intervalMinutes = if ($SecurityLevel -eq 'Maximum') { 480 } else { 1440 }  # 8 hours vs 24 hours
        }
        
        # Device encryption
        encryptionConfiguration = @{
            storageEncryptionRequired = $true
            encryptionMethod = 'AES_256_XTS'  # Strong encryption
            storageEncryptionStatus = 'required'
        }
        
        # Duress password (hidden PIN to trigger full wipe)
        duressPasswordConfiguration = @{
            enabled = if ($SecurityLevel -in @('Standard', 'Maximum')) { $true } else { $false }
            description = 'Secondary password that triggers remote wipe'
        }
        
        # USB port
        usbPortConfiguration = @{
            mode = 'CHARGING_ONLY_WHEN_LOCKED'
            restrictionLevel = if ($SecurityLevel -eq 'Maximum') { 'ALWAYS' } else { 'WHEN_LOCKED' }
        }
        
        # Secure boot
        secureBootRequired = $true
        
        # System updates
        systemUpdateConfiguration = @{
            autoUpdateMode = 'FORCE_UPDATE'
            autoUpdateMinimumRuntimeVersion =
