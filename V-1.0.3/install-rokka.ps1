<#
.SYNOPSIS
    Aarkam Rokka Sovereign Storage Engine (v1.0.3-GA) — Automated Production Installation & Bootstrap Script for Windows Server.

.DESCRIPTION
    Automates the production deployment of the Aarkam Rokka Sovereign Storage Engine (v1.0.3-GA)
    on Windows Server 2022 / Windows Server 2025 (and Windows 10/11 Enterprise/Pro x64 for evaluation).
    Deploys both standalone sovereign daemons and registers them following the Aarkam V2 service naming structure:
    - 'Aarkam.Rokka'         (rokka-coordinator.exe: Control Plane, Raft MON Quorum, HRW Placement & Node Enrollment CA)
                             Default Endpoint: https://rokka-coordinator.aarkam:57774 (HTTPS/mTLS :57774, gRPC :7774)
    - 'Aarkam.Rokka.Gateway' (rokka-gateway.exe: Sovereign Data Gateway, AES-256-GCM Envelope Encryption & Ahmodi SIMD Cauchy RS)
                             Default Endpoint: https://rokka-gateway.aarkam:57772 (HTTPS :57772, HTTP :7772)

    Key Capabilities & Pre-Flight Checks:
    - Validates Ecosystem Version Compatibility Matrix (Aarkam.Rokka v1.0.3, Aarkam.Rokka.Gateway v1.0.3,
      Aarkam.Abodi v1.0.3+, Aarkam.Kdouja SAT v1.0.2, Aarkam.Kdouja.SDK v1.0.1, Aarkam.Kdouja.Primitives v1.0.6,
      Aarkam.Ahmodi v1.0.1, Aarkam.AM CLI v1.0.2+).
    - Computes and prints the deterministic Rokka Coordinator Footprint (ARK-FP-XXXXXXXX-XXXXXXXX-XXXXXXXX)
      and hardware diagnostic profile (Host, CPU/Arch, RAM, Disk Count, Machine GUID, Primary Physical MAC)
      required to bind and activate the Rokka cluster on AarkamCP (https://aarkam.io/Administration/Auth/Login).
    - Resolves ClusterCode from CLI (-ClusterCode), existing coordinator.settings.json, or auto-generates a
      15-character sovereign identifier (XXXX-XXXX-XXXXX, 4-4-5 format with >=1 digit per segment).
    - Provisions 256-bit cryptographic keys (ROKKA_MASTER_KEY, ROKKA_WAL_ENCRYPTION_KEY, ROKKA_CLUSTER_CA_PASSWORD,
      ROKKA_CLUSTER_SECRET) strictly via Windows Machine/User environment variables (zero plaintext secrets in JSON, CWE-312).
    - Bootstraps the Zero-Trust ECDSA P-256 Cluster Root CA (ca.pfx / ca.crt) and Server TLS certificate
      (rokka-server-tls.pfx) inside the NTFS-ACL protected security vault (C:\ProgramData\Rokka\Security).
    - Registers and starts the 'Aarkam.Rokka' and 'Aarkam.Rokka.Gateway' Windows Services (migrating and cleaning up
      any legacy 'Rokka.Coordinator' / 'Rokka.Gateway' service registrations) and verifies /health probes.
    - Prints the complete Rokka Cluster Activation & Sovereign Genesis Ceremony summary after installation.

.PARAMETER ClusterCode
    Unique identifier for this Rokka cluster (e.g., "ARK-PROD-RYD-01"). If omitted, checks existing config or auto-generates XXXX-XXXX-XXXXX.

.PARAMETER RokkaUrl
    Rokka Coordinator endpoint URL. If omitted, defaults to "https://rokka-coordinator.aarkam:57774" (or uses -CoordinatorHttpsPort if customized).

.PARAMETER GatewayUrl
    Rokka Gateway endpoint URL. If omitted, defaults to "https://rokka-gateway.aarkam:57772" (or uses -GatewayHttpsPort if customized).

.PARAMETER TrustDomain
    Zero-Trust SPIFFE trust domain (default: "aarkam.cluster").

.PARAMETER Role
    Deployment role on this host: "All" (default: both Aarkam.Rokka and Aarkam.Rokka.Gateway), "Coordinator" (Aarkam.Rokka only), or "Gateway" (Aarkam.Rokka.Gateway only).

.PARAMETER CoordinatorPort
    Coordinator internal HTTP/2 gRPC & health probe port (default: 7774).

.PARAMETER CoordinatorHttpsPort
    Coordinator HTTPS / mTLS control plane & Raft quorum port (default: 57774).

.PARAMETER GatewayPort
    Gateway HTTP REST ingress port (default: 7772).

.PARAMETER GatewayHttpsPort
    Gateway HTTPS REST ingress port (default: 57772).

.PARAMETER DefaultStoragePolicy
    Default Ahmodi Cauchy Reed-Solomon erasure coding profile (default: "4+2"; supports "4+2", "8+3", "8+4", "16+4").

.PARAMETER InstallDir
    Target installation directory for binaries and configuration (default: "C:\Program Files\Aarkam\Rokka").

.PARAMETER DataDir
    Target directory for Kdouja LSM metadata, S3 catalog, security vault, and logs (default: "C:\ProgramData\Rokka").

.PARAMETER SourcePath
    Path to pre-published Rokka binaries, a release .zip archive (rokka-v1.0.3-win-x64.zip), or repository root.

.PARAMETER MasterKey
    64-character hexadecimal AES-256 master key (ROKKA_MASTER_KEY). If omitted, preserves existing Machine key or generates a new CSPRNG key.

.PARAMETER WalKey
    64-character hexadecimal AES-256 Kdouja WAL key (ROKKA_WAL_ENCRYPTION_KEY). If omitted, preserves existing key or generates a new CSPRNG key.

.PARAMETER CaPassword
    Cryptographic passphrase protecting the internal ECDSA P-256 Cluster Root CA (ROKKA_CLUSTER_CA_PASSWORD).

.PARAMETER ClusterSecret
    64-character hexadecimal secret for Raft quorum authentication and local operator JWT signing (ROKKA_CLUSTER_SECRET).

.PARAMETER S3AccessKeyId
    Root S3 SigV4 Access Key ID for Rokka Gateway (default: "rokka_admin").

.PARAMETER RotateKeys
    Switch to force generation of fresh cryptographic keys even if existing ROKKA_* environment variables are present.

.PARAMETER ResetMetadata
    Switch to clear existing Coordinator metadata (wal/pages) and Gateway catalog directories before starting (use on fresh re-install when existing WAL was encrypted with a different key).

.PARAMETER StartServices
    Switch to start Aarkam.Rokka and Aarkam.Rokka.Gateway Windows Services after installation (enabled by default unless -SkipStartServices is specified).

.PARAMETER SkipStartServices
    Switch to register Windows Services without starting them immediately.

.PARAMETER SkipFirewall
    Switch to skip Windows Defender Firewall rule creation.

.PARAMETER UserOnly
    Switch to install in user profile (%LOCALAPPDATA%\Aarkam\Rokka) without Administrator privileges or Windows Service registration.

.PARAMETER CheckOnly
    Switch to run pre-flight system requirements, version compatibility, and Rokka Coordinator Footprint checks without modifying the system.

.EXAMPLE
    .\install-rokka.ps1

.EXAMPLE
    .\install-rokka.ps1 -ClusterCode "ARK-PROD-RYD-01" -RokkaUrl "https://rokka-coordinator.aarkam:57774" -StartServices

.EXAMPLE
    .\install-rokka.ps1 -CheckOnly
#>

[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$ClusterCode = "",
    [string]$RokkaUrl = "",
    [string]$GatewayUrl = "",
    [string]$TrustDomain = "aarkam.cluster",
    [ValidateSet("All", "Coordinator", "Gateway")]
    [string]$Role = "All",
    [int]$CoordinatorPort = 7774,
    [int]$CoordinatorHttpsPort = 57774,
    [int]$GatewayPort = 7772,
    [int]$GatewayHttpsPort = 57772,
    [ValidateSet("4+2", "8+3", "8+4", "16+4")]
    [string]$DefaultStoragePolicy = "4+2",
    [string]$InstallDir = "",
    [string]$DataDir = "C:\ProgramData\Rokka",
    [string]$SourcePath = "",
    [string]$MasterKey = "",
    [string]$WalKey = "",
    [string]$CaPassword = "",
    [string]$ClusterSecret = "",
    [string]$S3AccessKeyId = "rokka_admin",
    [switch]$RotateKeys,
    [switch]$ResetMetadata,
    [switch]$StartServices,
    [switch]$SkipStartServices,
    [switch]$SkipFirewall,
    [switch]$UserOnly,
    [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"

# ------------------------------------------------------------------------------
# Aarkam V2 Standardized Service Names & Ecosystem Matrix Constants
# ------------------------------------------------------------------------------
$CoordinatorServiceName       = "Aarkam.Rokka"
$GatewayServiceName           = "Aarkam.Rokka.Gateway"
$LegacyCoordinatorServiceName = "Rokka.Coordinator"
$LegacyGatewayServiceName     = "Rokka.Gateway"

$RokkaReleaseVersion          = "1.0.3"
$RequiredAbodiMinVersion      = "1.0.3"
$RequiredKdoujaSatVersion     = "1.0.2"
$RequiredKdoujaSdkVersion     = "1.0.1"
$RequiredKdoujaPrimVersion    = "1.0.6"
$RequiredAhmodiVersion        = "1.0.1"
$RequiredAmCliMinVersion      = "1.0.2"
$RequiredDotNetMajor          = 10

$AarkamCpLoginUrl             = "https://aarkam.io/Administration/Auth/Login"
$AarkamCpSubscriptionUrl      = "https://aarkam.io/Administration/CurrentSubscription"

function Write-Info  { param([string]$Message) Write-Host "[INFO]  $Message" -ForegroundColor Cyan }
function Write-Ok    { param([string]$Message) Write-Host "[OK]    $Message" -ForegroundColor Green }
function Write-Warn  { param([string]$Message) Write-Host "[WARN]  $Message" -ForegroundColor Yellow }
function Write-Err   { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

# ------------------------------------------------------------------------------
# Helper: Generate Random 15-Char ClusterCode (XXXX-XXXX-XXXXX, >=1 digit per part)
# ------------------------------------------------------------------------------
function New-RandomRokkaCodePart {
    param([int]$Length)
    $chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray()
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $buf = New-Object byte[] $Length
        while ($true) {
            $rng.GetBytes($buf)
            $sb = New-Object System.Text.StringBuilder $Length
            for ($i = 0; $i -lt $Length; $i++) {
                [void]$sb.Append($chars[$buf[$i] % $chars.Length])
            }
            $candidate = $sb.ToString()
            if ($candidate -match '[0-9]' -and $candidate -match '[A-Z]') {
                return $candidate
            }
        }
    } finally {
        if ($null -ne $rng) { $rng.Dispose() }
    }
}

function New-RandomRokkaClusterCode {
    $p1 = New-RandomRokkaCodePart -Length 4
    $p2 = New-RandomRokkaCodePart -Length 4
    $p3 = New-RandomRokkaCodePart -Length 5
    return "$p1-$p2-$p3"
}

function Get-ConfiguredClusterCodeFromSettings {
    param([string[]]$CandidateFiles)
    foreach ($file in $CandidateFiles) {
        if ([string]::IsNullOrWhiteSpace($file) -or -not (Test-Path $file -PathType Leaf)) {
            continue
        }
        try {
            $raw = Get-Content -Path $file -Raw -ErrorAction Stop
            if ([string]::IsNullOrWhiteSpace($raw)) { continue }
            $obj = $raw | ConvertFrom-Json -ErrorAction Stop
            $candidates = @(
                $obj.Cluster.ClusterCode,
                $obj.Rokka.ClusterCode,
                $obj.Aarkam.ClusterCode
            )
            foreach ($val in $candidates) {
                if (-not [string]::IsNullOrWhiteSpace($val)) {
                    $trimmed = ([string]$val).Trim()
                    if ($trimmed -ine "YOUR_CLUSTER_CODE" -and
                        $trimmed -ine "CLUSTER-PLACEHOLDER" -and
                        $trimmed -match '^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$') {
                        return @{
                            ClusterCode = $trimmed
                            SourceFile  = $file
                        }
                    }
                }
            }
        } catch { }
    }
    return $null
}

# ------------------------------------------------------------------------------
# Helper: Generate 64-Character Hex Cryptographic Key (256-Bit CSPRNG)
# ------------------------------------------------------------------------------
function New-RandomHexKey256 {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        if ($null -ne $rng) { $rng.Dispose() }
    }
    return (($bytes | ForEach-Object { "{0:X2}" -f $_ }) -join "")
}

# ------------------------------------------------------------------------------
# Helper: Compute Deterministic Rokka Coordinator Footprint (ARK-FP-*)
# Matches Rokka.Common.Security.ClusterHardwareProfiler.GetClusterFingerprint()
# ------------------------------------------------------------------------------
function Get-RokkaCoordinatorFootprint {
    param(
        [string]$OsCaption,
        [int]$PhysicalCores,
        [int]$LogicalProcessors,
        [double]$TotalRamGB,
        [int]$PhysicalDiskCount
    )

    $machineName = [System.Environment]::MachineName
    $procCount   = [System.Environment]::ProcessorCount
    $osArch      = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToUpperInvariant()
    $osDesc      = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
    if ([string]::IsNullOrWhiteSpace($osDesc)) { $osDesc = $OsCaption }

    # 1. Primary Physical MAC Address (matches ClusterHardwareProfiler.GetPrimaryMacAddress)
    $primaryMac = "00155D000001"
    $formattedMac = "00:15:5D:00:00:01"
    try {
        $nics = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
        foreach ($nic in $nics) {
            if ($nic.OperationalStatus -eq [System.Net.NetworkInformation.OperationalStatus]::Up -and
                $nic.NetworkInterfaceType -ne [System.Net.NetworkInformation.NetworkInterfaceType]::Loopback -and
                $nic.NetworkInterfaceType -ne [System.Net.NetworkInformation.NetworkInterfaceType]::Tunnel) {
                $addrBytes = $nic.GetPhysicalAddress().GetAddressBytes()
                if ($null -ne $addrBytes -and $addrBytes.Length -gt 0) {
                    $primaryMac = ([System.BitConverter]::ToString($addrBytes) -replace '-', '').ToUpperInvariant()
                    $formattedMac = ([System.BitConverter]::ToString($addrBytes) -replace '-', ':').ToUpperInvariant()
                    break
                }
            }
        }
    } catch { }

    # 2. System Machine ID (matches ClusterHardwareProfiler.GetSystemMachineId on Windows)
    $machineId = if (-not [string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) { $env:COMPUTERNAME } else { $machineName }
    $osMachineGuid = ""
    try {
        $osMachineGuid = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name "MachineGuid" -ErrorAction Stop).MachineGuid
    } catch { }

    # 3. Official Aarkam Root Public Key (matches SovereignLicenseVerifier.OfficialAarkamRootPublicKeyBytes)
    $officialRootPubKey = [byte[]]@(
        0x30, 0x82, 0x02, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
        0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0F, 0x00, 0x30, 0x82, 0x02, 0x0A, 0x02, 0x82, 0x02, 0x01,
        0x00, 0xC2, 0x8D, 0x69, 0x15, 0x05, 0x4C, 0xC6, 0x7E, 0x58, 0x87, 0xA6, 0xE1, 0x03, 0x5A, 0x37,
        0x6D, 0xB5, 0x7C, 0xE2, 0x90, 0xE7, 0xA4, 0x54, 0x55, 0xD4, 0xE8, 0x23, 0xD2, 0xA3, 0x43, 0x96,
        0xDC, 0x5F, 0x15, 0x50, 0x71, 0xC9, 0x0E, 0x95, 0xCB, 0xE4, 0x29, 0xF7, 0x17, 0x7B, 0x7B, 0x35,
        0xA3, 0xF0, 0x33, 0xE4, 0x50, 0x9F, 0x65, 0xEE, 0x30, 0xC4, 0xA4, 0x0F, 0x17, 0x0D, 0xBC, 0x21,
        0x36, 0x25, 0x7B, 0x39, 0x39, 0x9C, 0xDC, 0xE4, 0xA7, 0xFA, 0xEA, 0x53, 0xCC, 0x49, 0xE5, 0x30,
        0x71, 0x6B, 0x54, 0x15, 0x02, 0x73, 0xE2, 0xCB, 0x76, 0xE8, 0x55, 0xC8, 0x36, 0x16, 0x12, 0x5A,
        0xB1, 0x8D, 0x65, 0x51, 0x15, 0x62, 0x51, 0x27, 0x12, 0xC9, 0x31, 0xAC, 0xF6, 0x98, 0x11, 0x69,
        0x3B, 0xCE, 0xB7, 0xC2, 0x42, 0x1D, 0xB7, 0x72, 0x44, 0x3E, 0xC6, 0xC0, 0x0B, 0xE4, 0x9D, 0xD1,
        0x17, 0x58, 0x83, 0x58, 0xA5, 0xAD, 0xA9, 0x09, 0x23, 0xA2, 0x07, 0xD9, 0xDB, 0xCE, 0x92, 0x0C,
        0x41, 0x26, 0x45, 0x12, 0x7C, 0x72, 0x83, 0xAA, 0x69, 0x57, 0xE2, 0x95, 0xE1, 0xFB, 0xE7, 0xF2,
        0xD8, 0x64, 0x9B, 0x0D, 0x15, 0x1B, 0x2E, 0xFF, 0x5B, 0x25, 0xAF, 0xF3, 0xEB, 0x5C, 0xED, 0x87,
        0x26, 0xE6, 0x5A, 0x2B, 0x16, 0x0F, 0xAE, 0x20, 0xB5, 0x67, 0x87, 0xC4, 0x2F, 0x30, 0x70, 0x8A,
        0x72, 0x5B, 0xC9, 0x65, 0xBE, 0xA6, 0x54, 0x07, 0x8D, 0xD7, 0xE5, 0x3B, 0xC2, 0x45, 0xA7, 0xEE,
        0xF6, 0x17, 0x5B, 0xD6, 0xB6, 0xD2, 0x5A, 0xCF, 0x38, 0xB2, 0x4D, 0x48, 0x15, 0x62, 0xCF, 0x25,
        0xB9, 0xEC, 0x12, 0xF2, 0x1E, 0x39, 0xE8, 0xC5, 0x58, 0xC1, 0x58, 0x7D, 0x9E, 0x18, 0x44, 0x49,
        0x74, 0xC4, 0xC3, 0x4C, 0x77, 0x2A, 0x14, 0x22, 0x33, 0xB9, 0xB7, 0x0F, 0xF2, 0x35, 0x20, 0xB1,
        0x97, 0xA4, 0x8A, 0x3E, 0x05, 0x2C, 0x1D, 0xE3, 0x29, 0xBB, 0x39, 0xDE, 0xE2, 0xB7, 0x80, 0x59,
        0x32, 0x82, 0xC1, 0x1A, 0xF3, 0xB8, 0xD8, 0xD8, 0xB5, 0xBB, 0x2A, 0xFB, 0x01, 0x9F, 0x60, 0x5A,
        0x90, 0x7E, 0x2B, 0x23, 0x6E, 0xB4, 0xD2, 0x8D, 0x9B, 0x79, 0x5C, 0x0D, 0xB1, 0x27, 0x19, 0x66,
        0xD9, 0xBA, 0xD4, 0x53, 0x73, 0x17, 0x9C, 0xE2, 0x23, 0xC6, 0xE7, 0xC3, 0x9C, 0xB0, 0xD5, 0x8D,
        0x91, 0x20, 0x06, 0xCA, 0xDC, 0x57, 0x8C, 0xCF, 0x06, 0x75, 0xE8, 0xFB, 0x47, 0x25, 0xEC, 0x2E,
        0x74, 0x20, 0x42, 0x5F, 0x14, 0xE1, 0xA3, 0x1B, 0x94, 0x72, 0xCA, 0x48, 0x75, 0x57, 0x9A, 0x04,
        0xC0, 0xB0, 0x94, 0x23, 0x80, 0x93, 0x7C, 0xB0, 0xA2, 0x0F, 0xDB, 0xE1, 0x8C, 0x66, 0xFB, 0x0F,
        0x30, 0x08, 0x3B, 0x09, 0x25, 0xBE, 0xD4, 0xAC, 0x3F, 0xFC, 0x9F, 0xD9, 0xA4, 0x7B, 0xA9, 0x59,
        0x40, 0x58, 0x7C, 0x3C, 0xEC, 0x88, 0x02, 0xD7, 0x8B, 0x02, 0xEB, 0xF1, 0xDA, 0xE7, 0x36, 0x08,
        0xB9, 0x71, 0xA1, 0x65, 0xF0, 0xDF, 0xB1, 0x7A, 0xD5, 0x90, 0x72, 0xD8, 0x1D, 0xE0, 0x7E, 0xF2,
        0x42, 0x87, 0x0E, 0x23, 0xC5, 0x10, 0x60, 0x24, 0x3E, 0x6B, 0xE5, 0x9D, 0x8C, 0x78, 0x3C, 0x65,
        0xAA, 0x11, 0xE2, 0xF7, 0x51, 0xE5, 0x14, 0xA8, 0x00, 0xCF, 0x04, 0xE0, 0x28, 0x4C, 0xA6, 0xD6,
        0x60, 0x2E, 0xC8, 0x4D, 0x16, 0xA1, 0x34, 0xCB, 0x32, 0x91, 0xEB, 0x8C, 0xA4, 0xA4, 0x9A, 0xE8,
        0x52, 0xF7, 0x3F, 0x8D, 0xDE, 0x79, 0x85, 0x08, 0xB0, 0x81, 0x85, 0xF6, 0x45, 0xD3, 0x8D, 0x1F,
        0xD0, 0x18, 0x11, 0xF3, 0x5C, 0x23, 0xCF, 0x16, 0xA6, 0xAD, 0x02, 0x81, 0xD3, 0xE4, 0xC3, 0x38,
        0x3F, 0x24, 0x6B, 0x06, 0x84, 0x9C, 0x74, 0x50, 0xA7, 0xAF, 0x98, 0x75, 0x63, 0x30, 0x9F, 0x81,
        0x09, 0x02, 0x03, 0x01, 0x00, 0x01
    )

    $profilePayload = "$($machineName.Trim().ToUpperInvariant())|$procCount|$osArch|$machineId|$primaryMac"
    $hmac = New-Object System.Security.Cryptography.HMACSHA256 (,$officialRootPubKey)
    try {
        $hmacBytes = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($profilePayload))
    } finally {
        $hmac.Dispose()
    }
    $arkHex = ([System.BitConverter]::ToString($hmacBytes) -replace '-', '').ToUpperInvariant()
    $arkFp = "ARK-FP-$($arkHex.Substring(0,8))-$($arkHex.Substring(8,8))-$($arkHex.Substring(16,8))"

    $cpuSummary = if ($PhysicalCores -gt 0 -and $LogicalProcessors -gt 0) {
        "$PhysicalCores Core(s) / $LogicalProcessors Thread(s) ($osArch)"
    } else {
        "$procCount Logical CPU(s) ($osArch)"
    }
    $guidPart = if (-not [string]::IsNullOrWhiteSpace($osMachineGuid)) { " | MachineGUID: $osMachineGuid" } else { "" }

    return @{
        ArkFingerprint  = $arkFp
        HostName        = $machineName
        Architecture    = $osArch
        Cores           = $procCount
        MachineId       = $machineId
        MachineGuid     = $osMachineGuid
        PrimaryMac      = $formattedMac
        HardwareSummary = "Host: $machineName | $cpuSummary | $TotalRamGB GB RAM | $PhysicalDiskCount Physical Disk(s) | MAC: $formattedMac$guidPart"
    }
}

Write-Host "==============================================================================" -ForegroundColor Blue
Write-Host " Aarkam Rokka Sovereign Storage Engine — Windows Server Installer             " -ForegroundColor Cyan
Write-Host " Release Version: v$RokkaReleaseVersion-GA (V-$RokkaReleaseVersion) | Services: $CoordinatorServiceName & $GatewayServiceName " -ForegroundColor Blue
Write-Host "==============================================================================" -ForegroundColor Blue

# ------------------------------------------------------------------------------
# Step 0: Resolve Default Ports, URLs, Install Paths & Release Payload
# ------------------------------------------------------------------------------
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }

# Default Rokka Coordinator URL: https://rokka-coordinator.aarkam:57774 if user did not specify one
if ([string]::IsNullOrWhiteSpace($RokkaUrl)) {
    $coordPortSuffix = if ($CoordinatorHttpsPort -eq 443) { "" } else { ":$CoordinatorHttpsPort" }
    $RokkaUrl = "https://rokka-coordinator.aarkam$coordPortSuffix"
} else {
    $RokkaUrl = $RokkaUrl.Trim().TrimEnd('/')
    if (-not $RokkaUrl.StartsWith("http://", [System.StringComparison]::OrdinalIgnoreCase) -and
        -not $RokkaUrl.StartsWith("https://", [System.StringComparison]::OrdinalIgnoreCase)) {
        $RokkaUrl = "https://$RokkaUrl"
    }
    try {
        $parsedCoordUri = [System.Uri]$RokkaUrl
        if (-not $PSBoundParameters.ContainsKey("CoordinatorHttpsPort") -and $parsedCoordUri.Port -gt 0 -and -not $parsedCoordUri.IsDefaultPort) {
            $CoordinatorHttpsPort = $parsedCoordUri.Port
        } elseif ($parsedCoordUri.IsDefaultPort -and $parsedCoordUri.Scheme -eq "https" -and -not $PSBoundParameters.ContainsKey("CoordinatorHttpsPort")) {
            $CoordinatorHttpsPort = 443
        }
    } catch {
        Write-Err "Invalid -RokkaUrl '$RokkaUrl'. Expected a valid URI (e.g. 'https://rokka-coordinator.aarkam:57774')."
        exit 1
    }
}

# Default Rokka Gateway URL: https://rokka-gateway.aarkam:57772 if user did not specify one
if ([string]::IsNullOrWhiteSpace($GatewayUrl)) {
    $gwPortSuffix = if ($GatewayHttpsPort -eq 443) { "" } else { ":$GatewayHttpsPort" }
    $GatewayUrl = "https://rokka-gateway.aarkam$gwPortSuffix"
} else {
    $GatewayUrl = $GatewayUrl.Trim().TrimEnd('/')
    if (-not $GatewayUrl.StartsWith("http://", [System.StringComparison]::OrdinalIgnoreCase) -and
        -not $GatewayUrl.StartsWith("https://", [System.StringComparison]::OrdinalIgnoreCase)) {
        $GatewayUrl = "https://$GatewayUrl"
    }
    try {
        $parsedGwUri = [System.Uri]$GatewayUrl
        if (-not $PSBoundParameters.ContainsKey("GatewayHttpsPort") -and $parsedGwUri.Port -gt 0 -and -not $parsedGwUri.IsDefaultPort) {
            $GatewayHttpsPort = $parsedGwUri.Port
        } elseif ($parsedGwUri.IsDefaultPort -and $parsedGwUri.Scheme -eq "https" -and -not $PSBoundParameters.ContainsKey("GatewayHttpsPort")) {
            $GatewayHttpsPort = 443
        }
    } catch {
        Write-Err "Invalid -GatewayUrl '$GatewayUrl'. Expected a valid URI (e.g. 'https://rokka-gateway.aarkam:57772')."
        exit 1
    }
}

$coordHostName = ([System.Uri]$RokkaUrl).Host
$gwHostName    = ([System.Uri]$GatewayUrl).Host
$coordPortSuffix = if ($CoordinatorHttpsPort -eq 443) { "" } else { ":$CoordinatorHttpsPort" }
$gwPortSuffix    = if ($GatewayHttpsPort -eq 443) { "" } else { ":$GatewayHttpsPort" }

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin -and -not $UserOnly.IsPresent -and -not $CheckOnly.IsPresent) {
    Write-Err "This installer must be run from an elevated PowerShell prompt (Run as Administrator), or pass -UserOnly / -CheckOnly."
    exit 1
}

if ($UserOnly.IsPresent) {
    if ([string]::IsNullOrWhiteSpace($InstallDir)) {
        $InstallDir = Join-Path $env:LOCALAPPDATA "Aarkam\Rokka"
    }
    if (-not $PSBoundParameters.ContainsKey("DataDir")) {
        $DataDir = Join-Path $env:LOCALAPPDATA "Aarkam\Rokka\data"
    }
} else {
    if ([string]::IsNullOrWhiteSpace($InstallDir)) {
        $InstallDir = "C:\Program Files\Aarkam\Rokka"
    }
}

$binDir      = Join-Path $InstallDir "bin"
$configDir   = Join-Path $InstallDir "config"
$metaDir     = Join-Path $DataDir "Coordinator\metadata"
$catalogDir  = Join-Path $DataDir "Gateway\catalog"
$securityDir = Join-Path $DataDir "Security"
$logsDir     = Join-Path $DataDir "Logs"

# Locate Release Payload (rokka-coordinator.exe & rokka-gateway.exe)
$tempZipExtract    = ""
$resolvedCoordExe  = ""
$resolvedGatewayExe = ""
$isSelfContainedBinary = $true

$candidateSources = @()
if (-not [string]::IsNullOrWhiteSpace($SourcePath)) {
    $candidateSources += $SourcePath
}
$candidateSources += @(
    (Get-Location).Path,
    $ScriptRoot,
    (Join-Path $ScriptRoot "win"),
    (Join-Path $ScriptRoot "V-$RokkaReleaseVersion\win"),
    (Join-Path $ScriptRoot "V-$RokkaReleaseVersion\rokka-v$RokkaReleaseVersion-win-x64.zip"),
    (Join-Path $ScriptRoot "rokka-v$RokkaReleaseVersion-win-x64.zip"),
    (Join-Path $ScriptRoot "..\dist\bundles\rokka-v$RokkaReleaseVersion-win-x64.zip"),
    (Join-Path $ScriptRoot "..\dist\staging\win-x64"),
    (Join-Path $ScriptRoot "..\dist\win-x64"),
    (Join-Path $ScriptRoot "..")
)

foreach ($cand in $candidateSources) {
    if ([string]::IsNullOrWhiteSpace($cand) -or -not (Test-Path $cand)) { continue }

    if ((Test-Path $cand -PathType Leaf) -and $cand.EndsWith(".zip", [System.StringComparison]::OrdinalIgnoreCase)) {
        if (-not $CheckOnly.IsPresent) {
            Write-Info "Extracting release archive '$cand'..."
            $tempZipExtract = Join-Path ([System.IO.Path]::GetTempPath()) ("rokka_inst_" + [Guid]::NewGuid().ToString("N"))
            Expand-Archive -Path $cand -DestinationPath $tempZipExtract -Force
            $cand = $tempZipExtract
        } else {
            Write-Ok "Found release archive: $cand"
            break
        }
    }

    if (Test-Path $cand -PathType Container) {
        $cDirect = Join-Path $cand "rokka-coordinator.exe"
        if (-not (Test-Path $cDirect)) { $cDirect = Join-Path $cand "Rokka.Coordinator.exe" }

        $gDirect = Join-Path $cand "rokka-gateway.exe"
        if (-not (Test-Path $gDirect)) { $gDirect = Join-Path $cand "Rokka.Gateway.exe" }

        if ((Test-Path $cDirect) -or (Test-Path $gDirect)) {
            if (Test-Path $cDirect) { $resolvedCoordExe = (Resolve-Path $cDirect).Path }
            if (Test-Path $gDirect) { $resolvedGatewayExe = (Resolve-Path $gDirect).Path }
            break
        }
    }
}

if (-not [string]::IsNullOrWhiteSpace($resolvedCoordExe)) {
    Write-Ok "Located Rokka Coordinator executable: $resolvedCoordExe"
}
if (-not [string]::IsNullOrWhiteSpace($resolvedGatewayExe)) {
    Write-Ok "Located Rokka Gateway executable:     $resolvedGatewayExe"
}

# Resolve ClusterCode (CLI -> existing settings -> Auto-Generated 15-char XXXX-XXXX-XXXXX)
$ClusterCodeSource = ""
if (-not [string]::IsNullOrWhiteSpace($ClusterCode)) {
    $ClusterCode = $ClusterCode.Trim()
    if ($ClusterCode -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$') {
        Write-Err "Invalid -ClusterCode '$ClusterCode'. Must start with a letter or digit and contain only letters, digits, '.', '_', or '-' (e.g. ARK-PROD-01)."
        exit 1
    }
    $ClusterCodeSource = "CLI Parameter (-ClusterCode)"
} else {
    $settingsCandidates = @(
        (Join-Path (Get-Location).Path "coordinator.settings.json"),
        (Join-Path $ScriptRoot "coordinator.settings.json"),
        (Join-Path $ScriptRoot "win\coordinator.settings.json"),
        (Join-Path $configDir "coordinator.settings.json"),
        (Join-Path $binDir "coordinator.settings.json")
    )
    if (-not [string]::IsNullOrWhiteSpace($resolvedCoordExe)) {
        $srcCoordSettings = Join-Path (Split-Path -Parent $resolvedCoordExe) "coordinator.settings.json"
        if ($settingsCandidates -notcontains $srcCoordSettings) {
            $settingsCandidates += $srcCoordSettings
        }
    }
    $foundCluster = Get-ConfiguredClusterCodeFromSettings -CandidateFiles $settingsCandidates
    if ($null -ne $foundCluster) {
        $ClusterCode = $foundCluster.ClusterCode
        $ClusterCodeSource = "Loaded from $($foundCluster.SourceFile)"
        Write-Ok "Resolved existing ClusterCode '$ClusterCode' from '$($foundCluster.SourceFile)'."
    } else {
        $ClusterCode = New-RandomRokkaClusterCode
        $ClusterCodeSource = "Auto-Generated (XXXX-XXXX-XXXXX, 15 chars)"
        Write-Info "Generated ClusterCode: $ClusterCode (15 chars [4-4-5])"
    }
}

Write-Info "Validating Aarkam V2 Ecosystem Version Compatibility Matrix:"
Write-Host "  • Aarkam Rokka Coordinator   : v$RokkaReleaseVersion-GA (V-$RokkaReleaseVersion) | Service: $CoordinatorServiceName (:57774 / :7774)" -ForegroundColor Gray
Write-Host "  • Aarkam Rokka Gateway       : v$RokkaReleaseVersion-GA (V-$RokkaReleaseVersion) | Service: $GatewayServiceName (:57772 / :7772)" -ForegroundColor Gray
Write-Host "  • Aarkam Abodi Node Agent    : >= v$RequiredAbodiMinVersion (Service: Aarkam.Abodi, mTLS :57775 / :57776)" -ForegroundColor Gray
Write-Host "  • Aarkam Kdouja SAT Engine   : v$RequiredKdoujaSatVersion (SDK v$RequiredKdoujaSdkVersion, Primitives v$RequiredKdoujaPrimVersion)" -ForegroundColor Gray
Write-Host "  • Aarkam Ahmodi Cauchy EC    : v$RequiredAhmodiVersion (Default Profile: $DefaultStoragePolicy)" -ForegroundColor Gray
Write-Host "  • Aarkam AM Fleet CLI        : >= v$RequiredAmCliMinVersion" -ForegroundColor Gray
Write-Host "  • Zero-Trust SPIFFE Domain   : spiffe://$TrustDomain" -ForegroundColor Gray

# ------------------------------------------------------------------------------
# Step 1: Verify Architecture, OS, Hardware Resources & Rokka Coordinator Footprint
# ------------------------------------------------------------------------------
if ([IntPtr]::Size -ne 8 -or ($env:PROCESSOR_ARCHITECTURE -ne "AMD64" -and $env:PROCESSOR_ARCHITEW6432 -ne "AMD64")) {
    Write-Err "Unsupported CPU architecture. Rokka v$RokkaReleaseVersion requires 64-bit (x64 / AMD64) Windows."
    exit 1
}
Write-Ok "CPU architecture check passed (x64 / AMD64)."

if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Err "PowerShell 5.1 or newer is required (Detected: $($PSVersionTable.PSVersion))."
    exit 1
}
Write-Ok "PowerShell runtime check passed (v$($PSVersionTable.PSVersion))."

if ($isAdmin) {
    Write-Ok "Administrator privilege check passed."
} elseif ($CheckOnly.IsPresent) {
    Write-Warn "Running in -CheckOnly mode without Administrator elevation. Service registration requires Run as Administrator."
} elseif ($UserOnly.IsPresent) {
    Write-Warn "Running in -UserOnly mode. Windows Services and Firewall rules will be skipped."
}

$osCaption  = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
$buildNum   = [System.Environment]::OSVersion.Version.Build
$totalRamMB = 8192
$totalRamGB = 8.0
try {
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $osCaption  = $osInfo.Caption
    $buildNum   = [int]$osInfo.BuildNumber
    $totalRamMB = [math]::Round($osInfo.TotalVisibleMemorySize / 1024)
    $totalRamGB = [math]::Round($osInfo.TotalVisibleMemorySize / 1048576, 1)
} catch {
    try {
        $memBytes = [System.GC]::GetGCMemoryInfo().TotalAvailableMemoryBytes
        if ($memBytes -gt 0) {
            $totalRamMB = [math]::Round($memBytes / 1MB)
            $totalRamGB = [math]::Round($memBytes / 1GB, 1)
        }
    } catch { }
}
try {
    $csInfo = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ($csInfo.TotalPhysicalMemory -gt 0) {
        $totalRamGB = [math]::Round($csInfo.TotalPhysicalMemory / 1GB, 1)
        $totalRamMB = [math]::Round($csInfo.TotalPhysicalMemory / 1MB)
    }
} catch { }

$physicalCores = 0
$logicalProcessors = [System.Environment]::ProcessorCount
try {
    $cpus = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop)
    if ($cpus.Count -gt 0) {
        $physicalCores = ($cpus | Measure-Object -Property NumberOfCores -Sum).Sum
        $logicalProcessors = ($cpus | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
    }
} catch { }

Write-Info "Detected OS: $osCaption (Build $buildNum) | RAM: $totalRamGB GB"

if ($buildNum -lt 19044) {
    Write-Warn "Windows Build $buildNum is older than recommended baseline (Windows Server 2022 Build 20348+ / Windows 10 21H2 Build 19044+)."
} else {
    Write-Ok "Windows OS build compatibility verified (Build $buildNum)."
}

if ($totalRamMB -lt 3800) {
    Write-Warn "Host has $totalRamGB GB RAM. Minimum 4.0 GB (16.0 GB+ recommended for production Rokka Quorum & Gateway)."
} else {
    Write-Ok "Memory check passed ($totalRamGB GB available)."
}

$physicalDiskCount = 0
try {
    $physDisks = @(Get-CimInstance -Namespace "root\Microsoft\Windows\Storage" -ClassName "MSFT_PhysicalDisk" -ErrorAction Stop)
    $physicalDiskCount = $physDisks.Count
} catch {
    try {
        $wmiDisks = @(Get-CimInstance -ClassName "Win32_DiskDrive" -ErrorAction Stop)
        $physicalDiskCount = $wmiDisks.Count
    } catch {
        $physicalDiskCount = 1
    }
}
if ($physicalDiskCount -le 0) { $physicalDiskCount = 1 }

$coordinatorFootprint = Get-RokkaCoordinatorFootprint `
    -OsCaption $osCaption `
    -PhysicalCores $physicalCores `
    -LogicalProcessors $logicalProcessors `
    -TotalRamGB $totalRamGB `
    -PhysicalDiskCount $physicalDiskCount
Write-Ok "Computed Rokka Coordinator Footprint: $($coordinatorFootprint.ArkFingerprint)"
Write-Info "Hardware Resource Footprint:          $($coordinatorFootprint.HardwareSummary)"

# Verify Windows Time Service (w32time) for Raft quorum & mTLS clock synchronization
$w32time = Get-Service -Name "w32time" -ErrorAction SilentlyContinue
if ($null -ne $w32time) {
    if ($w32time.Status -ne "Running") {
        if (-not $CheckOnly.IsPresent -and $isAdmin) {
            Write-Info "Starting Windows Time Service (w32time) for Raft quorum & mTLS clock synchronization..."
            Set-Service -Name "w32time" -StartupType Automatic
            Start-Service -Name "w32time"
            Write-Ok "Windows Time Service (w32time) started."
        } else {
            Write-Warn "Windows Time Service (w32time) is not running. Raft consensus and mTLS require synchronized system clocks."
        }
    } else {
        Write-Ok "Windows Time Service (w32time) is active and running."
    }
}

# Check free disk space on DataDir volume
$dataRoot = [System.IO.Path]::GetPathRoot($DataDir)
try {
    $dataDriveInfo = New-Object System.IO.DriveInfo($dataRoot)
    $freeGB = [math]::Round($dataDriveInfo.AvailableFreeSpace / 1GB, 2)
    if ($dataDriveInfo.AvailableFreeSpace -lt 5368709120) {
        Write-Warn "Metadata volume ($dataRoot) has $freeGB GB free. At least 10 GB free space is recommended for Kdouja LSM WAL and metadata."
    } else {
        Write-Ok "Metadata volume ($dataRoot) free space check passed ($freeGB GB available)."
    }
} catch { }

if ($CheckOnly.IsPresent) {
    Write-Host ""
    Write-Host "==============================================================================" -ForegroundColor Green
    Write-Host " Aarkam Rokka (v$RokkaReleaseVersion-GA) Pre-Flight Check Complete (Windows x64)" -ForegroundColor Green
    Write-Host "==============================================================================" -ForegroundColor Green
    Write-Host "  Coordinator Service:          $CoordinatorServiceName"
    Write-Host "  Gateway Service:              $GatewayServiceName"
    Write-Host "  Deployment Role:              $Role (Default Storage Policy: $DefaultStoragePolicy)"
    Write-Host "  Cluster Code:                 $ClusterCode ($ClusterCodeSource)"
    Write-Host "  Rokka Coordinator:            $RokkaUrl (HTTPS/mTLS :$CoordinatorHttpsPort | gRPC :$CoordinatorPort)"
    Write-Host "  Rokka Gateway:                $GatewayUrl (HTTPS :$GatewayHttpsPort | HTTP :$GatewayPort)"
    Write-Host "  SPIFFE Trust Domain:          spiffe://$TrustDomain"
    Write-Host "  Install Directory:            $InstallDir"
    Write-Host "  Data & Metadata Directory:    $DataDir"
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host " ROKKA CLUSTER ACTIVATION & SOVEREIGN GENESIS CEREMONY INFORMATION" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  AarkamCP (Customer Portal) Url: $AarkamCpLoginUrl" -ForegroundColor White
    Write-Host "  AarkamCP Subscription Portal:   $AarkamCpSubscriptionUrl" -ForegroundColor White
    Write-Host "  Rokka Coordinator Footprint:    $($coordinatorFootprint.ArkFingerprint)" -ForegroundColor Green
    Write-Host "  Cluster Code (For Binding):     $ClusterCode" -ForegroundColor White
    Write-Host "  Hardware Footprint:             $($coordinatorFootprint.HardwareSummary)" -ForegroundColor Gray
    Write-Host "==============================================================================" -ForegroundColor Green
    exit 0
}

# ------------------------------------------------------------------------------
# Step 2: Resolve or Generate 256-Bit Cryptographic Keys (Zero-Trust CWE-312)
# ------------------------------------------------------------------------------
$envScope = if ($UserOnly.IsPresent) { [EnvironmentVariableTarget]::User } else { [EnvironmentVariableTarget]::Machine }

if ([string]::IsNullOrWhiteSpace($MasterKey)) {
    if (-not $RotateKeys.IsPresent) {
        $existingMaster = [Environment]::GetEnvironmentVariable("ROKKA_MASTER_KEY", $envScope)
        if ([string]::IsNullOrWhiteSpace($existingMaster)) { $existingMaster = $env:ROKKA_MASTER_KEY }
        if (-not [string]::IsNullOrWhiteSpace($existingMaster) -and $existingMaster.Trim().Length -eq 64) {
            $MasterKey = $existingMaster.Trim()
            Write-Ok "Preserved existing 256-bit ROKKA_MASTER_KEY from environment."
        }
    }
    if ([string]::IsNullOrWhiteSpace($MasterKey)) {
        $MasterKey = New-RandomHexKey256
        Write-Info "Generated cryptographically secure 256-bit Master Key (ROKKA_MASTER_KEY)."
    }
}

if ([string]::IsNullOrWhiteSpace($WalKey)) {
    if (-not $RotateKeys.IsPresent) {
        $existingWal = [Environment]::GetEnvironmentVariable("ROKKA_WAL_ENCRYPTION_KEY", $envScope)
        if ([string]::IsNullOrWhiteSpace($existingWal)) { $existingWal = $env:ROKKA_WAL_ENCRYPTION_KEY }
        if (-not [string]::IsNullOrWhiteSpace($existingWal) -and $existingWal.Trim().Length -eq 64) {
            $WalKey = $existingWal.Trim()
            Write-Ok "Preserved existing 256-bit ROKKA_WAL_ENCRYPTION_KEY from environment."
        }
    }
    if ([string]::IsNullOrWhiteSpace($WalKey)) {
        $WalKey = New-RandomHexKey256
        Write-Info "Generated cryptographically secure 256-bit Kdouja WAL Encryption Key (ROKKA_WAL_ENCRYPTION_KEY)."
    }
}

if ([string]::IsNullOrWhiteSpace($CaPassword)) {
    if (-not $RotateKeys.IsPresent) {
        $existingCa = [Environment]::GetEnvironmentVariable("ROKKA_CLUSTER_CA_PASSWORD", $envScope)
        if ([string]::IsNullOrWhiteSpace($existingCa)) { $existingCa = $env:ROKKA_CLUSTER_CA_PASSWORD }
        if (-not [string]::IsNullOrWhiteSpace($existingCa)) {
            $CaPassword = $existingCa.Trim()
            Write-Ok "Preserved existing ROKKA_CLUSTER_CA_PASSWORD from environment."
        }
    }
    if ([string]::IsNullOrWhiteSpace($CaPassword)) {
        $CaPassword = New-RandomHexKey256
        Write-Info "Generated cryptographically secure Cluster Root CA Passphrase (ROKKA_CLUSTER_CA_PASSWORD)."
    }
}

if ([string]::IsNullOrWhiteSpace($ClusterSecret)) {
    if (-not $RotateKeys.IsPresent) {
        $existingSecret = [Environment]::GetEnvironmentVariable("ROKKA_CLUSTER_SECRET", $envScope)
        if ([string]::IsNullOrWhiteSpace($existingSecret)) { $existingSecret = $env:ROKKA_CLUSTER_SECRET }
        if (-not [string]::IsNullOrWhiteSpace($existingSecret) -and $existingSecret.Trim().Length -ge 32) {
            $ClusterSecret = $existingSecret.Trim()
            Write-Ok "Preserved existing ROKKA_CLUSTER_SECRET from environment."
        }
    }
    if ([string]::IsNullOrWhiteSpace($ClusterSecret)) {
        $ClusterSecret = New-RandomHexKey256
        Write-Info "Generated cryptographically secure Raft Quorum & JWT Cluster Secret (ROKKA_CLUSTER_SECRET)."
    }
}

# ------------------------------------------------------------------------------
# Step 3: Create Isolated Directory Hierarchy & Enforce Restricted NTFS ACLs
# ------------------------------------------------------------------------------
foreach ($dir in @($InstallDir, $binDir, $configDir, $DataDir, $metaDir, $catalogDir, $securityDir, $logsDir)) {
    if (-not (Test-Path -Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

function Set-RestrictedSecurityDirectoryAcl {
    param([string]$Path)
    $acl = Get-Acl -Path $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in $acl.Access) {
        $acl.RemoveAccessRule($rule) | Out-Null
    }

    $inheritFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propFlags    = [System.Security.AccessControl.PropagationFlags]::None

    $systemSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    $adminSid  = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)

    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule($systemSid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inheritFlags, $propFlags, [System.Security.AccessControl.AccessControlType]::Allow)
    $adminRule  = New-Object System.Security.AccessControl.FileSystemAccessRule($adminSid,  [System.Security.AccessControl.FileSystemRights]::FullControl, $inheritFlags, $propFlags, [System.Security.AccessControl.AccessControlType]::Allow)

    $acl.AddAccessRule($systemRule)
    $acl.AddAccessRule($adminRule)
    Set-Acl -Path $Path -AclObject $acl
}

if ($isAdmin -and -not $UserOnly.IsPresent) {
    Set-RestrictedSecurityDirectoryAcl -Path $securityDir
    Set-RestrictedSecurityDirectoryAcl -Path $metaDir
    Write-Ok "Configured restricted NTFS ACLs on Zero-Trust vault ($securityDir) and metadata store ($metaDir)."
}

# ------------------------------------------------------------------------------
# Step 4: Bootstrap Zero-Trust ECDSA P-256 Cluster Root CA & Server TLS Certificate
# ------------------------------------------------------------------------------
$caPfxPath      = Join-Path $securityDir "ca.pfx"
$caCrtPath      = Join-Path $securityDir "ca.crt"
$metaCaPfxPath  = Join-Path $metaDir "ca.pfx"
$serverPfxPath  = Join-Path $securityDir "rokka-server-tls.pfx"

function Initialize-RokkaClusterPki {
    param(
        [string]$CaPfx,
        [string]$CaCrt,
        [string]$MetaCaPfx,
        [string]$ServerPfx,
        [string]$Password,
        [string]$CoordHost,
        [string]$GwHost
    )

    $rootCaCert = $null
    $rootEcdsa  = $null

    try {
        if ((Test-Path $CaPfx) -and -not $RotateKeys.IsPresent) {
            try {
                $rootCaCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                    $CaPfx,
                    $Password,
                    ([System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]"Exportable, PersistKeySet")
                )
                Write-Ok "Loaded existing Cluster Root CA certificate from '$CaPfx' (Thumbprint: $($rootCaCert.Thumbprint))."
            } catch {
                Write-Warn "Existing CA certificate at '$CaPfx' could not be opened with current CA password; regenerating Cluster Root CA..."
                $rootCaCert = $null
            }
        }

        if ($null -eq $rootCaCert) {
            Write-Info "Generating Zero-Trust ECDSA P-256 Cluster Root CA (CN=Aarkam Cluster Root CA)..."
            $rootEcdsa = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
            $caDn = New-Object System.Security.Cryptography.X509Certificates.X500DistinguishedName("CN=Aarkam Cluster Root CA, O=Aarkam Cluster, OU=Sovereign PKI")
            $caReq = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest($caDn, $rootEcdsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256)

            $caReq.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension($true, $true, 1, $true)))
            $caKuFlags = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]"KeyCertSign, CrlSign, DigitalSignature"
            $caReq.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509KeyUsageExtension($caKuFlags, $true)))
            $caReq.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension($caReq.PublicKey, $false)))

            $now = [DateTimeOffset]::UtcNow
            $rootCaCert = $caReq.CreateSelfSigned($now.AddMinutes(-5), $now.AddDays(3650))

            $caPfxBytes = $rootCaCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $Password)
            [System.IO.File]::WriteAllBytes($CaPfx, $caPfxBytes)

            $caDerBytes = $rootCaCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
            $caPem = "-----BEGIN CERTIFICATE-----`r`n" + [System.Convert]::ToBase64String($caDerBytes, [System.Base64FormattingOptions]::InsertLineBreaks) + "`r`n-----END CERTIFICATE-----`r`n"
            [System.IO.File]::WriteAllText($CaCrt, $caPem, [System.Text.Encoding]::ASCII)

            Write-Ok "Generated Cluster Root CA at '$CaPfx' (Public Cert: '$CaCrt', Thumbprint: $($rootCaCert.Thumbprint))."
        }

        # Mirror ca.pfx into Coordinator metadata directory for default fallback discovery
        Copy-Item -Path $CaPfx -Destination $MetaCaPfx -Force

        # Generate Server TLS certificate signed by Root CA if not present or if rotating keys
        if (-not (Test-Path $ServerPfx) -or $RotateKeys.IsPresent) {
            Write-Info "Generating ECDSA P-256 Server TLS certificate for Rokka Coordinator & Gateway..."
            $srvEcdsa = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
            try {
                $srvDn = New-Object System.Security.Cryptography.X509Certificates.X500DistinguishedName("CN=rokka-coordinator.aarkam, O=Aarkam Cluster, OU=Rokka Substrate")
                $srvReq = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest($srvDn, $srvEcdsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256)

                $srvReq.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension($false, $false, 0, $true)))
                $srvKuFlags = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]"DigitalSignature, KeyEncipherment"
                $srvReq.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509KeyUsageExtension($srvKuFlags, $true)))

                $ekuOids = New-Object System.Security.Cryptography.OidCollection
                [void]$ekuOids.Add((New-Object System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1", "Server Authentication")))
                [void]$ekuOids.Add((New-Object System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.2", "Client Authentication")))
                $srvReq.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($ekuOids, $true)))

                $san = New-Object System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder
                $dnsNames = @("rokka-coordinator.aarkam", "rokka-gateway.aarkam", "localhost", [System.Environment]::MachineName)
                if (-not [string]::IsNullOrWhiteSpace($CoordHost) -and $dnsNames -notcontains $CoordHost) { $dnsNames += $CoordHost }
                if (-not [string]::IsNullOrWhiteSpace($GwHost) -and $dnsNames -notcontains $GwHost) { $dnsNames += $GwHost }

                foreach ($d in $dnsNames) {
                    $ipOut = $null
                    if ([System.Net.IPAddress]::TryParse($d, [ref]$ipOut)) {
                        $san.AddIpAddress($ipOut)
                    } else {
                        $san.AddDnsName($d)
                    }
                }
                $san.AddIpAddress([System.Net.IPAddress]::Loopback)
                $san.AddIpAddress([System.Net.IPAddress]::IPv6Loopback)
                $srvReq.CertificateExtensions.Add($san.Build($false))

                $now = [DateTimeOffset]::UtcNow
                $serial = New-Object byte[] 16
                $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
                $rng.GetBytes($serial)
                $rng.Dispose()
                $serial[0] = $serial[0] -band 0x7F

                $signedCert = $srvReq.Create($rootCaCert, $now.AddMinutes(-5), $now.AddDays(1825), $serial)
                $srvWithKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::CopyWithPrivateKey($signedCert, $srvEcdsa)
                $srvPfxBytes = $srvWithKey.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $Password)
                [System.IO.File]::WriteAllBytes($ServerPfx, $srvPfxBytes)

                $srvWithKey.Dispose()
                $signedCert.Dispose()
                Write-Ok "Generated Server TLS certificate at '$ServerPfx'."
            } finally {
                if ($null -ne $srvEcdsa) { $srvEcdsa.Dispose() }
            }
        }
    } finally {
        if ($null -ne $rootCaCert) { $rootCaCert.Dispose() }
        if ($null -ne $rootEcdsa)  { $rootEcdsa.Dispose() }
    }
}

Initialize-RokkaClusterPki `
    -CaPfx $caPfxPath `
    -CaCrt $caCrtPath `
    -MetaCaPfx $metaCaPfxPath `
    -ServerPfx $serverPfxPath `
    -Password $CaPassword `
    -CoordHost $coordHostName `
    -GwHost $gwHostName

# ------------------------------------------------------------------------------
# Step 5: Stop Active Services/Processes & Deploy Rokka Binaries
# ------------------------------------------------------------------------------
function Stop-RokkaServicesAndProcesses {
    param(
        [string[]]$ServiceNames,
        [string]$TargetBinDir
    )

    foreach ($svcName in $ServiceNames) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
            Write-Info "Stopping Windows Service '$svcName' (Current status: $($svc.Status))..."
            try {
                Stop-Service -Name $svcName -Force -NoWait -ErrorAction SilentlyContinue
                $svc.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(10))
            } catch {
                Write-Warn "Service '$svcName' did not stop within 10s timeout; proceeding to force-terminate process..."
            }
        }
    }

    foreach ($procName in @("rokka-coordinator", "Rokka.Coordinator", "rokka-gateway", "Rokka.Gateway")) {
        $procs = @(Get-Process -Name $procName -ErrorAction SilentlyContinue)
        if ($procs.Count -gt 0) {
            $pids = ($procs | Select-Object -ExpandProperty Id) -join ", "
            Write-Info "Force-terminating active $procName process(es) [PID: $pids] to release file locks..."
            foreach ($p in $procs) {
                try {
                    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                    $p.WaitForExit(5000) | Out-Null
                } catch { }
            }
            & taskkill.exe /F /IM "$procName.exe" /T 2>$null | Out-Null
        }
    }

    if (Test-Path $TargetBinDir) {
        Get-ChildItem -Path $TargetBinDir -Filter "*.old_*" -ErrorAction SilentlyContinue | ForEach-Object {
            Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
        }
    }
}

if ($isAdmin -and -not $UserOnly.IsPresent) {
    Stop-RokkaServicesAndProcesses `
        -ServiceNames @($GatewayServiceName, $CoordinatorServiceName, $LegacyGatewayServiceName, $LegacyCoordinatorServiceName) `
        -TargetBinDir $binDir

    foreach ($legacySvc in @($LegacyGatewayServiceName, $LegacyCoordinatorServiceName)) {
        if ($null -ne (Get-Service -Name $legacySvc -ErrorAction SilentlyContinue)) {
            Write-Info "Removing legacy Windows Service registration '$legacySvc'..."
            & sc.exe delete $legacySvc | Out-Null
            Write-Ok "Removed legacy Windows Service '$legacySvc'."
        }
    }
}

if ($ResetMetadata.IsPresent) {
    Write-Warn "Resetting existing Coordinator metadata and Gateway catalog directories (-ResetMetadata)..."
    foreach ($resetDir in @($metaDir, $catalogDir)) {
        if (Test-Path $resetDir) {
            Remove-Item -Path $resetDir -Recurse -Force -ErrorAction Stop
        }
        New-Item -ItemType Directory -Path $resetDir -Force | Out-Null
    }
    if (Test-Path $caPfxPath) {
        Copy-Item -Path $caPfxPath -Destination $metaCaPfxPath -Force
    }
    if ($isAdmin -and -not $UserOnly.IsPresent) {
        Set-RestrictedSecurityDirectoryAcl -Path $metaDir
    }
    Write-Ok "Coordinator metadata and Gateway catalog directories reset cleanly."
}

$destCoord   = Join-Path $binDir "rokka-coordinator.exe"
$destGateway = Join-Path $binDir "rokka-gateway.exe"

$deployCoord   = ($Role -eq "All" -or $Role -eq "Coordinator")
$deployGateway = ($Role -eq "All" -or $Role -eq "Gateway")

if ($deployCoord) {
    if (-not [string]::IsNullOrWhiteSpace($resolvedCoordExe) -and (Test-Path $resolvedCoordExe)) {
        if ([System.IO.Path]::GetFullPath($resolvedCoordExe) -ine [System.IO.Path]::GetFullPath($destCoord)) {
            Copy-Item -Path $resolvedCoordExe -Destination $destCoord -Force
        }
        Write-Ok "Deployed Rokka Coordinator binary: $destCoord"
    } elseif (-not (Test-Path $destCoord)) {
        Write-Err "Could not locate rokka-coordinator.exe. Specify -SourcePath to the release directory or zip archive."
        exit 1
    }
}

if ($deployGateway) {
    if (-not [string]::IsNullOrWhiteSpace($resolvedGatewayExe) -and (Test-Path $resolvedGatewayExe)) {
        if ([System.IO.Path]::GetFullPath($resolvedGatewayExe) -ine [System.IO.Path]::GetFullPath($destGateway)) {
            Copy-Item -Path $resolvedGatewayExe -Destination $destGateway -Force
        }
        Write-Ok "Deployed Rokka Gateway binary:     $destGateway"
    } elseif (-not (Test-Path $destGateway)) {
        Write-Err "Could not locate rokka-gateway.exe. Specify -SourcePath to the release directory or zip archive."
        exit 1
    }
}

# Remove legacy duplicate PascalCase executables if present
foreach ($dup in @((Join-Path $binDir "Rokka.Coordinator.exe"), (Join-Path $binDir "Rokka.Gateway.exe"))) {
    if (Test-Path $dup) { Remove-Item -Path $dup -Force -ErrorAction SilentlyContinue }
}

if (-not [string]::IsNullOrWhiteSpace($tempZipExtract) -and (Test-Path $tempZipExtract)) {
    Remove-Item -Path $tempZipExtract -Recurse -Force -ErrorAction SilentlyContinue
}

# ------------------------------------------------------------------------------
# Step 6: Generate Decoupled Production Configurations (Zero Plaintext Secrets)
# ------------------------------------------------------------------------------
$coordConfigObj = @{
    Logging = @{
        LogLevel = @{
            Default = "Information"
            "Microsoft.AspNetCore" = "Warning"
            "Microsoft.Hosting.Lifetime" = "Information"
        }
    }
    AllowedHosts = "*"
    Cluster = @{
        ClusterCode = $ClusterCode
        TrustDomain = $TrustDomain
        PublicEndpoint = $RokkaUrl
    }
    Security = @{
        RequireOperatorAuth = $true
        RequireNodeMtls = $false
        TrustDomain = $TrustDomain
        ClusterCaCertificatePath = $caPfxPath
    }
    Aarkam = @{
        BaseDirectory = $metaDir
        UnsafeSkipCertValidation = "true"
        Storage = @{
            Transport = @{
                Mode = "Auto"
                SlotSizeBytes = 4194304
                SlotCount = 256
                Port = 1
                GidIndex = 0
                EnableHugePages = $true
                CircuitBreakerFailureThreshold = 3
            }
        }
    }
    Rokka = @{
        BaseDirectory = $metaDir
        DefaultStoragePolicy = $DefaultStoragePolicy
        Transcoder = @{
            Enabled = $true
            ScanIntervalSeconds = 60
            TargetPolicy = $DefaultStoragePolicy
            MaxBytesPerSecond = 40000000
            ReclaimOriginalReplicas = $true
        }
    }
    PeerCoordinators = @()
    Health = @{
        HeartbeatTimeoutSeconds = 30
        ScanIntervalSeconds = 5
        MinAvailableBytesThreshold = 1073741824
    }
    Kestrel = @{
        Certificates = @{
            Default = @{
                Path = $serverPfxPath
            }
        }
        Endpoints = @{
            "gRPC-Http" = @{
                Url = "http://0.0.0.0:$CoordinatorPort"
                Protocols = "Http2"
            }
            "Https" = @{
                Url = "https://0.0.0.0:$CoordinatorHttpsPort"
                Protocols = "Http1AndHttp2"
            }
        }
    }
}

$gwCoordinatorTarget = if ($Role -eq "Gateway" -and $PSBoundParameters.ContainsKey("RokkaUrl")) {
    $RokkaUrl
} else {
    "http://127.0.0.1:$CoordinatorPort"
}

$gwConfigObj = @{
    Logging = @{
        LogLevel = @{
            Default = "Information"
            "Microsoft.AspNetCore" = "Warning"
            "Microsoft.Hosting.Lifetime" = "Information"
        }
    }
    AllowedHosts = "*"
    Cluster = @{
        ClusterCode = $ClusterCode
        TrustDomain = $TrustDomain
        PublicGatewayEndpoint = $GatewayUrl
    }
    Rokka = @{
        CoordinatorAddress = $gwCoordinatorTarget
        CatalogDirectory = $catalogDir
        DefaultStoragePolicy = $DefaultStoragePolicy
        S3 = @{
            AccessKeyId = $S3AccessKeyId
        }
    }
    Aarkam = @{
        BaseDirectory = $catalogDir
        UnsafeSkipCertValidation = "true"
        Storage = @{
            Transport = @{
                Mode = "Auto"
                SlotSizeBytes = 4194304
                SlotCount = 256
                Port = 1
                GidIndex = 0
                EnableHugePages = $true
                CircuitBreakerFailureThreshold = 3
            }
        }
    }
    Kestrel = @{
        Certificates = @{
            Default = @{
                Path = $serverPfxPath
            }
        }
        Endpoints = @{
            "Http" = @{
                Url = "http://0.0.0.0:$GatewayPort"
                Protocols = "Http1"
            }
            "Https" = @{
                Url = "https://0.0.0.0:$GatewayHttpsPort"
                Protocols = "Http1AndHttp2"
            }
        }
    }
}

$coordConfigFile = Join-Path $configDir "coordinator.settings.json"
$gwConfigFile    = Join-Path $configDir "gateway.settings.json"

$coordConfigObj | ConvertTo-Json -Depth 6 | Set-Content -Path $coordConfigFile -Encoding UTF8
$gwConfigObj    | ConvertTo-Json -Depth 6 | Set-Content -Path $gwConfigFile -Encoding UTF8

Copy-Item -Path $coordConfigFile -Destination (Join-Path $binDir "coordinator.settings.json") -Force
Copy-Item -Path $gwConfigFile    -Destination (Join-Path $binDir "gateway.settings.json") -Force

$staleAppSettings = Join-Path $binDir "appsettings.json"
if (Test-Path $staleAppSettings) {
    Remove-Item -Path $staleAppSettings -Force -ErrorAction SilentlyContinue
}

Write-Ok "Generated decoupled configurations at '$coordConfigFile' and '$gwConfigFile'."

# ------------------------------------------------------------------------------
# Step 7: Persist Environment Variables & PATH
# ------------------------------------------------------------------------------
$envVars = @{
    "ASPNETCORE_ENVIRONMENT"                           = "Production"
    "DOTNET_CLI_TELEMETRY_OPTOUT"                      = "1"
    "ROKKA_COORDINATOR_URL"                            = $RokkaUrl
    "ROKKA_GATEWAY_URL"                                = $GatewayUrl
    "ROKKA_MASTER_KEY"                                 = $MasterKey
    "ROKKA_WAL_ENCRYPTION_KEY"                         = $WalKey
    "ROKKA_CLUSTER_CA_PASSWORD"                        = $CaPassword
    "ROKKA_CLUSTER_SECRET"                             = $ClusterSecret
    "ROKKA_ACCESS_KEY_ID"                              = $S3AccessKeyId
    "ROKKA_SECRET_ACCESS_KEY"                          = $MasterKey
    "Jwt__Key"                                         = $ClusterSecret
    "Kestrel__Certificates__Default__Path"             = $serverPfxPath
    "Kestrel__Certificates__Default__Password"         = $CaPassword
    "ASPNETCORE_Kestrel__Certificates__Default__Path"     = $serverPfxPath
    "ASPNETCORE_Kestrel__Certificates__Default__Password" = $CaPassword
}

foreach ($kv in $envVars.GetEnumerator()) {
    [Environment]::SetEnvironmentVariable($kv.Key, $kv.Value, $envScope)
    Set-Item -Path "Env:\$($kv.Key)" -Value $kv.Value
}
# When installing in Machine scope, remove conflicting stale User-scope ROKKA_* overrides so CLI & Services use the same keys
if (-not $UserOnly.IsPresent) {
    foreach ($keyName in @("ROKKA_MASTER_KEY", "ROKKA_WAL_ENCRYPTION_KEY", "ROKKA_CLUSTER_CA_PASSWORD", "ROKKA_CLUSTER_SECRET", "ROKKA_ACCESS_KEY_ID", "ROKKA_SECRET_ACCESS_KEY")) {
        $userVal = [Environment]::GetEnvironmentVariable($keyName, [EnvironmentVariableTarget]::User)
        if (-not [string]::IsNullOrWhiteSpace($userVal) -and $userVal -ne $envVars[$keyName]) {
            [Environment]::SetEnvironmentVariable($keyName, $null, [EnvironmentVariableTarget]::User)
            Write-Warn "Removed conflicting User-scope override '$keyName' so interactive shells match Machine/Service configuration."
        }
    }
}
Write-Ok "Configured Zero-Trust cryptographic environment variables ($($envScope.ToString()) scope)."

$currentPath = [Environment]::GetEnvironmentVariable("Path", $envScope)
$paths = ($currentPath -split ';') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
if ($paths -notcontains $binDir) {
    $newPath = ($paths + $binDir) -join ';'
    [Environment]::SetEnvironmentVariable("Path", $newPath, $envScope)
    Write-Ok "Added '$binDir' to $($envScope.ToString()) PATH."
}
if (($env:Path -split ';') -notcontains $binDir) {
    $env:Path = "$binDir;$env:Path"
}

# ------------------------------------------------------------------------------
# Step 8: Configure Windows Defender Firewall Rules
# ------------------------------------------------------------------------------
if (-not $UserOnly.IsPresent -and -not $SkipFirewall.IsPresent) {
    Write-Info "Configuring Windows Defender Firewall rules for Rokka ports..."
    $fwRules = @()
    if ($deployCoord) {
        $fwRules += @{ DisplayName = "Aarkam Rokka Coordinator gRPC ($CoordinatorPort)"; Port = $CoordinatorPort }
        $fwRules += @{ DisplayName = "Aarkam Rokka Coordinator HTTPS mTLS ($CoordinatorHttpsPort)"; Port = $CoordinatorHttpsPort }
    }
    if ($deployGateway) {
        $fwRules += @{ DisplayName = "Aarkam Rokka Gateway HTTP ($GatewayPort)"; Port = $GatewayPort }
        $fwRules += @{ DisplayName = "Aarkam Rokka Gateway HTTPS ($GatewayHttpsPort)"; Port = $GatewayHttpsPort }
    }

    foreach ($r in $fwRules) {
        if (-not (Get-NetFirewallRule -DisplayName $r.DisplayName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $r.DisplayName -Direction Inbound -Protocol TCP -LocalPort $r.Port -Action Allow -Profile Any | Out-Null
        }
    }
    Write-Ok "Windows Defender Firewall rules configured."
}

# ------------------------------------------------------------------------------
# Step 9: Register & Start Windows Services ('Aarkam.Rokka' & 'Aarkam.Rokka.Gateway')
# ------------------------------------------------------------------------------
if (-not $UserOnly.IsPresent) {
    # Helper: Inject service-scoped Environment (REG_MULTI_SZ) so services.exe passes new env vars without a reboot
    function Set-WindowsServiceEnvironment {
        param(
            [string]$SvcName,
            [hashtable]$Vars
        )
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$SvcName"
        if (Test-Path $regPath) {
            [string[]]$multiSz = @()
            foreach ($entry in ($Vars.GetEnumerator() | Sort-Object Name)) {
                $multiSz += "$($entry.Key)=$($entry.Value)"
            }
            New-ItemProperty -Path $regPath -Name "Environment" -Value $multiSz -PropertyType MultiString -Force | Out-Null
        }
    }

    if ($deployCoord) {
        $coordBinPath = "`"$destCoord`" --config `"$coordConfigFile`""
        $coordDisplayName = "Aarkam Rokka Sovereign Storage Coordinator"
        $coordDescription = "Aarkam Rokka Sovereign Storage Coordinator, Raft MON Quorum Consensus, HRW Placement & Zero-Trust mTLS Node Enrollment CA"
        if ($null -eq (Get-Service -Name $CoordinatorServiceName -ErrorAction SilentlyContinue)) {
            Write-Info "Registering Windows Service '$CoordinatorServiceName'..."
            New-Service -Name $CoordinatorServiceName `
                -DisplayName $coordDisplayName `
                -BinaryPathName $coordBinPath `
                -StartupType Automatic `
                -Description $coordDescription | Out-Null
        } else {
            & sc.exe config $CoordinatorServiceName binPath= $coordBinPath start= auto | Out-Null
            & sc.exe config $CoordinatorServiceName DisplayName= $coordDisplayName | Out-Null
            & sc.exe description $CoordinatorServiceName $coordDescription | Out-Null
        }
        & sc.exe failure $CoordinatorServiceName reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
        Set-WindowsServiceEnvironment -SvcName $CoordinatorServiceName -Vars $envVars
        Write-Ok "Registered Windows Service '$CoordinatorServiceName' (Binary: $coordBinPath)."
    }

    if ($deployGateway) {
        $gwBinPath = "`"$destGateway`" --config `"$gwConfigFile`""
        $gwDisplayName = "Aarkam Rokka Sovereign Storage Gateway"
        $gwDescription = "Aarkam Rokka Sovereign Storage Gateway, AES-256-GCM Envelope Encryption & Ahmodi SIMD Cauchy Reed-Solomon Engine"
        if ($null -eq (Get-Service -Name $GatewayServiceName -ErrorAction SilentlyContinue)) {
            Write-Info "Registering Windows Service '$GatewayServiceName'..."
            New-Service -Name $GatewayServiceName `
                -DisplayName $gwDisplayName `
                -BinaryPathName $gwBinPath `
                -StartupType Automatic `
                -Description $gwDescription | Out-Null
        } else {
            & sc.exe config $GatewayServiceName binPath= $gwBinPath start= auto | Out-Null
            & sc.exe config $GatewayServiceName DisplayName= $gwDisplayName | Out-Null
            & sc.exe description $GatewayServiceName $gwDescription | Out-Null
        }
        if ($deployCoord) {
            & sc.exe config $GatewayServiceName depend= $CoordinatorServiceName | Out-Null
        }
        & sc.exe failure $GatewayServiceName reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
        Set-WindowsServiceEnvironment -SvcName $GatewayServiceName -Vars $envVars
        Write-Ok "Registered Windows Service '$GatewayServiceName' (Binary: $gwBinPath)."
    }

    function Write-CleanServiceStartupError {
        param(
            [string]$SvcName,
            [string]$BinaryMatch,
            [datetime]$SinceTime,
            [string]$DataDirectory
        )
        Write-Err "Service '$SvcName' could not be started."
        $reasonShown = $false
        try {
            $recentErr = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = '.NET Runtime'; Level = 2; StartTime = $SinceTime } -MaxEvents 5 -ErrorAction SilentlyContinue |
                Where-Object { $_.Message -like "*$BinaryMatch*" } |
                Select-Object -First 1
            if ($null -ne $recentErr) {
                $msg = $recentErr.Message
                if ($msg -like "*AuthenticationTagMismatchException*") {
                    Write-Warn "Reason: Existing WAL metadata in '$DataDirectory' was encrypted with a different ROKKA_WAL_ENCRYPTION_KEY."
                    Write-Info "Key Locations: Machine env var 'ROKKA_WAL_ENCRYPTION_KEY' (HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment) & Service registry (HKLM:\SYSTEM\CurrentControlSet\Services\$SvcName -> Environment)."
                    Write-Info "Action: Pass -WalKey `"<original-64-hex-key>`" to recover existing data, or re-run with -ResetMetadata for a clean cluster state."
                    $reasonShown = $true
                } elseif ($msg -like "*CRITICAL PKI VIOLATION*" -or $msg -like "*ca.pfx*") {
                    Write-Warn "Reason: Cluster Root CA certificate (ca.pfx) could not be loaded. Verify ROKKA_CLUSTER_CA_PASSWORD or re-run with -RotateKeys."
                    $reasonShown = $true
                } elseif ($msg -like "*Unable to configure HTTPS endpoint*") {
                    Write-Warn "Reason: Kestrel HTTPS TLS certificate could not be loaded. Verify certificate path and password."
                    $reasonShown = $true
                } elseif ($msg -like "*address already in use*" -or $msg -like "*Failed to bind to address*") {
                    Write-Warn "Reason: One of the configured Rokka ports is already in use by another process."
                    $reasonShown = $true
                } elseif ($msg -like "*UnauthorizedAccessException*") {
                    Write-Warn "Reason: File system permission denied while accessing '$DataDirectory'."
                    $reasonShown = $true
                }
            }
        } catch { }

        if (-not $reasonShown) {
            Write-Info "Action: Check Windows Event Viewer (Application & System logs) for service '$SvcName' details."
        }
    }

    $shouldStart = (-not $SkipStartServices.IsPresent) -or $StartServices.IsPresent
    if ($shouldStart) {
        if ($deployCoord -and (Test-Path $destCoord)) {
            Write-Info "Starting Windows Service '$CoordinatorServiceName'..."
            $coordStartTime = (Get-Date).AddSeconds(-2)
            try {
                Start-Service -Name $CoordinatorServiceName -ErrorAction Stop
                Start-Sleep -Seconds 2
                $cState = Get-Service -Name $CoordinatorServiceName
                if ($cState.Status -eq "Running") {
                    Write-Ok "Service '$CoordinatorServiceName' is active and running."
                    try {
                        $cResp = Invoke-WebRequest -Uri "http://127.0.0.1:$CoordinatorPort/health" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
                        Write-Ok "Rokka Coordinator Health Probe (http://127.0.0.1:$CoordinatorPort/health) returned HTTP $($cResp.StatusCode)."
                    } catch {
                        Write-Warn "Coordinator health probe on http://127.0.0.1:$CoordinatorPort/health is still warming up."
                    }
                } else {
                    Write-Warn "Service '$CoordinatorServiceName' status is '$($cState.Status)'. Inspect Event Viewer or logs in '$logsDir'."
                }
            } catch {
                Write-CleanServiceStartupError -SvcName $CoordinatorServiceName -BinaryMatch "rokka-coordinator" -SinceTime $coordStartTime -DataDirectory $metaDir
                exit 1
            }
        }

        if ($deployGateway -and (Test-Path $destGateway)) {
            Write-Info "Starting Windows Service '$GatewayServiceName'..."
            $gwStartTime = (Get-Date).AddSeconds(-2)
            try {
                Start-Service -Name $GatewayServiceName -ErrorAction Stop
                Start-Sleep -Seconds 2
                $gState = Get-Service -Name $GatewayServiceName
                if ($gState.Status -eq "Running") {
                    Write-Ok "Service '$GatewayServiceName' is active and running."
                    try {
                        $gResp = Invoke-WebRequest -Uri "http://127.0.0.1:$GatewayPort/health" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
                        Write-Ok "Rokka Gateway Health Probe (http://127.0.0.1:$GatewayPort/health) returned HTTP $($gResp.StatusCode)."
                    } catch {
                        Write-Warn "Gateway health probe on http://127.0.0.1:$GatewayPort/health is still warming up."
                    }
                } else {
                    Write-Warn "Service '$GatewayServiceName' status is '$($gState.Status)'. Inspect Event Viewer or logs in '$logsDir'."
                }
            } catch {
                Write-CleanServiceStartupError -SvcName $GatewayServiceName -BinaryMatch "rokka-gateway" -SinceTime $gwStartTime -DataDirectory $catalogDir
                exit 1
            }
        }
    } else {
        Write-Info "Skipped service startup (-SkipStartServices). Start manually via: Start-Service -Name '$CoordinatorServiceName', '$GatewayServiceName'"
    }
}

# ------------------------------------------------------------------------------
# Step 10: Print Complete Installation & Rokka Cluster Activation Summary
# ------------------------------------------------------------------------------
Write-Host ""
Write-Host "==============================================================================" -ForegroundColor Green
Write-Host " Aarkam Rokka Sovereign Storage Engine (v$RokkaReleaseVersion-GA) Installation Complete (Windows x64)" -ForegroundColor Green
Write-Host "==============================================================================" -ForegroundColor Green
Write-Host "  Coordinator Service Name:     $CoordinatorServiceName"
Write-Host "  Gateway Service Name:         $GatewayServiceName"
Write-Host "  Deployment Role:              $Role (Default Storage Policy: $DefaultStoragePolicy)"
Write-Host "  Cluster Code:                 $ClusterCode ($ClusterCodeSource)"
Write-Host "  Rokka Coordinator:            $RokkaUrl"
Write-Host "  Coordinator gRPC (Internal):  http://127.0.0.1:$CoordinatorPort (Health: http://127.0.0.1:$CoordinatorPort/health)"
Write-Host "  Rokka Gateway (HTTPS):        $GatewayUrl"
Write-Host "  Rokka Gateway (HTTP):         http://${gwHostName}:$GatewayPort (Health: http://127.0.0.1:$GatewayPort/health)"
Write-Host "  SPIFFE Trust Domain:          spiffe://$TrustDomain"
Write-Host "  Binary Directory:             $binDir"
Write-Host "  Configuration Directory:      $configDir"
Write-Host "  Zero-Trust Security Vault:    $securityDir (Root CA: $caPfxPath)"
Write-Host "  Kdouja Metadata Directory:    $metaDir"
Write-Host "  Gateway Catalog Directory:    $catalogDir"
Write-Host "  Service Status Command:       Get-Service -Name '$CoordinatorServiceName', '$GatewayServiceName'"
Write-Host "------------------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host " ROKKA CLUSTER ACTIVATION & SOVEREIGN GENESIS CEREMONY INFORMATION" -ForegroundColor Yellow
Write-Host "------------------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "  AarkamCP (Customer Portal) Url: $AarkamCpLoginUrl" -ForegroundColor White
Write-Host "  AarkamCP Subscription Portal:   $AarkamCpSubscriptionUrl" -ForegroundColor White
Write-Host "  Rokka Coordinator Footprint:    $($coordinatorFootprint.ArkFingerprint)" -ForegroundColor Green
Write-Host "  Cluster Code (For Binding):     $ClusterCode" -ForegroundColor White
Write-Host "  Host Diagnostic Profile:        $($coordinatorFootprint.HardwareSummary)" -ForegroundColor Gray
Write-Host "  Gateway Root Access Key ID:     $S3AccessKeyId" -ForegroundColor Gray
Write-Host "  ROKKA_MASTER_KEY (AES-256):     $MasterKey" -ForegroundColor Yellow
Write-Host "  ROKKA_WAL_ENCRYPTION_KEY:       $WalKey" -ForegroundColor Gray
Write-Host "  ROKKA_CLUSTER_CA_PASSWORD:      $CaPassword" -ForegroundColor Gray
Write-Host "  ROKKA_CLUSTER_SECRET:           $ClusterSecret" -ForegroundColor Gray
Write-Host ""
Write-Host "  [STEP 1] Bind Rokka Coordinator Footprint & Mint Genesis Bundle on AarkamCP:" -ForegroundColor Cyan
Write-Host "    1. Sign in to AarkamCP:        $AarkamCpLoginUrl"
Write-Host "    2. Open Subscription Portal:   $AarkamCpSubscriptionUrl"
Write-Host "    3. Click 'Bind Cluster Fingerprint' and enter:"
Write-Host "         • Cluster Fingerprint :   $($coordinatorFootprint.ArkFingerprint)"
Write-Host "         • Cluster Code        :   $ClusterCode"
Write-Host "    4. Click 'Manage Operators', add your enterprise operators (ClusterAdmin / StorageOperator),"
Write-Host "       and click 'Download Sovereign Genesis Bundle (.arkbundle)'."
Write-Host ""
Write-Host "  [STEP 2] Verify & Apply Genesis Bundle Offline via AM CLI (Air-Gapped Activation):" -ForegroundColor Cyan
Write-Host "    am config set --endpoint `"$RokkaUrl`""
Write-Host "    am cluster fingerprint"
Write-Host "    am license inspect --bundle .\<your-license-key>.arkbundle"
Write-Host "    am license apply --bundle .\<your-license-key>.arkbundle"
Write-Host "    am auth login -u <operator-username> -p `"<operator-password>`""
Write-Host ""
Write-Host "  [STEP 3] Enroll Abodi Storage Nodes (Minimum 6 Nodes for 4+2 Cauchy Erasure Coding):" -ForegroundColor Cyan
Write-Host "    am node token create --node-code `"NODE-01`" --tier `"SAT`""
Write-Host "    .\install-abodi.ps1 -NodeCode `"NODE-01`" -RokkaUrl `"$RokkaUrl`" -EnrollmentToken `"<ET1.TOKEN>`" -StorageDir `"D:\rokka_storage`""
Write-Host ""
Write-Host "  [STEP 4] Verify Cluster Topology & Rokka Gateway:" -ForegroundColor Cyan
Write-Host "    am cluster status"
Write-Host "    am node list"
Write-Host "    am s3 config set --endpoint `"$GatewayUrl`" --access-key `"$S3AccessKeyId`" --secret-key `"$MasterKey`""
Write-Host "    am s3 mb s3://sovereign-vault --policy $DefaultStoragePolicy"
Write-Host ""
Write-Host "  [CRITICAL DISASTER RECOVERY REQUIREMENT]" -ForegroundColor Red
Write-Host "    Backup ROKKA_MASTER_KEY, ROKKA_WAL_ENCRYPTION_KEY, and ROKKA_CLUSTER_CA_PASSWORD"
Write-Host "    in your enterprise vault (HashiCorp Vault, CyberArk, 1Password, or physical safe)."
Write-Host "==============================================================================" -ForegroundColor Green
