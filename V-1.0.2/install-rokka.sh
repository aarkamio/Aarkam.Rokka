#!/usr/bin/env bash
# ==============================================================================
# Aarkam Rokka Sovereign Storage Engine (v1.0.2-GA) — Linux Production Installer
# ==============================================================================
# Target OS:   Ubuntu 22.04 / 24.04 LTS, Debian 12+, RHEL / Rocky / AlmaLinux 9+
# Services:    Aarkam.Rokka (systemd unit Aarkam.Rokka.service — Coordinator)
#              Aarkam.Rokka.Gateway (systemd unit Aarkam.Rokka.Gateway.service — Gateway)
# Runtime:     Self-Contained Single-File .NET 10.0 Native Binaries
# Security:    Zero-Trust mTLS Cluster Root CA (ECDSA P-256), SPIFFE Trust Domain
#              (spiffe://aarkam.cluster), POSIX 0700/0600 Isolation, CWE-312 Key Hygiene
# ==============================================================================

set -Eeuo pipefail

ROKKA_RELEASE_VERSION="1.0.2"
REQUIRED_ABODI_MIN_VERSION="1.0.3"
REQUIRED_KDOUJA_SAT_VERSION="1.0.2"
REQUIRED_KDOUJA_SDK_VERSION="1.0.1"
REQUIRED_KDOUJA_PRIM_VERSION="1.0.6"
REQUIRED_AHMODI_VERSION="1.0.1"
REQUIRED_AM_CLI_MIN_VERSION="1.0.2"

# ------------------------------------------------------------------------------
# Standardized Aarkam V2 Service Names & Default Paths
# ------------------------------------------------------------------------------
COORDINATOR_SERVICE_NAME="Aarkam.Rokka"
GATEWAY_SERVICE_NAME="Aarkam.Rokka.Gateway"
LEGACY_COORDINATOR_SERVICE="rokka-coordinator"
LEGACY_GATEWAY_SERVICE="rokka-gateway"

INSTALL_DIR="/opt/aarkam/rokka"
CONFIG_DIR="/etc/rokka"
DATA_DIR="/var/lib/rokka"
META_DIR="/var/lib/rokka/metadata"
CATALOG_DIR="/var/lib/rokka/catalog"
SECURITY_DIR="/var/lib/rokka/security"
LOG_DIR="/var/log/rokka"
SERVICE_USER="rokka"
SERVICE_GROUP="rokka"

HOST_SHORT="$(hostname -s 2>/dev/null || hostname)"
CLUSTER_CODE=""
CLUSTER_CODE_SOURCE=""
ROLE="All"
DEFAULT_STORAGE_POLICY="4+2"
TRUST_DOMAIN="aarkam.cluster"

COORDINATOR_PORT=7774
COORDINATOR_HTTPS_PORT=57774
COORDINATOR_HTTPS_PORT_EXPLICIT="false"
GATEWAY_PORT=7772
GATEWAY_HTTPS_PORT=57772
GATEWAY_HTTPS_PORT_EXPLICIT="false"

ROKKA_URL=""
ROKKA_URL_EXPLICIT="false"
GATEWAY_URL=""
GATEWAY_URL_EXPLICIT="false"

BINARY_SOURCE=""
MASTER_KEY=""
WAL_KEY=""
CA_PASSWORD=""
CLUSTER_SECRET=""
S3_ACCESS_KEY_ID="rokka_admin"
ROTATE_KEYS="false"
RESET_METADATA="false"
RUN_AS_ROOT="false"
SKIP_SYSCTL="false"
SKIP_FIREWALL="false"
SKIP_START="false"
OFFLINE_MODE="false"
CHECK_ONLY="false"

AARKAMCP_LOGIN_URL="https://aarkam.io/Administration/Auth/Login"
AARKAMCP_SUBSCRIPTION_URL="https://aarkam.io/Administration/CurrentSubscription"

# Official Aarkam Root Public Key DER Hex (matches SovereignLicenseVerifier.OfficialAarkamRootPublicKeyBytes)
AARKAM_ROOT_PUBKEY_HEX="30820222300d06092a864886f70d01010105000382020f003082020a0282020100c28d6915054cc67e5887a6e1035a376db57ce290e7a45455d4e823d2a34396dc5f155071c90e95cbe429f7177b7b35a3f033e4509f65ee30c4a40f170dbc2136257b39399cdce4a7faea53cc49e530716b54150273e2cb76e855c83616125ab18d65511562512712c931acf69811693bceb7c2421db772443ec6c00be49dd117588358a5ada90923a207d9dbce920c412645127c7283aa6957e295e1fbe7f2d8649b0d151b2eff5b25aff3eb5ced8726e65a2b160fae20b56787c42f30708a725bc965bea654078dd7e53bc245a7eef6175bd6b6d25acf38b24d481562cf25b9ec12f21e39e8c558c1587d9e18444974c4c34c772a142233b9b70ff23520b197a48a3e052c1de329bb39dee2b780593282c11af3b8d8d8b5bb2afb019f605a907e2b236eb4d28d9b795c0db1271966d9bad45373179ce223c6e7c39cb0d58d912006cadc578ccf0675e8fb4725ec2e7420425f14e1a31b9472ca4875579a04c0b0942380937cb0a20fdbe18c66fb0f30083b0925bed4ac3ffc9fd9a47ba95940587c3cec8802d78b02ebf1dae73608b971a165f0dfb17ad59072d81de07ef242870e23c51060243e6be59d8c783c65aa11e2f751e514a800cf04e0284ca6d6602ec84d16a134cb3291eb8ca4a49ae852f73f8dde798508b08185f645d38d1fd01811f35c23cf16a6ad0281d3e4c3383f246b06849c7450a7af987563309f81090203010001"

# ------------------------------------------------------------------------------
# Output Formatting Helpers
# ------------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ------------------------------------------------------------------------------
# Helper: Generate Random 15-Char ClusterCode (XXXX-XXXX-XXXXX, >=1 digit per part)
# ------------------------------------------------------------------------------
generate_random_code_part() {
    local len="$1"
    local part=""
    while true; do
        part="$(LC_ALL=C tr -dc '0-9A-Z' < /dev/urandom | head -c "${len}" || true)"
        if [[ "${#part}" -eq "${len}" && "${part}" =~ [0-9] && "${part}" =~ [A-Z] ]]; then
            echo "${part}"
            return 0
        fi
    done
}

generate_random_cluster_code() {
    local p1 p2 p3
    p1="$(generate_random_code_part 4)"
    p2="$(generate_random_code_part 4)"
    p3="$(generate_random_code_part 5)"
    echo "${p1}-${p2}-${p3}"
}

extract_cluster_code_from_file() {
    local file="$1"
    if [[ ! -f "${file}" ]]; then
        return 1
    fi
    local val
    val="$(grep -oE '"ClusterCode"[[:space:]]*:[[:space:]]*"[^"]+"' "${file}" 2>/dev/null | head -n 1 | sed -E 's/.*"ClusterCode"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/' || true)"
    val="$(echo "${val}" | tr -d '[:space:]')"
    if [[ -n "${val}" && "${val^^}" != "YOUR_CLUSTER_CODE" && "${val^^}" != "CLUSTER-PLACEHOLDER" && "${val}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$ ]]; then
        echo "${val}"
        return 0
    fi
    return 1
}

# ------------------------------------------------------------------------------
# Helper: Generate 256-Bit (64-Hex) Cryptographic Key
# ------------------------------------------------------------------------------
generate_hex_key_256() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32 | tr '[:lower:]' '[:upper:]'
    else
        od -An -N32 -tx1 /dev/urandom | tr -d ' \n' | tr '[:lower:]' '[:upper:]'
    fi
}

# ------------------------------------------------------------------------------
# Helper: Compute Deterministic Rokka Coordinator Footprint (ARK-FP-*)
# Matches Rokka.Common.Security.ClusterHardwareProfiler.GetClusterFingerprint()
# ------------------------------------------------------------------------------
ROKKA_COORDINATOR_FOOTPRINT=""
ROKKA_HARDWARE_SUMMARY=""

compute_rokka_coordinator_footprint() {
    local total_ram_mb="${1:-0}"
    local disk_count="${2:-1}"

    local host_raw
    host_raw="$(hostname 2>/dev/null || echo "${HOST_SHORT}")"
    local host_upper="${host_raw^^}"
    local cores
    cores="$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo 1)"
    local os_arch="X64"

    # 1. Machine ID (matches ClusterHardwareProfiler.GetSystemMachineId on Linux)
    local machine_id="${host_raw}-AARKAM-HOST"
    if [[ -f /etc/machine-id ]]; then
        machine_id="$(tr -d '[:space:]' < /etc/machine-id)"
    elif [[ -f /var/lib/dbus/machine-id ]]; then
        machine_id="$(tr -d '[:space:]' < /var/lib/dbus/machine-id)"
    elif [[ -f /sys/class/dmi/id/product_uuid ]]; then
        machine_id="$(tr -d '[:space:]' < /sys/class/dmi/id/product_uuid)"
    fi

    # 2. Primary Physical MAC Address (matches ClusterHardwareProfiler.GetPrimaryMacAddress)
    local primary_mac="00155D000001"
    local formatted_mac="00:15:5D:00:00:01"
    for net_dev in /sys/class/net/*; do
        local dev_name
        dev_name="$(basename "${net_dev}")"
        if [[ "${dev_name}" == "lo" || "${dev_name}" == tun* || "${dev_name}" == tap* ]]; then
            continue
        fi
        local operstate
        operstate="$(cat "${net_dev}/operstate" 2>/dev/null || echo "down")"
        if [[ "${operstate}" == "up" || "${operstate}" == "unknown" ]]; then
            local raw_mac
            raw_mac="$(tr -d ':\n\r ' < "${net_dev}/address" 2>/dev/null | tr '[:lower:]' '[:upper:]' || true)"
            if [[ -n "${raw_mac}" && "${raw_mac}" != "000000000000" ]]; then
                primary_mac="${raw_mac}"
                formatted_mac="$(tr -d '\n\r ' < "${net_dev}/address" 2>/dev/null | tr '[:lower:]' '[:upper:]' || echo "${raw_mac}")"
                break
            fi
        fi
    done

    # 3. Sovereign Hardware Footprint (ARK-FP-XXXXXXXX-XXXXXXXX-XXXXXXXX)
    # NOTE: profile_payload MUST stay identical to ClusterHardwareProfiler.GetClusterFingerprint()
    local profile_payload="${host_upper}|${cores}|${os_arch}|${machine_id}|${primary_mac}"
    local ark_hex=""
    if command -v openssl >/dev/null 2>&1; then
        ark_hex="$(printf "%s" "${profile_payload}" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:${AARKAM_ROOT_PUBKEY_HEX}" 2>/dev/null | awk '{print toupper($NF)}' || true)"
    fi
    if [[ -z "${ark_hex}" || "${#ark_hex}" -lt 24 ]]; then
        ark_hex="$(printf "%s" "${profile_payload}" | sha256sum | awk '{print toupper($1)}')"
    fi
    ROKKA_COORDINATOR_FOOTPRINT="ARK-FP-${ark_hex:0:8}-${ark_hex:8:8}-${ark_hex:16:8}"

    local phys_cores=""
    if command -v lscpu >/dev/null 2>&1; then
        local cps sockets
        cps="$(lscpu 2>/dev/null | awk -F: '/Core\(s\) per socket/ {gsub(/[^0-9]/,"",$2); print $2; exit}' || true)"
        sockets="$(lscpu 2>/dev/null | awk -F: '/Socket\(s\)/ {gsub(/[^0-9]/,"",$2); print $2; exit}' || true)"
        if [[ -n "${cps}" && -n "${sockets}" && "${cps}" -gt 0 && "${sockets}" -gt 0 ]]; then
            phys_cores="$((cps * sockets))"
        fi
    fi
    local cpu_summary
    if [[ -n "${phys_cores}" && "${phys_cores}" -gt 0 ]]; then
        cpu_summary="${phys_cores} Core(s) / ${cores} Thread(s) (${os_arch})"
    else
        cpu_summary="${cores} Logical CPU(s) (${os_arch})"
    fi
    local ram_gb
    ram_gb="$(awk -v mb="${total_ram_mb}" 'BEGIN { printf "%.1f", mb / 1024 }')"
    ROKKA_HARDWARE_SUMMARY="Host: ${host_raw} | ${cpu_summary} | ${ram_gb} GB RAM | ${disk_count} Physical Disk(s) | MAC: ${formatted_mac} | MachineID: ${machine_id}"
}

usage() {
    cat <<EOF
Usage: sudo ./install-rokka.sh [OPTIONS]

Automated production installer for the Aarkam Rokka Sovereign Storage Engine (v${ROKKA_RELEASE_VERSION}-GA).
Registers systemd services following the Aarkam V2 service naming structure:
  • ${COORDINATOR_SERVICE_NAME}         (rokka-coordinator — Control Plane, Raft Quorum & Node CA)
  • ${GATEWAY_SERVICE_NAME} (rokka-gateway     — Sovereign Storage Gateway & Ahmodi Cauchy EC)

Options:
  --cluster-code <id>            Unique cluster identifier (if omitted: checks config or generates XXXX-XXXX-XXXXX)
  --rokka-url <url>              Rokka Coordinator endpoint (default: https://rokka-coordinator.aarkam:57774)
  --gateway-url <url>            Rokka Gateway endpoint (default: https://rokka-gateway.aarkam:57772)
  --trust-domain <domain>        Zero-Trust SPIFFE trust domain (default: ${TRUST_DOMAIN})
  --role <all|coordinator|gateway> Deployment role on this server (default: All)
  --coordinator-port <port>      Coordinator HTTP/2 gRPC & health port (default: ${COORDINATOR_PORT})
  --coordinator-https-port <pt>  Coordinator HTTPS / mTLS control plane port (default: ${COORDINATOR_HTTPS_PORT})
  --gateway-port <port>          Gateway HTTP port (default: ${GATEWAY_PORT})
  --gateway-https-port <port>    Gateway HTTPS port (default: ${GATEWAY_HTTPS_PORT})
  --storage-policy <policy>      Default Cauchy Reed-Solomon profile: 4+2 (default), 8+3, 8+4, or 16+4
  --install-dir <path>           Target installation directory (default: ${INSTALL_DIR})
  --data-dir <path>              Target data & metadata directory (default: ${DATA_DIR})
  --source, --source-path <path> Path to pre-published Rokka binaries or release .zip archive
  --master-key <hex64>           64-char hex AES-256 master key (ROKKA_MASTER_KEY)
  --wal-key <hex64>              64-char hex AES-256 Kdouja WAL encryption key (ROKKA_WAL_ENCRYPTION_KEY)
  --ca-password <passphrase>     Passphrase protecting the Cluster Root CA (ROKKA_CLUSTER_CA_PASSWORD)
  --cluster-secret <hex64>       64-char hex Raft quorum & JWT signing secret (ROKKA_CLUSTER_SECRET)
  --s3-access-key <id>           Root S3 Access Key ID (default: ${S3_ACCESS_KEY_ID})
  --rotate-keys                  Force generation of new cryptographic keys and PKI certificates
  --reset-metadata               Clear existing Coordinator metadata and Gateway catalog before starting
  --run-as-root                  Run systemd services as root instead of dedicated '${SERVICE_USER}' account
  --skip-sysctl                  Skip Linux kernel and network sysctl tuning
  --skip-firewall                Skip UFW / firewalld port configuration
  --skip-start                   Configure and enable systemd units without starting them immediately
  --start-services               Start Aarkam.Rokka and Aarkam.Rokka.Gateway immediately (default)
  --offline                      Air-gapped mode: skip apt/dnf package manager calls if tools exist
  --check-only                   Run pre-flight system requirements & Rokka Coordinator Footprint checks only
  -h, --help                     Display this help message
EOF
    exit 0
}

# ------------------------------------------------------------------------------
# Parse Command-Line Arguments
# ------------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --cluster-code)           CLUSTER_CODE="$2"; shift 2 ;;
        --rokka-url)              ROKKA_URL="$2"; ROKKA_URL_EXPLICIT="true"; shift 2 ;;
        --gateway-url)            GATEWAY_URL="$2"; GATEWAY_URL_EXPLICIT="true"; shift 2 ;;
        --trust-domain)           TRUST_DOMAIN="$2"; shift 2 ;;
        --role)                   ROLE="$2"; shift 2 ;;
        --coordinator-port)       COORDINATOR_PORT="$2"; shift 2 ;;
        --coordinator-https-port) COORDINATOR_HTTPS_PORT="$2"; COORDINATOR_HTTPS_PORT_EXPLICIT="true"; shift 2 ;;
        --gateway-port)           GATEWAY_PORT="$2"; shift 2 ;;
        --gateway-https-port)     GATEWAY_HTTPS_PORT="$2"; GATEWAY_HTTPS_PORT_EXPLICIT="true"; shift 2 ;;
        --storage-policy)         DEFAULT_STORAGE_POLICY="$2"; shift 2 ;;
        --install-dir)            INSTALL_DIR="$2"; shift 2 ;;
        --data-dir)               DATA_DIR="$2"; shift 2 ;;
        --source|--source-path)   BINARY_SOURCE="$2"; shift 2 ;;
        --master-key)             MASTER_KEY="$2"; shift 2 ;;
        --wal-key)                WAL_KEY="$2"; shift 2 ;;
        --ca-password)            CA_PASSWORD="$2"; shift 2 ;;
        --cluster-secret)         CLUSTER_SECRET="$2"; shift 2 ;;
        --s3-access-key)          S3_ACCESS_KEY_ID="$2"; shift 2 ;;
        --rotate-keys)            ROTATE_KEYS="true"; shift ;;
        --reset-metadata)         RESET_METADATA="true"; shift ;;
        --run-as-root)            RUN_AS_ROOT="true"; shift ;;
        --skip-sysctl)            SKIP_SYSCTL="true"; shift ;;
        --skip-firewall)          SKIP_FIREWALL="true"; shift ;;
        --skip-start)             SKIP_START="true"; shift ;;
        --start-services|--start-service) SKIP_START="false"; shift ;;
        --offline)                OFFLINE_MODE="true"; shift ;;
        --check-only)             CHECK_ONLY="true"; shift ;;
        -h|--help)                usage ;;
        *)                        log_error "Unknown option: $1"; usage ;;
    esac
done

echo -e "${BLUE}==============================================================================${NC}"
echo -e "${CYAN} Aarkam Rokka Sovereign Storage Engine — Linux Server Installer               ${NC}"
echo -e "${BLUE} Release Version: v${ROKKA_RELEASE_VERSION}-GA (V-${ROKKA_RELEASE_VERSION}) | Services: ${COORDINATOR_SERVICE_NAME} & ${GATEWAY_SERVICE_NAME} ${NC}"
echo -e "${BLUE}==============================================================================${NC}"

# Normalize Role
case "${ROLE,,}" in
    all|both|cluster) ROLE="All" ;;
    coordinator)      ROLE="Coordinator" ;;
    gateway)          ROLE="Gateway" ;;
    *)
        log_error "Invalid --role '${ROLE}'. Expected 'All', 'Coordinator', or 'Gateway'."
        exit 1
        ;;
esac

# Resolve Default Rokka Coordinator URL: https://rokka-coordinator.aarkam:57774 if user did not specify one
if [[ -z "${ROKKA_URL}" ]]; then
    if [[ "${COORDINATOR_HTTPS_PORT}" == "443" ]]; then
        ROKKA_URL="https://rokka-coordinator.aarkam"
    else
        ROKKA_URL="https://rokka-coordinator.aarkam:${COORDINATOR_HTTPS_PORT}"
    fi
else
    ROKKA_URL="${ROKKA_URL%/}"
    if [[ "${ROKKA_URL}" != http://* && "${ROKKA_URL}" != https://* ]]; then
        ROKKA_URL="https://${ROKKA_URL}"
    fi
    if [[ "${COORDINATOR_HTTPS_PORT_EXPLICIT}" == "false" ]]; then
        extracted_port="$(echo "${ROKKA_URL}" | sed -nE 's|^https?://[^/:]+:([0-9]+).*|\1|p')"
        if [[ -n "${extracted_port}" ]]; then
            COORDINATOR_HTTPS_PORT="${extracted_port}"
        fi
    fi
fi

# Resolve Default Rokka Gateway URL: https://rokka-gateway.aarkam:57772 if user did not specify one
if [[ -z "${GATEWAY_URL}" ]]; then
    if [[ "${GATEWAY_HTTPS_PORT}" == "443" ]]; then
        GATEWAY_URL="https://rokka-gateway.aarkam"
    else
        GATEWAY_URL="https://rokka-gateway.aarkam:${GATEWAY_HTTPS_PORT}"
    fi
else
    GATEWAY_URL="${GATEWAY_URL%/}"
    if [[ "${GATEWAY_URL}" != http://* && "${GATEWAY_URL}" != https://* ]]; then
        GATEWAY_URL="https://${GATEWAY_URL}"
    fi
    if [[ "${GATEWAY_HTTPS_PORT_EXPLICIT}" == "false" ]]; then
        extracted_gw_port="$(echo "${GATEWAY_URL}" | sed -nE 's|^https?://[^/:]+:([0-9]+).*|\1|p')"
        if [[ -n "${extracted_gw_port}" ]]; then
            GATEWAY_HTTPS_PORT="${extracted_gw_port}"
        fi
    fi
fi

COORD_HOST="$(echo "${ROKKA_URL}" | sed -E 's|^https?://([^/:]+).*|\1|')"
GW_HOST="$(echo "${GATEWAY_URL}" | sed -E 's|^https?://([^/:]+).*|\1|')"

BIN_DIR="${INSTALL_DIR}/bin"
META_DIR="${DATA_DIR}/metadata"
CATALOG_DIR="${DATA_DIR}/catalog"
SECURITY_DIR="${DATA_DIR}/security"

# ------------------------------------------------------------------------------
# Step 0: Locate Release Payload & Resolve ClusterCode
# ------------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMP_ZIP_DIR=""
RESOLVED_COORD=""
RESOLVED_GW=""

cleanup_temp() {
    if [[ -n "${TEMP_ZIP_DIR}" && -d "${TEMP_ZIP_DIR}" ]]; then
        rm -rf "${TEMP_ZIP_DIR}"
    fi
}
trap cleanup_temp EXIT

CANDIDATE_SOURCES=(
    "${BINARY_SOURCE}"
    "$(pwd)"
    "${SCRIPT_DIR}"
    "${SCRIPT_DIR}/linux"
    "${SCRIPT_DIR}/V-${ROKKA_RELEASE_VERSION}/linux"
    "${SCRIPT_DIR}/V-${ROKKA_RELEASE_VERSION}/rokka-v${ROKKA_RELEASE_VERSION}-linux-x64.zip"
    "${SCRIPT_DIR}/rokka-v${ROKKA_RELEASE_VERSION}-linux-x64.zip"
    "${SCRIPT_DIR}/../dist/bundles/rokka-v${ROKKA_RELEASE_VERSION}-linux-x64.zip"
    "${SCRIPT_DIR}/../dist/staging/linux-x64"
    "${SCRIPT_DIR}/../dist/linux-x64"
    "${SCRIPT_DIR}/.."
)

for cand in "${CANDIDATE_SOURCES[@]}"; do
    if [[ -z "${cand}" || ! -e "${cand}" ]]; then continue; fi

    if [[ -f "${cand}" && "${cand}" == *.zip ]]; then
        if [[ "${CHECK_ONLY}" == "false" ]]; then
            log_info "Extracting release bundle '${cand}'..."
            TEMP_ZIP_DIR="$(mktemp -d /tmp/rokka_inst_XXXXXX)"
            unzip -q "${cand}" -d "${TEMP_ZIP_DIR}"
            cand="${TEMP_ZIP_DIR}"
        else
            log_ok "Located release archive: ${cand}"
            break
        fi
    fi

    if [[ -d "${cand}" ]]; then
        c_cand=""
        g_cand=""
        if [[ -f "${cand}/rokka-coordinator" ]]; then c_cand="${cand}/rokka-coordinator"; elif [[ -f "${cand}/Rokka.Coordinator" ]]; then c_cand="${cand}/Rokka.Coordinator"; fi
        if [[ -f "${cand}/rokka-gateway" ]]; then g_cand="${cand}/rokka-gateway"; elif [[ -f "${cand}/Rokka.Gateway" ]]; then g_cand="${cand}/Rokka.Gateway"; fi

        if [[ -n "${c_cand}" || -n "${g_cand}" ]]; then
            [[ -n "${c_cand}" ]] && RESOLVED_COORD="$(cd "$(dirname "${c_cand}")" && pwd)/$(basename "${c_cand}")"
            [[ -n "${g_cand}" ]] && RESOLVED_GW="$(cd "$(dirname "${g_cand}")" && pwd)/$(basename "${g_cand}")"
            break
        fi
    fi
done

[[ -n "${RESOLVED_COORD}" ]] && log_ok "Located Rokka Coordinator native binary: ${RESOLVED_COORD}"
[[ -n "${RESOLVED_GW}" ]]    && log_ok "Located Rokka Gateway native binary:     ${RESOLVED_GW}"

if [[ -n "${CLUSTER_CODE}" ]]; then
    CLUSTER_CODE_SOURCE="CLI Parameter (--cluster-code)"
else
    SETTINGS_CANDIDATES=(
        "$(pwd)/coordinator.settings.json"
        "${SCRIPT_DIR}/coordinator.settings.json"
        "${SCRIPT_DIR}/linux/coordinator.settings.json"
        "${CONFIG_DIR}/coordinator.settings.json"
        "${BIN_DIR}/coordinator.settings.json"
    )
    for cfg in "${SETTINGS_CANDIDATES[@]}"; do
        if found_code="$(extract_cluster_code_from_file "${cfg}")"; then
            CLUSTER_CODE="${found_code}"
            CLUSTER_CODE_SOURCE="Loaded from ${cfg}"
            log_ok "Resolved existing ClusterCode '${CLUSTER_CODE}' from '${cfg}'."
            break
        fi
    done

    if [[ -z "${CLUSTER_CODE}" ]]; then
        CLUSTER_CODE="$(generate_random_cluster_code)"
        CLUSTER_CODE_SOURCE="Auto-Generated (XXXX-XXXX-XXXXX, 15 chars)"
        log_info "Generated ClusterCode: ${CLUSTER_CODE} (15 chars [4-4-5])"
    fi
fi

log_info "Validating Aarkam V2 Ecosystem Version Compatibility Matrix:"
echo "  • Aarkam Rokka Coordinator   : v${ROKKA_RELEASE_VERSION}-GA (V-${ROKKA_RELEASE_VERSION}) | Service: ${COORDINATOR_SERVICE_NAME} (:57774 / :7774)"
echo "  • Aarkam Rokka Gateway       : v${ROKKA_RELEASE_VERSION}-GA (V-${ROKKA_RELEASE_VERSION}) | Service: ${GATEWAY_SERVICE_NAME} (:57772 / :7772)"
echo "  • Aarkam Abodi Node Agent    : >= v${REQUIRED_ABODI_MIN_VERSION} (Service: Aarkam.Abodi, mTLS :57775 / :57776)"
echo "  • Aarkam Kdouja SAT Engine   : v${REQUIRED_KDOUJA_SAT_VERSION} (SDK v${REQUIRED_KDOUJA_SDK_VERSION}, Primitives v${REQUIRED_KDOUJA_PRIM_VERSION})"
echo "  • Aarkam Ahmodi Cauchy EC    : v${REQUIRED_AHMODI_VERSION} (Default Profile: ${DEFAULT_STORAGE_POLICY})"
echo "  • Aarkam AM Fleet CLI        : >= v${REQUIRED_AM_CLI_MIN_VERSION}"
echo "  • Zero-Trust SPIFFE Domain   : spiffe://${TRUST_DOMAIN}"

# ------------------------------------------------------------------------------
# Step 1: Root, Architecture, OS, Memory & Rokka Coordinator Footprint Checks
# ------------------------------------------------------------------------------
if [[ "${EUID}" -ne 0 ]]; then
    if [[ "${CHECK_ONLY}" == "true" ]]; then
        log_warn "Running in --check-only mode as non-root user (EUID=${EUID}). Production install requires sudo/root."
    else
        log_error "This installer must be executed with root privileges (use sudo)."
        exit 1
    fi
else
    log_ok "Root privilege check passed."
fi

ARCH="$(uname -m)"
if [[ "${ARCH}" != "x86_64" && "${ARCH}" != "amd64" ]]; then
    log_error "Unsupported CPU architecture '${ARCH}'. Rokka v${ROKKA_RELEASE_VERSION} requires 64-bit x86_64 (amd64)."
    exit 1
fi
log_ok "CPU architecture check passed (${ARCH})."

OS_ID="linux"
PRETTY_NAME="Linux"
if [[ -f /etc/os-release ]]; then
    # shellcheck source=/dev/null
    source /etc/os-release
    OS_ID="${ID:-linux}"
fi
KERNEL_REL="$(uname -r)"
log_info "Detected OS: ${PRETTY_NAME} | Kernel: ${KERNEL_REL} | Arch: ${ARCH}"

TOTAL_MEM_KB="$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 8388608)"
TOTAL_MEM_MB="$((TOTAL_MEM_KB / 1024))"
if (( TOTAL_MEM_MB < 3800 )); then
    log_warn "Host has ${TOTAL_MEM_MB} MB RAM. Minimum recommended for Rokka Coordinator + Gateway is 4,096 MB (16,384 MB+ for production)."
else
    log_ok "Memory check passed: ${TOTAL_MEM_MB} MB RAM available."
fi

DISK_COUNT="$(lsblk -dn -o TYPE 2>/dev/null | grep -c '^disk$' || echo 1)"
compute_rokka_coordinator_footprint "${TOTAL_MEM_MB}" "${DISK_COUNT}"
log_ok "Computed Rokka Coordinator Footprint: ${ROKKA_COORDINATOR_FOOTPRINT}"
log_info "Hardware Resource Footprint:          ${ROKKA_HARDWARE_SUMMARY}"

if command -v timedatectl >/dev/null 2>&1; then
    if timedatectl status 2>/dev/null | grep -qi "System clock synchronized: yes"; then
        log_ok "System clock is NTP synchronized (Raft quorum & mTLS clock-skew compliant)."
    else
        log_warn "System clock NTP synchronization not confirmed by timedatectl. Ensure chronyd or systemd-timesyncd is active."
    fi
fi

DATA_CHECK_PATH="${DATA_DIR}"
while [[ ! -d "${DATA_CHECK_PATH}" && "${DATA_CHECK_PATH}" != "/" ]]; do
    DATA_CHECK_PATH="$(dirname "${DATA_CHECK_PATH}")"
done
FREE_KB="$(df -Pk "${DATA_CHECK_PATH}" 2>/dev/null | awk 'NR==2 {print $4}' || echo 0)"
FREE_GB="$((FREE_KB / 1024 / 1024))"
if (( FREE_KB < 5242880 )); then
    log_warn "Metadata filesystem (${DATA_CHECK_PATH}) has ~${FREE_GB} GB free. At least 10 GB free space is recommended."
else
    log_ok "Metadata filesystem (${DATA_CHECK_PATH}) free space check passed (${FREE_GB} GB available)."
fi

if [[ "${CHECK_ONLY}" == "true" ]]; then
    echo ""
    echo -e "${GREEN}==============================================================================${NC}"
    echo -e "${GREEN} Aarkam Rokka (v${ROKKA_RELEASE_VERSION}-GA) Pre-Flight Check Complete (Linux x86_64)${NC}"
    echo -e "${GREEN}==============================================================================${NC}"
    echo "  Coordinator Service:          ${COORDINATOR_SERVICE_NAME}"
    echo "  Gateway Service:              ${GATEWAY_SERVICE_NAME}"
    echo "  Deployment Role:              ${ROLE} (Default Storage Policy: ${DEFAULT_STORAGE_POLICY})"
    echo "  Cluster Code:                 ${CLUSTER_CODE} (${CLUSTER_CODE_SOURCE})"
    echo "  Rokka Coordinator:            ${ROKKA_URL} (HTTPS/mTLS :${COORDINATOR_HTTPS_PORT} | gRPC :${COORDINATOR_PORT})"
    echo "  Rokka Gateway:                ${GATEWAY_URL} (HTTPS :${GATEWAY_HTTPS_PORT} | HTTP :${GATEWAY_PORT})"
    echo "  SPIFFE Trust Domain:          spiffe://${TRUST_DOMAIN}"
    echo "  Install Directory:            ${INSTALL_DIR}"
    echo "  Data & Metadata Directory:    ${DATA_DIR}"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}"
    echo -e "${YELLOW} ROKKA CLUSTER ACTIVATION & SOVEREIGN GENESIS CEREMONY INFORMATION${NC}"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}"
    echo "  AarkamCP (Customer Portal) Url: ${AARKAMCP_LOGIN_URL}"
    echo "  AarkamCP Subscription Portal:   ${AARKAMCP_SUBSCRIPTION_URL}"
    echo -e "  Rokka Coordinator Footprint:    ${GREEN}${ROKKA_COORDINATOR_FOOTPRINT}${NC}"
    echo "  Cluster Code (For Binding):     ${CLUSTER_CODE}"
    echo "  Hardware Footprint:             ${ROKKA_HARDWARE_SUMMARY}"
    echo -e "${GREEN}==============================================================================${NC}"
    exit 0
fi

# ------------------------------------------------------------------------------
# Step 2: Ensure System Prerequisites (openssl, curl, unzip, libicu, libssl3)
# ------------------------------------------------------------------------------
if [[ "${OFFLINE_MODE}" == "false" ]]; then
    case "${OS_ID}" in
        ubuntu|debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq 2>/dev/null || true
            apt-get install -y -qq curl ca-certificates openssl unzip libsqlite3-0 libicu-dev libssl3 iproute2 2>/dev/null || true
            ;;
        rhel|rocky|almalinux|centos|fedora)
            dnf install -y -q curl ca-certificates openssl unzip sqlite-libs libicu openssl-libs iproute 2>/dev/null || true
            ;;
    esac
fi

# ------------------------------------------------------------------------------
# Step 3: Resolve or Generate 256-Bit Cryptographic Keys (Zero-Trust CWE-312)
# ------------------------------------------------------------------------------
ENV_SECRET_FILE="${CONFIG_DIR}/rokka.env"
if [[ -f "${ENV_SECRET_FILE}" && "${ROTATE_KEYS}" == "false" ]]; then
    # shellcheck source=/dev/null
    source "${ENV_SECRET_FILE}" 2>/dev/null || true
fi

if [[ -z "${MASTER_KEY}" ]]; then
    if [[ -n "${ROKKA_MASTER_KEY:-}" && "${#ROKKA_MASTER_KEY}" -eq 64 && "${ROTATE_KEYS}" == "false" ]]; then
        MASTER_KEY="${ROKKA_MASTER_KEY}"
        log_ok "Preserved existing 256-bit ROKKA_MASTER_KEY."
    else
        MASTER_KEY="$(generate_hex_key_256)"
        log_info "Generated cryptographically secure 256-bit Master Key (ROKKA_MASTER_KEY)."
    fi
fi

if [[ -z "${WAL_KEY}" ]]; then
    if [[ -n "${ROKKA_WAL_ENCRYPTION_KEY:-}" && "${#ROKKA_WAL_ENCRYPTION_KEY}" -eq 64 && "${ROTATE_KEYS}" == "false" ]]; then
        WAL_KEY="${ROKKA_WAL_ENCRYPTION_KEY}"
        log_ok "Preserved existing 256-bit ROKKA_WAL_ENCRYPTION_KEY."
    else
        WAL_KEY="$(generate_hex_key_256)"
        log_info "Generated cryptographically secure 256-bit Kdouja WAL Encryption Key (ROKKA_WAL_ENCRYPTION_KEY)."
    fi
fi

if [[ -z "${CA_PASSWORD}" ]]; then
    if [[ -n "${ROKKA_CLUSTER_CA_PASSWORD:-}" && "${ROTATE_KEYS}" == "false" ]]; then
        CA_PASSWORD="${ROKKA_CLUSTER_CA_PASSWORD}"
        log_ok "Preserved existing ROKKA_CLUSTER_CA_PASSWORD."
    else
        CA_PASSWORD="$(generate_hex_key_256)"
        log_info "Generated cryptographically secure Cluster Root CA Passphrase (ROKKA_CLUSTER_CA_PASSWORD)."
    fi
fi

if [[ -z "${CLUSTER_SECRET}" ]]; then
    if [[ -n "${ROKKA_CLUSTER_SECRET:-}" && "${#ROKKA_CLUSTER_SECRET}" -ge 32 && "${ROTATE_KEYS}" == "false" ]]; then
        CLUSTER_SECRET="${ROKKA_CLUSTER_SECRET}"
        log_ok "Preserved existing ROKKA_CLUSTER_SECRET."
    else
        CLUSTER_SECRET="$(generate_hex_key_256)"
        log_info "Generated cryptographically secure Raft Quorum & JWT Cluster Secret (ROKKA_CLUSTER_SECRET)."
    fi
fi

# ------------------------------------------------------------------------------
# Step 4: Create Dedicated Service Account & Zero-Trust Directory Hierarchy
# ------------------------------------------------------------------------------
log_info "Provisioning service account and isolated Zero-Trust filesystem layout..."

if ! getent group "${SERVICE_GROUP}" >/dev/null 2>&1; then
    groupadd --system "${SERVICE_GROUP}"
fi

if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    useradd --system \
        --gid "${SERVICE_GROUP}" \
        --home-dir "${DATA_DIR}" \
        --no-create-home \
        --shell /usr/sbin/nologin \
        --comment "Aarkam Rokka Sovereign Storage Engine" \
        "${SERVICE_USER}"
    log_ok "Created system user '${SERVICE_USER}'."
fi

mkdir -p "${INSTALL_DIR}" "${BIN_DIR}" "${CONFIG_DIR}" "${DATA_DIR}" "${META_DIR}" "${CATALOG_DIR}" "${SECURITY_DIR}" "${LOG_DIR}"
chmod 0755 "${INSTALL_DIR}" "${BIN_DIR}"
chmod 0750 "${CONFIG_DIR}" "${DATA_DIR}" "${META_DIR}" "${CATALOG_DIR}" "${LOG_DIR}"
chmod 0700 "${SECURITY_DIR}"

# ------------------------------------------------------------------------------
# Step 5: Bootstrap Zero-Trust ECDSA P-256 Cluster Root CA & Server TLS Certificate
# ------------------------------------------------------------------------------
CA_PFX_PATH="${SECURITY_DIR}/ca.pfx"
CA_CRT_PATH="${SECURITY_DIR}/ca.crt"
CA_KEY_PATH="${SECURITY_DIR}/ca.key"
META_CA_PFX_PATH="${META_DIR}/ca.pfx"
SERVER_PFX_PATH="${SECURITY_DIR}/rokka-server-tls.pfx"

bootstrap_cluster_pki() {
    if [[ ! -f "${CA_PFX_PATH}" || "${ROTATE_KEYS}" == "true" ]]; then
        log_info "Generating Zero-Trust ECDSA P-256 Cluster Root CA (CN=Aarkam Cluster Root CA)..."
        umask 0077
        openssl ecparam -name prime256v1 -genkey -noout -out "${CA_KEY_PATH}"
        openssl req -new -x509 -sha256 -key "${CA_KEY_PATH}" -out "${CA_CRT_PATH}" -days 3650 \
            -subj "/CN=Aarkam Cluster Root CA/O=Aarkam Cluster/OU=Sovereign PKI" \
            -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
            -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" 2>/dev/null || \
        openssl req -new -x509 -sha256 -key "${CA_KEY_PATH}" -out "${CA_CRT_PATH}" -days 3650 \
            -subj "/CN=Aarkam Cluster Root CA/O=Aarkam Cluster/OU=Sovereign PKI"

        openssl pkcs12 -export -out "${CA_PFX_PATH}" \
            -inkey "${CA_KEY_PATH}" -in "${CA_CRT_PATH}" \
            -passout "pass:${CA_PASSWORD}"
        log_ok "Generated Cluster Root CA at '${CA_PFX_PATH}' (Public Cert: '${CA_CRT_PATH}')."
    else
        log_ok "Existing Cluster Root CA detected at '${CA_PFX_PATH}'."
    fi

    cp -f "${CA_PFX_PATH}" "${META_CA_PFX_PATH}"

    if [[ ! -f "${SERVER_PFX_PATH}" || "${ROTATE_KEYS}" == "true" ]]; then
        log_info "Generating ECDSA P-256 Server TLS certificate for Rokka Coordinator & Gateway..."
        local srv_key="${SECURITY_DIR}/server-tls.key"
        local srv_csr="${SECURITY_DIR}/server-tls.csr"
        local srv_crt="${SECURITY_DIR}/server-tls.crt"
        local srv_ext="${SECURITY_DIR}/server-tls.ext"

        openssl ecparam -name prime256v1 -genkey -noout -out "${srv_key}"
        openssl req -new -sha256 -key "${srv_key}" -out "${srv_csr}" \
            -subj "/CN=rokka-coordinator.aarkam/O=Aarkam Cluster/OU=Rokka Substrate"

        cat > "${srv_ext}" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=DNS:rokka-coordinator.aarkam,DNS:rokka-gateway.aarkam,DNS:localhost,DNS:${HOST_SHORT},IP:127.0.0.1
EOF
        if [[ -f "${CA_KEY_PATH}" && -f "${CA_CRT_PATH}" ]]; then
            openssl x509 -req -sha256 -in "${srv_csr}" -CA "${CA_CRT_PATH}" -CAkey "${CA_KEY_PATH}" \
                -CAcreateserial -out "${srv_crt}" -days 1825 -extfile "${srv_ext}" 2>/dev/null
        else
            openssl x509 -req -sha256 -in "${srv_csr}" -signkey "${srv_key}" \
                -out "${srv_crt}" -days 1825 -extfile "${srv_ext}" 2>/dev/null
        fi

        openssl pkcs12 -export -out "${SERVER_PFX_PATH}" \
            -inkey "${srv_key}" -in "${srv_crt}" \
            -passout "pass:${CA_PASSWORD}"

        rm -f "${srv_csr}" "${srv_ext}" "${SECURITY_DIR}/ca.srl"
        log_ok "Generated Server TLS certificate at '${SERVER_PFX_PATH}'."
    fi

    chmod 0600 "${SECURITY_DIR}"/* "${META_CA_PFX_PATH}" 2>/dev/null || true
}

bootstrap_cluster_pki

# ------------------------------------------------------------------------------
# Step 6: Stop Active Services/Processes & Deploy Rokka Binaries
# ------------------------------------------------------------------------------
for unit in "${GATEWAY_SERVICE_NAME}" "${COORDINATOR_SERVICE_NAME}" "${LEGACY_GATEWAY_SERVICE}" "${LEGACY_COORDINATOR_SERVICE}"; do
    if systemctl is-active --quiet "${unit}.service" 2>/dev/null; then
        log_info "Stopping running ${unit}.service..."
        systemctl stop "${unit}.service" || true
    fi
done

for legacy_unit in "${LEGACY_GATEWAY_SERVICE}" "${LEGACY_COORDINATOR_SERVICE}"; do
    if [[ -f "/etc/systemd/system/${legacy_unit}.service" && ! -L "/etc/systemd/system/${legacy_unit}.service" ]]; then
        log_info "Removing legacy systemd unit file /etc/systemd/system/${legacy_unit}.service..."
        systemctl disable "${legacy_unit}.service" 2>/dev/null || true
        rm -f "/etc/systemd/system/${legacy_unit}.service"
    fi
done

for proc in "rokka-coordinator" "rokka-gateway" "Rokka.Coordinator" "Rokka.Gateway"; do
    if pgrep -x "${proc}" >/dev/null 2>&1; then
        log_info "Force-terminating lingering ${proc} process(es)..."
        pkill -9 -x "${proc}" 2>/dev/null || true
        sleep 1
    fi
done

if [[ "${RESET_METADATA}" == "true" ]]; then
    log_warn "Resetting existing Coordinator metadata and Gateway catalog directories (--reset-metadata)..."
    rm -rf "${META_DIR}" "${CATALOG_DIR}"
    mkdir -p "${META_DIR}" "${CATALOG_DIR}"
    chmod 0750 "${META_DIR}" "${CATALOG_DIR}"
    if [[ -f "${CA_PFX_PATH}" ]]; then
        cp -f "${CA_PFX_PATH}" "${META_CA_PFX_PATH}"
        chmod 0600 "${META_CA_PFX_PATH}"
    fi
    log_ok "Coordinator metadata and Gateway catalog directories reset cleanly."
fi

DEPLOY_COORD="false"
DEPLOY_GW="false"
[[ "${ROLE}" == "All" || "${ROLE}" == "Coordinator" ]] && DEPLOY_COORD="true"
[[ "${ROLE}" == "All" || "${ROLE}" == "Gateway" ]]     && DEPLOY_GW="true"

if [[ "${DEPLOY_COORD}" == "true" ]]; then
    if [[ -n "${RESOLVED_COORD}" && -f "${RESOLVED_COORD}" ]]; then
        if [[ "$(cd "$(dirname "${RESOLVED_COORD}")" && pwd)/$(basename "${RESOLVED_COORD}")" != "${BIN_DIR}/rokka-coordinator" ]]; then
            cp -f "${RESOLVED_COORD}" "${BIN_DIR}/rokka-coordinator"
        fi
        chmod 0755 "${BIN_DIR}/rokka-coordinator"
        ln -sf "${BIN_DIR}/rokka-coordinator" "/usr/local/bin/rokka-coordinator"
        log_ok "Deployed Rokka Coordinator binary to '${BIN_DIR}/rokka-coordinator'."
    elif [[ ! -x "${BIN_DIR}/rokka-coordinator" ]]; then
        log_error "Could not locate rokka-coordinator binary. Specify --source to a valid release directory or zip archive."
        exit 1
    fi
fi

if [[ "${DEPLOY_GW}" == "true" ]]; then
    if [[ -n "${RESOLVED_GW}" && -f "${RESOLVED_GW}" ]]; then
        if [[ "$(cd "$(dirname "${RESOLVED_GW}")" && pwd)/$(basename "${RESOLVED_GW}")" != "${BIN_DIR}/rokka-gateway" ]]; then
            cp -f "${RESOLVED_GW}" "${BIN_DIR}/rokka-gateway"
        fi
        chmod 0755 "${BIN_DIR}/rokka-gateway"
        ln -sf "${BIN_DIR}/rokka-gateway" "/usr/local/bin/rokka-gateway"
        log_ok "Deployed Rokka Gateway binary to '${BIN_DIR}/rokka-gateway'."
    elif [[ ! -x "${BIN_DIR}/rokka-gateway" ]]; then
        log_error "Could not locate rokka-gateway binary. Specify --source to a valid release directory or zip archive."
        exit 1
    fi
fi

# ------------------------------------------------------------------------------
# Step 7: Generate Decoupled Production Configurations & Restricted Environment File
# ------------------------------------------------------------------------------
cat > "${CONFIG_DIR}/coordinator.settings.json" <<EOF
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning",
      "Microsoft.Hosting.Lifetime": "Information"
    }
  },
  "AllowedHosts": "*",
  "Cluster": {
    "ClusterCode": "${CLUSTER_CODE}",
    "TrustDomain": "${TRUST_DOMAIN}",
    "PublicEndpoint": "${ROKKA_URL}"
  },
  "Security": {
    "RequireOperatorAuth": true,
    "RequireNodeMtls": false,
    "TrustDomain": "${TRUST_DOMAIN}",
    "ClusterCaCertificatePath": "${CA_PFX_PATH}"
  },
  "Aarkam": {
    "BaseDirectory": "${META_DIR}",
    "UnsafeSkipCertValidation": "true",
    "Storage": {
      "Transport": {
        "Mode": "Auto",
        "SlotSizeBytes": 4194304,
        "SlotCount": 256,
        "Port": 1,
        "GidIndex": 0,
        "EnableHugePages": true,
        "CircuitBreakerFailureThreshold": 3
      }
    }
  },
  "Rokka": {
    "BaseDirectory": "${META_DIR}",
    "DefaultStoragePolicy": "${DEFAULT_STORAGE_POLICY}",
    "Transcoder": {
      "Enabled": true,
      "ScanIntervalSeconds": 60,
      "TargetPolicy": "${DEFAULT_STORAGE_POLICY}",
      "MaxBytesPerSecond": 40000000,
      "ReclaimOriginalReplicas": true
    }
  },
  "PeerCoordinators": [],
  "Health": {
    "HeartbeatTimeoutSeconds": 30,
    "ScanIntervalSeconds": 5,
    "MinAvailableBytesThreshold": 1073741824
  },
  "Kestrel": {
    "Certificates": {
      "Default": {
        "Path": "${SERVER_PFX_PATH}"
      }
    },
    "Endpoints": {
      "gRPC-Http": {
        "Url": "http://0.0.0.0:${COORDINATOR_PORT}",
        "Protocols": "Http2"
      },
      "Https": {
        "Url": "https://0.0.0.0:${COORDINATOR_HTTPS_PORT}",
        "Protocols": "Http1AndHttp2"
      }
    }
  }
}
EOF

GW_COORD_TARGET="http://127.0.0.1:${COORDINATOR_PORT}"
if [[ "${ROLE}" == "Gateway" && "${ROKKA_URL_EXPLICIT}" == "true" ]]; then
    GW_COORD_TARGET="${ROKKA_URL}"
fi

cat > "${CONFIG_DIR}/gateway.settings.json" <<EOF
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning",
      "Microsoft.Hosting.Lifetime": "Information"
    }
  },
  "AllowedHosts": "*",
  "Cluster": {
    "ClusterCode": "${CLUSTER_CODE}",
    "TrustDomain": "${TRUST_DOMAIN}",
    "PublicGatewayEndpoint": "${GATEWAY_URL}"
  },
  "Rokka": {
    "CoordinatorAddress": "${GW_COORD_TARGET}",
    "CatalogDirectory": "${CATALOG_DIR}",
    "DefaultStoragePolicy": "${DEFAULT_STORAGE_POLICY}",
    "S3": {
      "AccessKeyId": "${S3_ACCESS_KEY_ID}"
    }
  },
  "Aarkam": {
    "BaseDirectory": "${CATALOG_DIR}",
    "UnsafeSkipCertValidation": "true",
    "Storage": {
      "Transport": {
        "Mode": "Auto",
        "SlotSizeBytes": 4194304,
        "SlotCount": 256,
        "Port": 1,
        "GidIndex": 0,
        "EnableHugePages": true,
        "CircuitBreakerFailureThreshold": 3
      }
    }
  },
  "Kestrel": {
    "Certificates": {
      "Default": {
        "Path": "${SERVER_PFX_PATH}"
      }
    },
    "Endpoints": {
      "Http": {
        "Url": "http://0.0.0.0:${GATEWAY_PORT}",
        "Protocols": "Http1"
      },
      "Https": {
        "Url": "https://0.0.0.0:${GATEWAY_HTTPS_PORT}",
        "Protocols": "Http1AndHttp2"
      }
    }
  }
}
EOF

cp -f "${CONFIG_DIR}/coordinator.settings.json" "${BIN_DIR}/coordinator.settings.json"
cp -f "${CONFIG_DIR}/gateway.settings.json" "${BIN_DIR}/gateway.settings.json"
rm -f "${BIN_DIR}/appsettings.json"

umask 0077
cat > "${ENV_SECRET_FILE}" <<EOF
ASPNETCORE_ENVIRONMENT=Production
DOTNET_PRINT_TELEMETRY_MESSAGE=false
DOTNET_CLI_TELEMETRY_OPTOUT=1
ROKKA_COORDINATOR_URL=${ROKKA_URL}
ROKKA_GATEWAY_URL=${GATEWAY_URL}
ROKKA_MASTER_KEY=${MASTER_KEY}
ROKKA_WAL_ENCRYPTION_KEY=${WAL_KEY}
ROKKA_CLUSTER_CA_PASSWORD=${CA_PASSWORD}
ROKKA_CLUSTER_SECRET=${CLUSTER_SECRET}
ROKKA_ACCESS_KEY_ID=${S3_ACCESS_KEY_ID}
ROKKA_SECRET_ACCESS_KEY=${MASTER_KEY}
Jwt__Key=${CLUSTER_SECRET}
Kestrel__Certificates__Default__Path=${SERVER_PFX_PATH}
Kestrel__Certificates__Default__Password=${CA_PASSWORD}
ASPNETCORE_Kestrel__Certificates__Default__Path=${SERVER_PFX_PATH}
ASPNETCORE_Kestrel__Certificates__Default__Password=${CA_PASSWORD}
EOF

cat > /etc/profile.d/rokka.sh <<EOF
export PATH="${BIN_DIR}:\$PATH"
export ROKKA_COORDINATOR_URL="${ROKKA_URL}"
export ROKKA_GATEWAY_URL="${GATEWAY_URL}"
EOF
chmod 0644 /etc/profile.d/rokka.sh

SVC_USER="${SERVICE_USER}"
SVC_GROUP="${SERVICE_GROUP}"
if [[ "${RUN_AS_ROOT}" == "true" ]]; then
    SVC_USER="root"
    SVC_GROUP="root"
fi

chown -R "${SVC_USER}:${SVC_GROUP}" "${INSTALL_DIR}" "${CONFIG_DIR}" "${DATA_DIR}" "${LOG_DIR}"
chmod 0640 "${CONFIG_DIR}/coordinator.settings.json" "${CONFIG_DIR}/gateway.settings.json" "${BIN_DIR}/coordinator.settings.json" "${BIN_DIR}/gateway.settings.json"
chmod 0600 "${ENV_SECRET_FILE}"
log_ok "Generated decoupled configurations and Zero-Trust environment vault (${ENV_SECRET_FILE})."

# ------------------------------------------------------------------------------
# Step 8: Apply Linux Kernel & High-Throughput Network sysctl Tuning
# ------------------------------------------------------------------------------
if [[ "${SKIP_SYSCTL}" == "false" ]]; then
    log_info "Applying production Linux kernel & storage network sysctl tuning..."
    cat > /etc/sysctl.d/99-aarkam-rokka.conf <<EOF
# Aarkam Rokka Sovereign Storage Engine & Gateway Kernel Tuning
fs.file-max = 2097152
fs.aio-max-nr = 1048576
vm.swappiness = 1
vm.max_map_count = 262144
net.core.somaxconn = 65535
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_tw_reuse = 1
EOF
    sysctl --system >/dev/null 2>&1 || log_warn "Some sysctl parameters could not be applied (containerized environment?)."
    log_ok "Applied sysctl parameters."
fi

# ------------------------------------------------------------------------------
# Step 9: Register systemd Services ('Aarkam.Rokka' & 'Aarkam.Rokka.Gateway')
# ------------------------------------------------------------------------------
if [[ "${DEPLOY_COORD}" == "true" ]]; then
    log_info "Creating hardened systemd unit /etc/systemd/system/${COORDINATOR_SERVICE_NAME}.service..."
    cat > "/etc/systemd/system/${COORDINATOR_SERVICE_NAME}.service" <<EOF
[Unit]
Description=Aarkam Rokka Sovereign Storage Coordinator, Raft Quorum & Node CA (v${ROKKA_RELEASE_VERSION})
Documentation=https://aarkam.io/docs/rokka
After=network-online.target local-fs.target
Wants=network-online.target

[Service]
Type=simple
User=${SVC_USER}
Group=${SVC_GROUP}
WorkingDirectory=${BIN_DIR}
EnvironmentFile=${ENV_SECRET_FILE}
ExecStart=${BIN_DIR}/rokka-coordinator --config ${CONFIG_DIR}/coordinator.settings.json
Restart=always
RestartSec=5s
TimeoutStopSec=30s

LimitNOFILE=1048576
LimitMEMLOCK=infinity
TasksMax=infinity

AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_DAC_READ_SEARCH

NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
ReadWritePaths=${INSTALL_DIR} ${CONFIG_DIR} ${DATA_DIR} ${META_DIR} ${SECURITY_DIR} ${LOG_DIR}

[Install]
WantedBy=multi-user.target
Alias=aarkam-rokka.service rokka-coordinator.service
EOF
fi

if [[ "${DEPLOY_GW}" == "true" ]]; then
    log_info "Creating hardened systemd unit /etc/systemd/system/${GATEWAY_SERVICE_NAME}.service..."
    AFTER_UNIT="network-online.target local-fs.target"
    WANTS_UNIT="network-online.target"
    if [[ "${DEPLOY_COORD}" == "true" ]]; then
        AFTER_UNIT="network-online.target local-fs.target ${COORDINATOR_SERVICE_NAME}.service"
        WANTS_UNIT="network-online.target ${COORDINATOR_SERVICE_NAME}.service"
    fi

    cat > "/etc/systemd/system/${GATEWAY_SERVICE_NAME}.service" <<EOF
[Unit]
Description=Aarkam Rokka Sovereign Storage & Ahmodi Cauchy Erasure Coding Gateway (v${ROKKA_RELEASE_VERSION})
Documentation=https://aarkam.io/docs/rokka
After=${AFTER_UNIT}
Wants=${WANTS_UNIT}

[Service]
Type=simple
User=${SVC_USER}
Group=${SVC_GROUP}
WorkingDirectory=${BIN_DIR}
EnvironmentFile=${ENV_SECRET_FILE}
ExecStart=${BIN_DIR}/rokka-gateway --config ${CONFIG_DIR}/gateway.settings.json
Restart=always
RestartSec=5s
TimeoutStopSec=30s

LimitNOFILE=1048576
LimitMEMLOCK=infinity
TasksMax=infinity

AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_DAC_READ_SEARCH

NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
ReadWritePaths=${INSTALL_DIR} ${CONFIG_DIR} ${DATA_DIR} ${CATALOG_DIR} ${SECURITY_DIR} ${LOG_DIR}

[Install]
WantedBy=multi-user.target
Alias=aarkam-rokka-gateway.service rokka-gateway.service
EOF
fi

systemctl daemon-reload
[[ "${DEPLOY_COORD}" == "true" ]] && systemctl enable "${COORDINATOR_SERVICE_NAME}.service" >/dev/null 2>&1 || true
[[ "${DEPLOY_GW}" == "true" ]]    && systemctl enable "${GATEWAY_SERVICE_NAME}.service" >/dev/null 2>&1 || true
log_ok "Registered and enabled systemd service unit(s): ${COORDINATOR_SERVICE_NAME}, ${GATEWAY_SERVICE_NAME}"

# ------------------------------------------------------------------------------
# Step 10: Configure Host Firewall (UFW / firewalld)
# ------------------------------------------------------------------------------
if [[ "${SKIP_FIREWALL}" == "false" ]]; then
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        log_info "Configuring UFW firewall rules for Rokka ports..."
        if [[ "${DEPLOY_COORD}" == "true" ]]; then
            ufw allow "${COORDINATOR_PORT}/tcp" comment "Aarkam Rokka Coordinator gRPC" >/dev/null || true
            ufw allow "${COORDINATOR_HTTPS_PORT}/tcp" comment "Aarkam Rokka Coordinator HTTPS mTLS" >/dev/null || true
        fi
        if [[ "${DEPLOY_GW}" == "true" ]]; then
            ufw allow "${GATEWAY_PORT}/tcp" comment "Aarkam Rokka Gateway HTTP" >/dev/null || true
            ufw allow "${GATEWAY_HTTPS_PORT}/tcp" comment "Aarkam Rokka Gateway HTTPS" >/dev/null || true
        fi
        log_ok "UFW rules updated."
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        log_info "Configuring firewalld rules for Rokka ports..."
        if [[ "${DEPLOY_COORD}" == "true" ]]; then
            firewall-cmd --permanent --add-port="${COORDINATOR_PORT}/tcp" >/dev/null || true
            firewall-cmd --permanent --add-port="${COORDINATOR_HTTPS_PORT}/tcp" >/dev/null || true
        fi
        if [[ "${DEPLOY_GW}" == "true" ]]; then
            firewall-cmd --permanent --add-port="${GATEWAY_PORT}/tcp" >/dev/null || true
            firewall-cmd --permanent --add-port="${GATEWAY_HTTPS_PORT}/tcp" >/dev/null || true
        fi
        firewall-cmd --reload >/dev/null || true
        log_ok "firewalld rules updated."
    fi
fi

# ------------------------------------------------------------------------------
# Step 11: Start Services & Probe Health Endpoints
# ------------------------------------------------------------------------------
if [[ "${SKIP_START}" == "true" ]]; then
    log_info "Skipped service startup (--skip-start). Start manually via: sudo systemctl start ${COORDINATOR_SERVICE_NAME} ${GATEWAY_SERVICE_NAME}"
else
    if [[ "${DEPLOY_COORD}" == "true" && -x "${BIN_DIR}/rokka-coordinator" ]]; then
        log_info "Starting ${COORDINATOR_SERVICE_NAME} service..."
        systemctl restart "${COORDINATOR_SERVICE_NAME}.service" || true
        sleep 2
        if systemctl is-active --quiet "${COORDINATOR_SERVICE_NAME}.service"; then
            log_ok "${COORDINATOR_SERVICE_NAME} is active and running."
            if command -v curl >/dev/null 2>&1; then
                if curl -fsS --max-time 5 "http://127.0.0.1:${COORDINATOR_PORT}/health" >/dev/null 2>&1; then
                    log_ok "Rokka Coordinator Health Probe (http://127.0.0.1:${COORDINATOR_PORT}/health) succeeded."
                else
                    log_warn "Coordinator health probe on http://127.0.0.1:${COORDINATOR_PORT}/health is still warming up."
                fi
            fi
        else
            log_error "Service '${COORDINATOR_SERVICE_NAME}' could not be started."
            jlog="$(journalctl -u "${COORDINATOR_SERVICE_NAME}.service" -n 60 --no-pager 2>/dev/null || true)"
            if grep -qE "AuthenticationTagMismatchException|AesGcmEncryptor\.Decrypt|WALReader" <<< "${jlog}"; then
                log_warn "Reason: Existing WAL metadata in '${META_DIR}' was encrypted with a different ROKKA_WAL_ENCRYPTION_KEY."
                log_info "Key Source: '${ENV_SECRET_FILE}' (loaded by systemd EnvironmentFile for ${COORDINATOR_SERVICE_NAME}.service)."
                log_info "Action: Pass --wal-key \"<original-64-hex-key>\" to preserve existing data, or re-run with --reset-metadata for a clean cluster state."
            elif grep -qE "No server certificate was specified|Unable to configure HTTPS endpoint" <<< "${jlog}"; then
                log_warn "Reason: TLS server certificate could not be loaded from '${SECURITY_DIR}'."
                log_info "Action: Re-run with --rotate-keys to regenerate the Cluster Root CA and TLS certificates."
            elif grep -qE "Failed to bind to address|address already in use" <<< "${jlog}"; then
                log_warn "Reason: One of the configured Coordinator ports (${COORDINATOR_PORT} or ${COORDINATOR_HTTPS_PORT}) is already in use."
                log_info "Action: Free the port or specify --coordinator-port / --coordinator-https-port."
            else
                log_warn "Check systemd logs for details: sudo journalctl -u ${COORDINATOR_SERVICE_NAME} -n 50 --no-pager"
            fi
        fi
    fi

    if [[ "${DEPLOY_GW}" == "true" && -x "${BIN_DIR}/rokka-gateway" ]]; then
        log_info "Starting ${GATEWAY_SERVICE_NAME} service..."
        systemctl restart "${GATEWAY_SERVICE_NAME}.service" || true
        sleep 2
        if systemctl is-active --quiet "${GATEWAY_SERVICE_NAME}.service"; then
            log_ok "${GATEWAY_SERVICE_NAME} is active and running."
            if command -v curl >/dev/null 2>&1; then
                if curl -fsS --max-time 5 "http://127.0.0.1:${GATEWAY_PORT}/health" >/dev/null 2>&1; then
                    log_ok "Rokka Gateway Health Probe (http://127.0.0.1:${GATEWAY_PORT}/health) succeeded."
                else
                    log_warn "Gateway health probe on http://127.0.0.1:${GATEWAY_PORT}/health is still warming up."
                fi
            fi
        else
            log_error "Service '${GATEWAY_SERVICE_NAME}' could not be started."
            jlog="$(journalctl -u "${GATEWAY_SERVICE_NAME}.service" -n 60 --no-pager 2>/dev/null || true)"
            if grep -qE "No server certificate was specified|Unable to configure HTTPS endpoint" <<< "${jlog}"; then
                log_warn "Reason: TLS server certificate could not be loaded from '${SECURITY_DIR}'."
                log_info "Action: Re-run with --rotate-keys to regenerate the Cluster Root CA and TLS certificates."
            elif grep -qE "Failed to bind to address|address already in use" <<< "${jlog}"; then
                log_warn "Reason: One of the configured Gateway ports (${GATEWAY_PORT} or ${GATEWAY_HTTPS_PORT}) is already in use."
                log_info "Action: Free the port or specify --gateway-port / --gateway-https-port."
            else
                log_warn "Check systemd logs for details: sudo journalctl -u ${GATEWAY_SERVICE_NAME} -n 50 --no-pager"
            fi
        fi
    fi
fi

# ------------------------------------------------------------------------------
# Step 12: Print Complete Installation & Rokka Cluster Activation Summary
# ------------------------------------------------------------------------------
echo ""
echo -e "${GREEN}==============================================================================${NC}"
echo -e "${GREEN} Aarkam Rokka Sovereign Storage Engine (v${ROKKA_RELEASE_VERSION}-GA) Installation Complete (Linux x86_64)${NC}"
echo -e "${GREEN}==============================================================================${NC}"
echo "  Coordinator Service Name:     ${COORDINATOR_SERVICE_NAME}"
echo "  Gateway Service Name:         ${GATEWAY_SERVICE_NAME}"
echo "  Deployment Role:              ${ROLE} (Default Storage Policy: ${DEFAULT_STORAGE_POLICY})"
echo "  Cluster Code:                 ${CLUSTER_CODE} (${CLUSTER_CODE_SOURCE})"
echo "  Rokka Coordinator:            ${ROKKA_URL}"
echo "  Coordinator gRPC (Internal):  http://127.0.0.1:${COORDINATOR_PORT} (Health: http://127.0.0.1:${COORDINATOR_PORT}/health)"
echo "  Rokka Gateway (HTTPS):        ${GATEWAY_URL}"
echo "  Rokka Gateway (HTTP):         http://${GW_HOST}:${GATEWAY_PORT} (Health: http://127.0.0.1:${GATEWAY_PORT}/health)"
echo "  SPIFFE Trust Domain:          spiffe://${TRUST_DOMAIN}"
echo "  Binary Directory:             ${BIN_DIR}"
echo "  Configuration Directory:      ${CONFIG_DIR}"
echo "  Zero-Trust Security Vault:    ${SECURITY_DIR} (Root CA: ${CA_PFX_PATH}, mode 0700)"
echo "  Kdouja Metadata Directory:    ${META_DIR}"
echo "  Gateway Catalog Directory:    ${CATALOG_DIR}"
echo "  Service Status Command:       sudo systemctl status ${COORDINATOR_SERVICE_NAME} ${GATEWAY_SERVICE_NAME}"
echo "  Live Logs Command:            sudo journalctl -u ${COORDINATOR_SERVICE_NAME} -u ${GATEWAY_SERVICE_NAME} -f"
echo -e "${CYAN}------------------------------------------------------------------------------${NC}"
echo -e "${YELLOW} ROKKA CLUSTER ACTIVATION & SOVEREIGN GENESIS CEREMONY INFORMATION${NC}"
echo -e "${CYAN}------------------------------------------------------------------------------${NC}"
echo "  AarkamCP (Customer Portal) Url: ${AARKAMCP_LOGIN_URL}"
echo "  AarkamCP Subscription Portal:   ${AARKAMCP_SUBSCRIPTION_URL}"
echo -e "  Rokka Coordinator Footprint:    ${GREEN}${ROKKA_COORDINATOR_FOOTPRINT}${NC}"
echo "  Cluster Code (For Binding):     ${CLUSTER_CODE}"
echo "  Host Diagnostic Profile:        ${ROKKA_HARDWARE_SUMMARY}"
echo "  Gateway Root Access Key ID:     ${S3_ACCESS_KEY_ID}"
echo -e "  ROKKA_MASTER_KEY (AES-256):     ${YELLOW}${MASTER_KEY}${NC}"
echo "  ROKKA_WAL_ENCRYPTION_KEY:       ${WAL_KEY}"
echo "  ROKKA_CLUSTER_CA_PASSWORD:      ${CA_PASSWORD}"
echo "  ROKKA_CLUSTER_SECRET:           ${CLUSTER_SECRET}"
echo ""
echo -e "  ${CYAN}[STEP 1] Bind Rokka Coordinator Footprint & Mint Genesis Bundle on AarkamCP:${NC}"
echo "    1. Sign in to AarkamCP:        ${AARKAMCP_LOGIN_URL}"
echo "    2. Open Subscription Portal:   ${AARKAMCP_SUBSCRIPTION_URL}"
echo "    3. Click 'Bind Cluster Fingerprint' and enter:"
echo "         • Cluster Fingerprint :   ${ROKKA_COORDINATOR_FOOTPRINT}"
echo "         • Cluster Code        :   ${CLUSTER_CODE}"
echo "    4. Click 'Manage Operators', add your enterprise operators (ClusterAdmin / StorageOperator),"
echo "       and click 'Download Sovereign Genesis Bundle (.arkbundle)'."
echo ""
echo -e "  ${CYAN}[STEP 2] Verify & Apply Genesis Bundle Offline via AM CLI (Air-Gapped Activation):${NC}"
echo "    am config set --endpoint \"${ROKKA_URL}\""
echo "    am cluster fingerprint"
echo "    am license inspect --bundle ./<your-license-key>.arkbundle"
echo "    am license apply --bundle ./<your-license-key>.arkbundle"
echo "    am auth login -u <operator-username> -p \"<operator-password>\""
echo ""
echo -e "  ${CYAN}[STEP 3] Enroll Abodi Storage Nodes (Minimum 6 Nodes for 4+2 Cauchy Erasure Coding):${NC}"
echo "    am node token create --node-code \"NODE-01\" --tier \"SAT\""
echo "    sudo ./install-abodi.sh --node-code \"NODE-01\" --rokka-url \"${ROKKA_URL}\" --enrollment-token \"<ET1.TOKEN>\" --storage-dir \"/var/lib/rokka/storage\""
echo ""
echo -e "  ${CYAN}[STEP 4] Verify Cluster Topology & Rokka Gateway:${NC}"
echo "    am cluster status"
echo "    am node list"
echo "    am s3 config set --endpoint \"${GATEWAY_URL}\" --access-key \"${S3_ACCESS_KEY_ID}\" --secret-key \"${MASTER_KEY}\""
echo "    am s3 mb s3://sovereign-vault --policy ${DEFAULT_STORAGE_POLICY}"
echo ""
echo -e "  ${RED}[CRITICAL DISASTER RECOVERY REQUIREMENT]${NC}"
echo "    Backup ROKKA_MASTER_KEY, ROKKA_WAL_ENCRYPTION_KEY, and ROKKA_CLUSTER_CA_PASSWORD"
echo "    (stored in ${ENV_SECRET_FILE}) in your enterprise vault (HashiCorp Vault, CyberArk, 1Password, or physical safe)."
echo -e "${GREEN}==============================================================================${NC}"
