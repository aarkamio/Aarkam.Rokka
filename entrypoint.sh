#!/usr/bin/env bash
# =========================================================================
# Aarkam Rokka Sovereign Storage Fabric Container Entrypoint (v1.0.3-GA)
# Services: Aarkam.Rokka (rokka-coordinator) & Aarkam.Rokka.Gateway (rokka-gateway)
# Supports: ROKKA_ROLE = "all" (default), "coordinator", or "gateway"
# =========================================================================

set -Eeuo pipefail

if [ "$#" -gt 0 ]; then
    exec "$@"
fi

ROLE="${ROKKA_ROLE:-all}"
ROKKA_URL="${ROKKA_COORDINATOR_URL:-https://rokka-coordinator.aarkam:57774}"
GATEWAY_URL="${ROKKA_GATEWAY_URL:-https://rokka-gateway.aarkam:57772}"
AARKAMCP_LOGIN_URL="https://aarkam.io/Administration/Auth/Login"
AARKAMCP_SUBSCRIPTION_URL="https://aarkam.io/Administration/CurrentSubscription"

AARKAM_ROOT_PUBKEY_HEX="30820222300d06092a864886f70d01010105000382020f003082020a0282020100c28d6915054cc67e5887a6e1035a376db57ce290e7a45455d4e823d2a34396dc5f155071c90e95cbe429f7177b7b35a3f033e4509f65ee30c4a40f170dbc2136257b39399cdce4a7faea53cc49e530716b54150273e2cb76e855c83616125ab18d65511562512712c931acf69811693bceb7c2421db772443ec6c00be49dd117588358a5ada90923a207d9dbce920c412645127c7283aa6957e295e1fbe7f2d8649b0d151b2eff5b25aff3eb5ced8726e65a2b160fae20b56787c42f30708a725bc965bea654078dd7e53bc245a7eef6175bd6b6d25acf38b24d481562cf25b9ec12f21e39e8c558c1587d9e18444974c4c34c772a142233b9b70ff23520b197a48a3e052c1de329bb39dee2b780593282c11af3b8d8d8b5bb2afb019f605a907e2b236eb4d28d9b795c0db1271966d9bad45373179ce223c6e7c39cb0d58d912006cadc578ccf0675e8fb4725ec2e7420425f14e1a31b9472ca4875579a04c0b0942380937cb0a20fdbe18c66fb0f30083b0925bed4ac3ffc9fd9a47ba95940587c3cec8802d78b02ebf1dae73608b971a165f0dfb17ad59072d81de07ef242870e23c51060243e6be59d8c783c65aa11e2f751e514a800cf04e0284ca6d6602ec84d16a134cb3291eb8ca4a49ae852f73f8dde798508b08185f645d38d1fd01811f35c23cf16a6ad0281d3e4c3383f246b06849c7450a7af987563309f81090203010001"

compute_footprint() {
    local host_raw
    host_raw="$(hostname 2>/dev/null || echo "rokka-node")"
    local host_upper="${host_raw^^}"
    local cores
    cores="$(nproc 2>/dev/null || echo 1)"
    local os_arch="X64"
    local machine_id="${host_raw}-AARKAM-HOST"
    if [[ -f /etc/machine-id ]]; then
        machine_id="$(tr -d '[:space:]' < /etc/machine-id)"
    fi
    local primary_mac="00155D000001"
    for net_dev in /sys/class/net/*; do
        local dev_name
        dev_name="$(basename "${net_dev}")"
        [[ "${dev_name}" == "lo" || "${dev_name}" == tun* ]] && continue
        local raw_mac
        raw_mac="$(tr -d ':\n\r ' < "${net_dev}/address" 2>/dev/null | tr '[:lower:]' '[:upper:]' || true)"
        if [[ -n "${raw_mac}" && "${raw_mac}" != "000000000000" ]]; then
            primary_mac="${raw_mac}"
            break
        fi
    done
    local payload="${host_upper}|${cores}|${os_arch}|${machine_id}|${primary_mac}"
    local ark_hex=""
    if command -v openssl >/dev/null 2>&1; then
        ark_hex="$(printf "%s" "${payload}" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:${AARKAM_ROOT_PUBKEY_HEX}" 2>/dev/null | awk '{print toupper($NF)}' || true)"
    fi
    if [[ -z "${ark_hex}" || "${#ark_hex}" -lt 24 ]]; then
        ark_hex="$(printf "%s" "${payload}" | sha256sum | awk '{print toupper($1)}')"
    fi
    echo "ARK-FP-${ark_hex:0:8}-${ark_hex:8:8}-${ark_hex:16:8}"
}

FOOTPRINT="$(compute_footprint)"

# Ensure Cluster Root CA exists for Zero-Trust Node Enrollment
SECURITY_DIR="/var/lib/rokka/security"
META_DIR="/var/lib/rokka/metadata"
mkdir -p "${SECURITY_DIR}" "${META_DIR}" /app/aarkam_metadata
CA_PASS="${ROKKA_CLUSTER_CA_PASSWORD:-AARKAM_SOVEREIGN_CA_SECRET_PASSPHRASE}"
export ROKKA_CLUSTER_CA_PASSWORD="${CA_PASS}"

if [[ ! -f "${META_DIR}/ca.pfx" ]] && command -v openssl >/dev/null 2>&1; then
    openssl ecparam -name prime256v1 -genkey -noout -out "${SECURITY_DIR}/ca.key" 2>/dev/null
    openssl req -new -x509 -sha256 -key "${SECURITY_DIR}/ca.key" -out "${SECURITY_DIR}/ca.crt" -days 3650 \
        -subj "/CN=Aarkam Cluster Root CA/O=Aarkam Cluster/OU=Sovereign PKI" 2>/dev/null
    openssl pkcs12 -export -out "${META_DIR}/ca.pfx" -inkey "${SECURITY_DIR}/ca.key" -in "${SECURITY_DIR}/ca.crt" \
        -passout "pass:${CA_PASS}" 2>/dev/null
    cp -f "${META_DIR}/ca.pfx" "${SECURITY_DIR}/ca.pfx"
    cp -f "${META_DIR}/ca.pfx" "/app/aarkam_metadata/ca.pfx"
fi

echo "=============================================================================="
echo " Aarkam Rokka Sovereign Storage Fabric (v1.0.3-GA)"
echo " Services: Aarkam.Rokka (Coordinator) & Aarkam.Rokka.Gateway (Gateway)"
echo " Role: ${ROLE}"
echo "------------------------------------------------------------------------------"
echo " Rokka Coordinator:              ${ROKKA_URL} (Ports: 57774 HTTPS / 7774 gRPC)"
echo " Rokka Gateway:                  ${GATEWAY_URL} (Ports: 57772 HTTPS / 7772 HTTP)"
echo " Rokka Coordinator Footprint:    ${FOOTPRINT}"
echo " AarkamCP (Customer Portal) Url: ${AARKAMCP_LOGIN_URL}"
echo " AarkamCP Subscription Portal:   ${AARKAMCP_SUBSCRIPTION_URL}"
echo "=============================================================================="

case "${ROLE,,}" in
    coordinator|aarkam.rokka)
        echo "[INFO] Launching Aarkam.Rokka (rokka-coordinator)..."
        exec /app/rokka-coordinator
        ;;
    gateway|aarkam.rokka.gateway)
        echo "[INFO] Launching Aarkam.Rokka.Gateway (rokka-gateway)..."
        exec /app/rokka-gateway
        ;;
    all|both|cluster)
        echo "[INFO] Launching both Aarkam.Rokka (rokka-coordinator) and Aarkam.Rokka.Gateway (rokka-gateway)..."
        /app/rokka-coordinator &
        COORD_PID=$!

        sleep 2

        /app/rokka-gateway &
        GW_PID=$!

        trap "echo '[INFO] Terminating Aarkam.Rokka and Aarkam.Rokka.Gateway daemons...'; kill -TERM $COORD_PID $GW_PID 2>/dev/null || true; wait $COORD_PID $GW_PID 2>/dev/null || true" SIGINT SIGTERM

        wait -n "$COORD_PID" "$GW_PID"
        ;;
    *)
        echo "[ERROR] Unknown ROKKA_ROLE: '${ROLE}'. Expected: 'coordinator', 'gateway', or 'all'."
        exit 1
        ;;
esac
