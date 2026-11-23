<div align="center">

<img src="https://raw.githubusercontent.com/aarkamio/Aarkam/main/docs/images/aarkam-logo.png" alt="Aarkam Logo" width="180" />

# Aarkam Rokka Sovereign Storage Engine & Distributed Fabric (`v1.0.3`)
### Stateless Cluster Control Plane (`Aarkam.Rokka`), Raft Consensus Quorum & Line-Rate Storage Gateway (`Aarkam.Rokka.Gateway`)

[![Version](https://img.shields.io/badge/version-v1.0.3--GA-blue.svg?style=for-the-badge&logo=semver)](https://github.com/aarkamio/Aarkam)
[![Docker Image](https://img.shields.io/badge/docker-aarkam%2Faarkam.rokka%3Av1.0.3-2496ED.svg?style=for-the-badge&logo=docker)](https://hub.docker.com/r/aarkam/aarkam.rokka)
[![Abodi Node Agent](https://img.shields.io/badge/Aarkam.Abodi-v1.0.3%2B%20(%3A57775%2F%3A57776)-008080.svg?style=for-the-badge)](https://hub.docker.com/r/aarkam/aarkam.abodi)
[![Kdouja SAT](https://img.shields.io/badge/Kdouja%20SAT-v1.0.2%20%7C%20SDK%20v1.0.1-purple.svg?style=for-the-badge)](https://hub.docker.com/r/aarkam/aarkam.kdouja)
[![Target OS](https://img.shields.io/badge/platform-Linux%20x64%20%7C%20Windows%20x64-333333.svg?style=for-the-badge&logo=linux)](https://github.com/aarkamio/Aarkam)
[![Compliance](https://img.shields.io/badge/compliance-NCA%20ECC--2%3A2024%20%7C%20FIPS%20140--3-darkgreen.svg?style=for-the-badge)](https://github.com/aarkamio/Aarkam)

</div>

---

## 1. Overview: `Aarkam.Rokka` & `Aarkam.Rokka.Gateway`

**Aarkam Rokka (`v1.0.3-GA`)** is the autonomous, zero-egress control plane and high-speed data plane of the **Aarkam Sovereign Storage Ecosystem**. Built on **.NET 10.0** for 100% air-gapped datacenters, Rokka comprises two standardized services:

1. **`Aarkam.Rokka` (`rokka-coordinator` — Default Endpoint `https://rokka-coordinator.aarkam:57774`):**
   - Stateless cluster control plane, Raft MON consensus quorum, and Highest Random Weight (HRW / Rendezvous) shard placement engine.
   - Internal ECDSA P-256 mTLS Certificate Authority (`ClusterCertificateAuthority`) issuing SPIFFE identities (`spiffe://aarkam.cluster/node/{NodeCode}`) to enrolling **Abodi (`Aarkam.Abodi`)** storage nodes via single-use tokens (`ET1.<hex>`).
   - Zero-Trust Operator Authentication & Offline Genesis License Verification (`OperatorAuthCoordinatorService` / `ClusterHardwareProfiler`), cryptographically bound to the host's deterministic **Rokka Coordinator Footprint (`ARK-FP-XXXXXXXX-XXXXXXXX-XXXXXXXX`)**.
2. **`Aarkam.Rokka.Gateway` (`rokka-gateway` — Default Endpoint `https://rokka-gateway.aarkam:57772`):**
   - Line-rate AWS SigV4 compatible S3 REST API gateway (`PutObject`, `GetObject`, `DeleteObject`, `HeadObject`, `ListObjectsV2`, `CreateBucket`, `DeleteBucket`) and Kdouja Key-Value REST gateway (`/api/v1/kv/*`).
   - **Ahmodi SIMD Cauchy Reed-Solomon Erasure Coding (`4+2`, `8+3`, `8+4`, `16+4`)** over Galois Field $\text{GF}(2^8)$ with AVX2/AVX-512 acceleration, inline AES-256-GCM envelope encryption, and speculative hedged download pipelines.

---

## 2. Valid Version & Ecosystem Compatibility Matrix

| Service / Component | Valid Version / Tag | Service Name (Win / Linux) | Container Image / Package | Port(s) | Architectural Role |
| :--- | :---: | :--- | :--- | :---: | :--- |
| **Rokka Coordinator** | **`v1.0.3`** (`latest`) | **`Aarkam.Rokka`** | `aarkam/aarkam.rokka:v1.0.3` | `57774`, `7774` | Raft Consensus Quorum, HRW Placement, Node CA & Genesis License Verifier |
| **Rokka Gateway** | **`v1.0.3`** (`latest`) | **`Aarkam.Rokka.Gateway`** | `aarkam/aarkam.rokka:v1.0.3` | `57772`, `7772` | AWS SigV4 Object & KV REST API, AES-256-GCM & Ahmodi SIMD Cauchy Erasure Coding |
| **Abodi Node Agent** | **`v1.0.3+`** (`latest`) | **`Aarkam.Abodi`** | `aarkam/aarkam.abodi:v1.0.3` | `57775`, `57776`, `7775`, `7776` | Storage Node Gateway, Dual-Mode Kdouja SAT & Hardware SMART Telemetry |
| **Kdouja SAT Engine** | **`v1.0.2`** (`latest`) | **`Aarkam.Kdouja`** | `aarkam/aarkam.kdouja:v1.0.2` | `57771` *(internal)* | LSM-Tree Metadata Engine & Direct I/O Block PageStore (`SDK v1.0.1`) |
| **AM Fleet CLI** | **`v1.0.2+`** (`latest`) | `am` / `am.exe` | `aarkam/aarkam.am:v1.0.2` | — | Operator CLI (`am cluster fingerprint`, `am license apply`, `am node token create`) |

---

## 3. Standardized Sovereign Endpoint & Port Topology

| Service Name | Binary | Port | Protocol | Default Sovereign Endpoint | Purpose |
| :--- | :--- | :---: | :---: | :--- | :--- |
| **`Aarkam.Rokka`** | `rokka-coordinator` | **`57774`** | HTTPS / mTLS (HTTP/1.1 & HTTP/2) | **`https://rokka-coordinator.aarkam:57774`** | Control Plane, Raft Quorum, Node CSR Enrollment & Operator Auth |
| **`Aarkam.Rokka`** | `rokka-coordinator` | **`7774`** | HTTP/2 Cleartext | `http://rokka-coordinator.aarkam:7774` | Internal gRPC, Liveness Probe (`/health`) & Prometheus (`/metrics`) |
| **`Aarkam.Rokka.Gateway`** | `rokka-gateway` | **`57772`** | HTTPS / TLS 1.3 | **`https://rokka-gateway.aarkam:57772`** | Production AWS SigV4 S3 REST API & Key-Value Data Plane |
| **`Aarkam.Rokka.Gateway`** | `rokka-gateway` | **`7772`** | HTTP / REST | `http://rokka-gateway.aarkam:7772` | High-Throughput VPC S3 REST API & Liveness Probe (`/health`) |

---

## 4. Quick Start & Docker Deployment Guides

### 4.1 Option A: Docker Compose — Unified Container (`ROKKA_ROLE=all`, Default)

Uses the repository's [`docker-compose.yml`](docker-compose.yml) to launch both **`Aarkam.Rokka`** (`:57774` / `:7774`) and **`Aarkam.Rokka.Gateway`** (`:57772` / `:7772`):

```bash
# Start Aarkam Rokka Coordinator + Gateway
docker compose up -d

# Inspect container startup banner (displays Rokka Coordinator Footprint & AarkamCP Activation URL)
docker logs aarkam-rokka
```

### 4.2 Option B: Docker Compose — Split Coordinator & Gateway Containers (`--profile split`)

```bash
# Launch separate aarkam-rokka-coordinator and aarkam-rokka-gateway containers
docker compose --profile split up -d
```

### 4.3 Option C: Direct `docker run` CLI

```bash
docker run -d \
  --name aarkam-rokka \
  --hostname rokka-coordinator.aarkam \
  --restart unless-stopped \
  -p 7774:7774 \
  -p 57774:57774 \
  -p 7772:7772 \
  -p 57772:57772 \
  -v rokka_metadata:/var/lib/rokka/metadata \
  -v rokka_catalog:/var/lib/rokka/catalog \
  -v rokka_security:/var/lib/rokka/security \
  -v rokka_data:/var/lib/rokka/data \
  -v rokka_logs:/var/log/rokka \
  -e ASPNETCORE_ENVIRONMENT=Production \
  -e DOTNET_CLI_TELEMETRY_OPTOUT=1 \
  -e ROKKA_ROLE=all \
  -e ROKKA_COORDINATOR_URL="https://rokka-coordinator.aarkam:57774" \
  -e ROKKA_GATEWAY_URL="https://rokka-gateway.aarkam:57772" \
  -e ROKKA_MASTER_KEY="$(openssl rand -hex 32)" \
  -e ROKKA_WAL_ENCRYPTION_KEY="$(openssl rand -hex 32)" \
  -e ROKKA_CLUSTER_CA_PASSWORD="$(openssl rand -hex 32)" \
  -e ROKKA_CLUSTER_SECRET="$(openssl rand -hex 32)" \
  aarkam/aarkam.rokka:v1.0.3
```

---

## 5. Rokka Cluster Activation & Sovereign Genesis Ceremony

Every Rokka cluster operates under a **Zero-Trust 2-Tier Air-Gapped Activation Model** with zero default operator passwords and zero outbound internet calls.

### 5.1 Activation Information Printed at Install / Container Startup
When `install-rokka.ps1`, `install-rokka.sh`, or the Docker container (`entrypoint.sh`) finishes initializing, it prints all information required to activate the Rokka cluster:

| Activation Requirement | Value / Source |
| :--- | :--- |
| **AarkamCP (Customer Portal) Url** | **[https://aarkam.io/Administration/Auth/Login](https://aarkam.io/Administration/Auth/Login)** |
| **AarkamCP Subscription Portal** | **[https://aarkam.io/Administration/CurrentSubscription](https://aarkam.io/Administration/CurrentSubscription)** |
| **Rokka Coordinator Footprint** | `ARK-FP-XXXXXXXX-XXXXXXXX-XXXXXXXX` *(Printed by installer/container or `am cluster fingerprint`)* |
| **Rokka Coordinator Endpoint** | `https://rokka-coordinator.aarkam:57774` *(Default unless custom port/URL specified)* |
| **Rokka Gateway Endpoint** | `https://rokka-gateway.aarkam:57772` |
| **Cluster Code** | `XXXX-XXXX-XXXXX` *(Auto-generated 15-char code or custom `-ClusterCode` / `--cluster-code`)* |

### 5.2 Step-by-Step Cluster Activation Procedure

1. **Step 1 — Copy Rokka Coordinator Footprint & Bind on AarkamCP:**
   - Sign in to **AarkamCP**: **[https://aarkam.io/Administration/Auth/Login](https://aarkam.io/Administration/Auth/Login)**
   - Navigate to **Current Subscription**: `https://aarkam.io/Administration/CurrentSubscription`
   - Click **Bind Cluster Fingerprint**, paste your **Rokka Coordinator Footprint** (`ARK-FP-...`), and enter your **Cluster Code**.
   - Click **Manage Operators**, configure your enterprise operators (`ClusterAdmin`, `StorageOperator`, `SecurityOfficer`, `Auditor`), and download your signed **Sovereign Genesis Bundle (`.arkbundle`)**.

2. **Step 2 — Verify & Apply Genesis Bundle Offline via AM CLI:**
   ```bash
   # Target Rokka Coordinator (default port 57774)
   am config set --endpoint "https://rokka-coordinator.aarkam:57774"

   # Confirm local hardware footprint matches the bundle
   am cluster fingerprint

   # Inspect RSA-4096-PSS signature & hardware lock offline
   am license inspect --bundle ./<your-license-key>.arkbundle

   # Ingest Genesis bundle into Aarkam.Rokka Coordinator
   am license apply --bundle ./<your-license-key>.arkbundle

   # Authenticate operator session
   am auth login -u <operator-username> -p "<operator-password>"
   ```

3. **Step 3 — Enroll Physical Storage Nodes (`Aarkam.Abodi`):**
   ```bash
   # Generate single-use enrollment token (ET1.<hex>) for each storage node
   am node token create --node-code "NODE-01" --tier "SAT"

   # On Linux Storage Host:
   sudo ./install-abodi.sh --node-code "NODE-01" --rokka-url "https://rokka-coordinator.aarkam:57774" --enrollment-token "<ET1.TOKEN>"

   # On Windows Storage Host:
   .\install-abodi.ps1 -NodeCode "NODE-01" -RokkaUrl "https://rokka-coordinator.aarkam:57774" -EnrollmentToken "<ET1.TOKEN>"
   ```

---

## 6. Environment Variable Reference (Zero-Trust CWE-312)

| Environment Variable | Default | Description |
| :--- | :--- | :--- |
| `ROKKA_ROLE` | `"all"` | Container daemon execution mode: `"all"` (both Coordinator & Gateway), `"coordinator"` (`Aarkam.Rokka`), or `"gateway"` (`Aarkam.Rokka.Gateway`). |
| `ROKKA_COORDINATOR_URL` | `"https://rokka-coordinator.aarkam:57774"` | Sovereign Rokka Coordinator HTTPS/mTLS control plane endpoint. |
| `ROKKA_GATEWAY_URL` | `"https://rokka-gateway.aarkam:57772"` | Sovereign Rokka Gateway HTTPS endpoint. |
| `ROKKA_MASTER_KEY` | *Required (64-hex)* | 256-bit AES master key for per-chunk AES-256-GCM envelope key derivation. |
| `ROKKA_WAL_ENCRYPTION_KEY` | *Required (64-hex)* | 256-bit AES key encrypting in-process Kdouja LSM-Tree write-ahead logs. |
| `ROKKA_CLUSTER_CA_PASSWORD` | *Required* | Passphrase protecting the internal mTLS Cluster Root CA (`ca.pfx`). |
| `ROKKA_CLUSTER_SECRET` | *Required (64-hex)* | Shared cluster secret for Raft inter-node consensus and local JWT operator session signing. |
| `ROKKA_ACCESS_KEY_ID` | `"rokka_admin"` | Root S3 SigV4 Access Key ID for `Aarkam.Rokka.Gateway`. |
| `ROKKA_SECRET_ACCESS_KEY` | `ROKKA_MASTER_KEY` | Root S3 SigV4 Secret Access Key (defaults to `ROKKA_MASTER_KEY`). |

---

## 7. Health Checks & Verification

```bash
# 1. Check Aarkam.Rokka Coordinator Liveness Probe
curl -f http://127.0.0.1:7774/health

# 2. Check Aarkam.Rokka.Gateway Liveness Probe
curl -f http://127.0.0.1:7772/health
```

---

<div align="center">
<sub>Copyright &copy; 2026 Aarkam.IO. All rights reserved. Sovereign Cloud, Rokka Distributed Storage Fabric & Kdouja SAT Substrate.</sub>
</div>
