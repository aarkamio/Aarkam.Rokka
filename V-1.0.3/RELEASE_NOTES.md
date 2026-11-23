# Rokka Sovereign Storage Engine & Distributed Fabric
# Official Production Release Notes (Version 1.0.3-GA)

| Release Metadata | Specification |
| :--- | :--- |
| **Product** | Rokka Sovereign Storage Engine & Distributed Control Plane |
| **Release Version** | `v1.0.3-GA (General Availability)` |
| **Release Date** | November 2026 |
| **Architectural Role** | Autonomous Sovereign Storage Data Plane & Control Plane |
| **Standardized Services** | **`Aarkam.Rokka`** (Coordinator) & **`Aarkam.Rokka.Gateway`** (Gateway) |
| **Dependency Scope** | Core Substrate for **Aarkam - SAT (Standalone Tier)** & **Aarkam - SCT (Storage Centers Tier)** |
| **Compliance Level** | Saudi NCA ECC-2:2024, NCA CSCC-1:2023, FIPS 140-3 Zero-Trust Architecture |
| **Target Distribution** | Zero-Egress Air-Gapped Datacenters (Linux x64, Windows Server x64, OCI Container) |

---

## 1. Executive Summary

**Rokka v1.0.3-GA** delivers native **Windows Service** and **Linux systemd** daemon hosting, standardized Aarkam V2 service naming (**`Aarkam.Rokka`** & **`Aarkam.Rokka.Gateway`**), hardened production installers with deterministic **Rokka Coordinator Footprint** (`ARK-FP-*`) activation reporting, complete **Docker Compose & OCI** container packaging, and migration to official **Aarkam.Ahmodi v1.0.1** NuGet packages with upgraded **.NET 10 / gRPC 2.85.0** dependencies.

---

## 2. What's New in Version 1.0.3-GA

### 2.1 Native Windows Service & Linux Systemd Hosting
- **Windows Service Integration (`AddWindowsService`)**: Both `rokka-coordinator.exe` and `rokka-gateway.exe` now embed `Microsoft.Extensions.Hosting.WindowsServices` (`10.0.11`) bound to standardized service names **`Aarkam.Rokka`** and **`Aarkam.Rokka.Gateway`**.
- **Linux Systemd Integration (`AddSystemd`)**: Both `rokka-coordinator` and `rokka-gateway` embed `Microsoft.Extensions.Hosting.Systemd` (`10.0.11`) for native `sd_notify` lifecycle integration and journald logging.
- **Kestrel HTTPS Configuration Fix**: Restored `ASPNETCORE_` environment variable configuration binding after custom configuration source initialization so TLS certificates and Kestrel endpoints load reliably under Windows `LocalSystem` and systemd services.

### 2.2 Production Installers & Cluster Activation Experience (`install-rokka.ps1` / `install-rokka.sh`)
- **Standardized Service Names & Legacy Migration**: Registers **`Aarkam.Rokka`** (`Aarkam Rokka Sovereign Storage Coordinator`) and **`Aarkam.Rokka.Gateway`** (`Aarkam Rokka Sovereign Storage Gateway`), automatically migrating and cleaning up legacy `Rokka.Coordinator` / `Rokka.Gateway` registrations.
- **Default Sovereign Endpoints**: Defaults automatically to `https://rokka-coordinator.aarkam:57774` and `https://rokka-gateway.aarkam:57772` unless explicitly overridden via CLI options.
- **Deterministic Rokka Coordinator Footprint & Activation Summary**: Computes and prints the `ARK-FP-XXXXXXXX-XXXXXXXX-XXXXXXXX` hardware fingerprint (bit-for-bit aligned with `ClusterHardwareProfiler`), **AarkamCP Customer Portal URL** (`https://aarkam.io/Administration/Auth/Login`), Subscription Portal URL, Cluster Code, and step-by-step offline activation commands (`am cluster fingerprint`, `am license inspect`, `am license apply`, `am auth login`, `am node token create`).
- **Accurate Host Hardware Diagnostics**: Displays physical CPU cores vs. logical threads, RAM in GB, physical disk count (`MSFT_PhysicalDisk` / `lsblk`), colon-formatted primary MAC, and OS `MachineGUID` / `MachineID`.
- **Clean Operational Diagnostics & Secret Hygiene**:
  - Injects service-scoped `REG_MULTI_SZ` environment variables on Windows (`HKLM:\SYSTEM\CurrentControlSet\Services\Aarkam.Rokka`) so services immediately pick up cryptographic keys without a host reboot, and removes conflicting user-scope (`HKCU`) overrides.
  - Never dumps raw `.NET` exception stack traces to end clients on service startup failure; reports concise actionable diagnostics (e.g., WAL key mismatch source + `-WalKey` / `-ResetMetadata` remediation).
  - Enforces strict parameter validation (`PositionalBinding = $false`) and `ClusterCode` hygiene.

### 2.3 Official Ahmodi NuGet Packages & Dependency Upgrades
- **Erasure Coding Packages**: Migrated to official **`Aarkam.Ahmodi` v1.0.1** and **`Aarkam.Ahmodi.Abstractions` v1.0.1** NuGet packages across all Rokka projects.
- **Core Networking & Runtime**: Upgraded `Grpc.AspNetCore`, `Grpc.Net.Client`, and `Grpc.Tools` to **`2.85.0`**, `Microsoft.Extensions.Hosting.WindowsServices` / `Systemd` to **`10.0.11`**, and maintained `Aarkam.Kdouja.Primitives` **`1.0.6`** on **.NET 10.0**.

### 2.4 Complete OCI Container & Docker Compose Distribution
- **Added `docker-compose.yml` & `DOCKER_README.md`**: Supports both all-in-one (`ROKKA_ROLE=all`) and split (`--profile split`) Coordinator + Gateway deployments with persistent volumes for metadata, catalog, and Zero-Trust security vault.
- **Enhanced Container `entrypoint.sh` & `Dockerfile.release`**: Bootstraps internal ECDSA P-256 Cluster Root CA (`ca.pfx`), computes and prints the **Rokka Coordinator Footprint** and **AarkamCP** activation details on startup, and includes `openssl` and `/var/lib/rokka/security` isolation.

---

## 3. Package & Distribution Matrix

| Artifact Name | Target Architecture | Contents | Distribution Channel |
| :--- | :--- | :--- | :--- |
| **`rokka-v1.0.3-linux-x64.zip`** | Linux x64 (glibc 2.31+) | Single-file `rokka-coordinator`, `rokka-gateway`, `install-rokka.sh`, settings, docs | [GitHub Releases](https://github.com/aarkamio/Aarkam.Rokka/releases) |
| **`rokka-v1.0.3-win-x64.zip`** | Windows Server x64 (2022/2025) | Single-file `rokka-coordinator.exe`, `rokka-gateway.exe`, `install-rokka.ps1`, settings, docs | [GitHub Releases](https://github.com/aarkamio/Aarkam.Rokka/releases) |
| **`rokka-coordinator-v1.0.3-win-x64.zip`** | Windows Server x64 | Standalone `rokka-coordinator.exe`, `coordinator.settings.json`, `install-rokka.ps1` | [GitHub Releases](https://github.com/aarkamio/Aarkam.Rokka/releases) |
| **`rokka-gateway-v1.0.3-win-x64.zip`** | Windows Server x64 | Standalone `rokka-gateway.exe`, `gateway.settings.json`, `install-rokka.ps1` | [GitHub Releases](https://github.com/aarkamio/Aarkam.Rokka/releases) |
| **`rokka-coordinator-v1.0.3-linux-x64.zip`** | Linux x64 | Standalone `rokka-coordinator`, `coordinator.settings.json`, `install-rokka.sh` | [GitHub Releases](https://github.com/aarkamio/Aarkam.Rokka/releases) |
| **`rokka-gateway-v1.0.3-linux-x64.zip`** | Linux x64 | Standalone `rokka-gateway`, `gateway.settings.json`, `install-rokka.sh` | [GitHub Releases](https://github.com/aarkamio/Aarkam.Rokka/releases) |
| **`aarkam/aarkam.rokka:v1.0.3`** | OCI Container (Linux x64) | Production-hardened container image with embedded daemons and footprint entrypoint | [Docker Hub Repository](https://hub.docker.com/r/aarkam/aarkam.rokka) |
