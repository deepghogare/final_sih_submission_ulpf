<div align="center">
  <img src="https://img.shields.io/badge/Deployment-Multi_Node-005E8C?style=for-the-badge&logo=wazuh&logoColor=white" alt="Multi Node">
  <img src="https://img.shields.io/badge/ULPF-Integration-0D1117?style=for-the-badge&logo=shield&logoColor=58a6ff" alt="ULPF Integration">
</div>

<br>

<h1 align="center">Wazuh SIEM: Multi-Node Cluster Deployment</h1>

This directory contains the `docker-compose.yml` for deploying a highly-available, distributed Wazuh enterprise environment. It provisions:
- **2x Wazuh Managers** (Clustered Core engines for High Availability)
- **3x Wazuh Indexers** (Distributed datastore cluster for resilience)
- **1x Wazuh Dashboard** (Kibana-based UI)
- **1x Nginx Load Balancer** (Distributes traffic across Managers)

> [!IMPORTANT]
> This deployment mode requires significant hardware resources. It is intended for production ULPF environments handling tens of thousands of Events Per Second (EPS).

---

## 🚀 Deployment Instructions

### 1. Host Preparation (Linux Only)
The Wazuh Indexer requires a larger memory map limit. Run this command with root privileges on your Docker host:
```bash
sudo sysctl -w vm.max_map_count=262144
```
*(To make this permanent, add `vm.max_map_count=262144` to `/etc/sysctl.conf`)*

### 2. Generate Cluster TLS Certificates
Before starting the stack, you must generate the internal SSL/TLS certificates used for secure communication across all the distributed nodes.

Run the provided utility container:
```bash
docker-compose -f generate-indexer-certs.yml run --rm generator
```

### 3. Launch the Cluster
Start the entire SIEM environment:
```bash
# Run in background (detached mode)
docker-compose up -d
```

> [!NOTE]
> **First-Boot Initialization**  
> The environment takes roughly **3-5 minutes** to fully initialize. The Wazuh Indexer nodes must form a quorum, bootstrap their shards, and the Dashboard must generate its index patterns before the UI becomes accessible at `https://localhost:8443`.
