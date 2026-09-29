<div align="center">
  <img src="https://img.shields.io/badge/Deployment-Single_Node-005E8C?style=for-the-badge&logo=wazuh&logoColor=white" alt="Single Node">
  <img src="https://img.shields.io/badge/ULPF-Integration-0D1117?style=for-the-badge&logo=shield&logoColor=58a6ff" alt="ULPF Integration">
</div>

<br>

<h1 align="center">Wazuh SIEM: Single-Node Deployment</h1>

This directory contains the `docker-compose.yml` for deploying a highly-efficient, standalone Wazuh environment. It provisions:
- **1x Wazuh Manager** (Core engine)
- **1x Wazuh Indexer** (Elasticsearch/OpenSearch compatible datastore)
- **1x Wazuh Dashboard** (Kibana-based UI)

> [!TIP]
> This is the recommended deployment mode for testing the **Universal Log Pre-processing Framework (ULPF)** in a constrained hardware environment or Hackathon setting.

---

## 🚀 Deployment Instructions

### 1. Host Preparation (Linux Only)
The Wazuh Indexer requires a larger memory map limit. Run this command with root privileges on your Docker host:
```bash
sudo sysctl -w vm.max_map_count=262144
```
*(To make this permanent, add `vm.max_map_count=262144` to `/etc/sysctl.conf`)*

### 2. Generate TLS Certificates
Before starting the stack, you must generate the internal SSL/TLS certificates used for secure communication between the Indexer and Manager.

Run the provided utility container:
```bash
docker-compose -f generate-indexer-certs.yml run --rm generator
```

### 3. Launch the Stack
Start the entire SIEM environment:
```bash
# Run in background (detached mode)
docker-compose up -d
```

> [!NOTE]
> **First-Boot Initialization**  
> The environment takes about **1-3 minutes** to fully initialize depending on your hardware. The Wazuh Indexer must bootstrap its indices, and the Dashboard must generate its index patterns before the UI becomes accessible at `https://localhost:8443`.
