<div align="center">
  <img src="https://img.shields.io/badge/Component-Wazuh_SIEM-005E8C?style=for-the-badge&logo=wazuh&logoColor=white" alt="Wazuh SIEM">
  <img src="https://img.shields.io/badge/ULPF-Integration-0D1117?style=for-the-badge&logo=shield&logoColor=58a6ff" alt="ULPF Integration">
  <img src="https://img.shields.io/badge/Docker-Enabled-2496ed?style=for-the-badge&logo=docker&logoColor=white" alt="Docker">
</div>

<br>

<h1 align="center">Wazuh SIEM Containers for ULPF</h1>

> **Note**: This is the official Wazuh Docker container repository, pre-configured and optimized to ingest normalized JSON events from the **Universal Log Pre-processing Framework (ULPF)**.

In this repository you will find the orchestrated containers to run:

* 🛡️ **Wazuh Manager**: Runs the core Wazuh engine, API, and Filebeat OSS. Pre-loaded with custom ULPF JSON decoders and alerting rules.
* 📊 **Wazuh Dashboard**: Provides a highly customizable web user interface to browse through alert data and visualize endpoint telemetry.
* 🗄️ **Wazuh Indexer**: The scalable document store (works as a single-node or multi-node cluster).

> [!WARNING]
> **Host Configuration Required**  
> Be sure to increase the `vm.max_map_count` setting on your Linux host before deploying:  
> `sysctl -w vm.max_map_count=262144`

---

## 📁 Repository Structure

| Directory | Description |
| :--- | :--- |
| `single-node/` | **[RECOMMENDED]** Configuration for running 1 Manager, 1 Indexer, and 1 Dashboard. Ideal for ULPF testing. |
| `multi-node/` | Configuration for distributed clusters (2 Managers, 3 Indexers, 1 Dashboard) for high-availability enterprise environments. |
| `build-docker-images/` | Source Dockerfiles and scripts for manually building Wazuh container images. |
| `indexer-certs-creator/` | Utility scripts to automatically generate self-signed TLS certificates for the Wazuh Indexer cluster. |

---

## 🚀 Quick Deployment with ULPF

If you are using the default `docker-compose.yml` in the root ULPF directory, these containers are orchestrated automatically. 

If you are running Wazuh in isolation, follow the instructions inside the `single-node/` or `multi-node/` directories.

---

## 🔐 Environment Variables

The ULPF integration uses the following default values (configurable via `.env`):

### Wazuh Core Configuration
```env
API_USERNAME="wazuh-wui"
API_PASSWORD="MyS3cr37P450r.*-"
INDEXER_URL="https://wazuh.indexer:9200"
INDEXER_USERNAME="admin"
INDEXER_PASSWORD="SecretPassword"
```

### Wazuh Dashboard & Extensions
```env
PATTERN="wazuh-alerts-*"
CHECKS_PATTERN=true
CHECKS_TEMPLATE=true
CHECKS_API=true
CHECKS_SETUP=true

# Security Compliance Extensions
EXTENSIONS_PCI=true
EXTENSIONS_GDPR=true
EXTENSIONS_HIPAA=true
EXTENSIONS_NIST=true
EXTENSIONS_TSC=true
EXTENSIONS_AUDIT=true
```

---

## 🤝 Credits

These Docker containers are originally based on:
* `deviantony` docker-elk
* `xetus-oss` docker-ossec-server
* Wazuh Inc. Official Repositories

**Wazuh Docker Copyright (C) 2017, Wazuh Inc. (License GPLv2)**
