# Deployment and Operations Guide for ULPF

## Deployment Options

ULPF provides three operational deployment topologies:
1. **Standalone Batch / Daemon CLI**: High-throughput file and directory log ingestion.
2. **Containerized (Docker & Docker Compose)**: Isolated container deployment with mounted host volumes.
3. **High-Performance FastAPI REST Service**: Online HTTP log ingestion microservice.

---

## 1. Standalone CLI Ingestion

### Prerequisites
- Python 3.11+
- Virtual environment with dependencies installed:
  ```powershell
  pip install -r requirements.txt
  ```

### Processing a Directory of Heterogeneous Logs:
```powershell
python -m app.main process test_data/ --output output/universal_events.jsonl
```

### Processing with Offline Asset Enrichment Enabled:
```powershell
python -m app.main process test_data/ --enrich
```

### Automatic Log Format Detection:
```powershell
python -m app.main detect test_data/
```

### Cryptographic SHA-256 Audit:
```powershell
python -m app.main verify-hash output/universal_events.jsonl
```

---

## 2. Docker & Docker Compose Deployment

### Starting the Batch Processor:
```bash
docker compose up ulpf-processor
```

### Starting the FastAPI Web Service:
```bash
docker compose up -d ulpf-api
```

Check API health:
```bash
curl http://localhost:8000/api/v1/health
```

View real-time processing metrics:
```bash
curl http://localhost:8000/api/v1/metrics
```

---

## 3. Linux systemd Service Configuration

Create `/etc/systemd/system/ulpf-api.service`:

```ini
[Unit]
Description=ULPF Universal Log Pre-processing Framework API
After=network.target

[Service]
Type=simple
User=ulpf
WorkingDirectory=/opt/ulpf
ExecStart=/opt/ulpf/venv/bin/python -m app.main serve --host 127.0.0.1 --port 8000
Restart=always
RestartSec=5
Environment=ULPF_LOG_LEVEL=INFO
Environment=ULPF_OUTPUT_DIR=/var/log/ulpf/output

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ulpf-api
```
