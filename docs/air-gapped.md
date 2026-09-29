# Air-Gapped & Offline Deployment Guide for ULPF

## 1. Threat Model & Air-Gapped Mandate
In mission-critical national security environments (NTRO, defense centers, SCADA air-gapped facilities), log processing systems operate with **zero internet connectivity**. 

ULPF is designed from the ground up to operate completely offline:
- **Zero Cloud APIs**: No external LLM, cloud tokenizers, or web endpoints.
- **Zero Runtime Downloads**: No dynamic package pulling or CDN script loading.
- **Self-Contained Schemas & Rules**: All mappings, regexes, and taxonomies are stored locally in pure YAML and Python.
- **Offline Asset Intelligence**: Enrichment utilizes a local embedded JSON/SQLite database.

---

## 2. The 4-Step Offline Wheelhouse Strategy

```
[ Connected Staging PC ]                      [ Isolated Air-Gapped Host ]
           │                                                ▲
    1. pip download                                         │
       into wheelhouse/ ──> 2. Transfer via USB/CD-ROM ─────┘
                                                            │
                                                     3. Offline pip install
                                                        --no-index --find-links
                                                            │
                                                     4. Run ULPF / Docker
```

### Step 1: Download Wheels on Connected Staging PC
On a machine with internet access and matching Python version (Python 3.12, Linux x86_64 or Windows AMD64):

```bash
# Clone or prepare the project directory
cd ULPF

# Create the wheelhouse directory
mkdir wheelhouse

# Download all compiled binary wheels and dependencies
pip download -d wheelhouse -r requirements.txt
```

Verify that `wheelhouse/` contains the `.whl` files for:
- `pydantic` & `pydantic_core`
- `pyyaml`
- `fastapi` & `starlette` & `anyio`
- `uvicorn` & `click` & `h11`
- `pytest` & `pluggy` & `iniconfig`

---

### Step 2: Transfer to Air-Gapped Secure Host
Copy the entire `ULPF/` directory (including `wheelhouse/`) to an approved read-only transfer medium (e.g. encrypted optical disk, screened USB storage device) according to your organization's air-gap data diode protocols.

Move the directory to the air-gapped server:
```bash
cp -r /media/usb/ULPF /opt/ulpf
cd /opt/ulpf
```

---

### Step 3: Install Offline Without Internet Access
Execute `pip install` in offline mode pointing to the local `wheelhouse/` directory:

```bash
# Linux / macOS
pip install --no-index --find-links=wheelhouse -r requirements.txt

# Windows PowerShell
python -m pip install --no-index --find-links=wheelhouse -r requirements.txt
```

---

### Step 4: Build & Run Offline Docker Container

The ULPF `Dockerfile` includes an intelligent detection mechanism: if the `wheelhouse/` directory is present, it installs packages using `--no-index --find-links=wheelhouse`.

#### Build Image Offline:
```bash
docker build -t ulpf:1.0.0 .
```

#### Run Container Offline:
```bash
docker run --rm \
  --network none \
  -v $(pwd)/test_data:/app/test_data:ro \
  -v $(pwd)/output:/app/output \
  ulpf:1.0.0 process /app/test_data/
```

Notice the `--network none` flag: ULPF executes seamlessly with all network interfaces physically disabled!

#### Run via Docker Compose:
```bash
docker compose up ulpf-processor
```
