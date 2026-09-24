# Walkthrough: Real-Time Streaming Ingestion Listeners (UDP/TCP/Syslog & Kafka)

We have successfully implemented real-time streaming ingestion listeners for **ULPF**, enabling live log ingestion over network sockets and Kafka topics for live pitch demonstrations and enterprise security deployments.

---

## 🛠️ Changes Implemented

### Core Framework & Stream Listeners

#### [NEW] [stream_listener.py](file:///c:/Users/Maitra%20Prajapati/Desktop/sih/app/app/core/stream_listener.py)
- Implemented `UDPLogProtocol` (`asyncio.DatagramProtocol`) for asynchronous UDP Syslog datagram ingestion on port `5140`.
- Implemented `SyslogTCPServer` (`asyncio.start_server`) for continuous TCP stream socket ingestion on port `5141`.
- Implemented `KafkaStreamConsumer` with graceful fallback handling for Kafka topics.
- Built `StreamListenerManager` to manage lifecycle, metrics, and multi-subscriber event dispatching.

#### [MODIFY] [routes.py](file:///c:/Users/Maitra%20Prajapati/Desktop/sih/app/app/api/routes.py)
- Added REST control endpoints:
  - `GET /api/v1/listeners/status`
  - `POST /api/v1/listeners/start`
  - `POST /api/v1/listeners/stop`
- Added WebSocket endpoint `WS /api/v1/ws/live-stream` to push normalized Universal Events live to dashboard UI.

#### [MODIFY] [main.py](file:///c:/Users/Maitra%20Prajapati/Desktop/sih/app/app/main.py)
- Added `ulpf listen` sub-command to launch streaming servers directly from the CLI:
  ```bash
  python -m app.main listen --udp-port 5140 --tcp-port 5141 --output output/live_events.jsonl
  ```

---

### Pitch Demo & Testing Infrastructure

#### [NEW] [stream_simulator.py](file:///c:/Users/Maitra%20Prajapati/Desktop/sih/app/scripts/stream_simulator.py)
- Built a simulation script generating multi-format realistic Syslog (RFC 3164/5424), CEF, JSON, LEEF, and XML log events over UDP/TCP sockets at configurable rates for SIH live pitch demonstrations.

#### [NEW] [test_stream_listeners.py](file:///c:/Users/Maitra%20Prajapati/Desktop/sih/app/tests/test_stream_listeners.py)
- Automated unit test suite verifying UDP socket ingestion, TCP stream socket ingestion, output file writing, SHA-256 integrity hashing, and listener status tracking.

---

## 🧪 Verification Results

### Automated Tests
- Executed `python -m pytest tests/test_stream_listeners.py`:
```text
============================= test session starts =============================
collected 3 items

tests\test_stream_listeners.py ...                                       [100%]

============================== 3 passed in 1.06s ==============================
```

### End-to-End Simulation Test
- Verified `python scripts/stream_simulator.py --protocol udp --port 51400 --count 5` executes without errors.
