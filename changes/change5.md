# Walkthrough: Built-in Log Anomaly & Rate Spike Detector

Implemented **Built-in Log Anomaly & Rate Spike Detector** (Requirement 6) in **ULPF**, introducing lightweight statistical anomaly detection (Z-score volume spikes, unexpected null fields identification, and format deviation alerts) executed prior to forwarding events to downstream SIEM collectors.

---

## 🛠️ Summary of Changes

### 1. Statistical Log Anomaly Engine
- **[NEW] [anomaly_detector.py](file:///c:/Users/Maitra%20Prajapati/Desktop/sih/app/app/core/anomaly_detector.py)**:
  - **`WelfordOnlineStats`**: Implements Welford's online algorithm for running mean and variance computation with O(1) memory footprint.
  - **`LogAnomalyDetector`**: High-performance real-time statistical detector:
    - **Volume Spike Detector**: Computes sliding time-window EPS and Z-scores (Z = (x - mean) / stddev). Triggers `VOLUME_SPIKE` alerts when rate spikes exceed Z >= 3.0.
    - **Unexpected Null Fields Detector**: Scans essential fields (`action`, `severity`, `timestamp`, `source.ip`, `user.name`) for missing values and triggers `UNEXPECTED_NULL_FIELD` alerts.
    - **Format Deviation Detector**: Identifies syntax corruption, parser fallbacks, and format drift (`FORMAT_DEVIATION`).
    - **Event Enrichment**: Attaches anomaly details directly to `event.extensions["anomalies"]` before SIEM forwarding.

### 2. Application Configuration & Pipeline Integration
- **[MODIFY] [config.py](file:///c:/Users/Maitra%20Prajapati/Desktop/sih/app/app/core/config.py)**:
  - Added configuration parameters: `enable_anomaly_detection`, `anomaly_zscore_threshold` (default `3.0`), `anomaly_volume_window_sec`, and `anomaly_null_rate_threshold`.
- **[MODIFY] [pipeline.py](file:///c:/Users/Maitra%20Prajapati/Desktop/sih/app/app/core/pipeline.py)**:
  - Integrated `LogAnomalyDetector` into `Pipeline` and invoked Step 9.5 (`self.anomaly_detector.analyze(event_obj)`) right before SIEM forwarding.

### 3. REST API & Web UI Dashboard
- **[MODIFY] [routes.py](file:///c:/Users/Maitra%20Prajapati/Desktop/sih/app/app/api/routes.py)**:
  - Added `GET /api/v1/anomalies/status`: Exposes real-time Z-scores, volume burst counts, null field counters, format deviation counters, and recent alerts log.
  - Added `POST /api/v1/anomalies/reset`: Resets statistical baseline metrics.
  - Updated `GET /api/v1/metrics` to include anomaly statistics payload.
- **[MODIFY] [dashboard.html](file:///c:/Users/Maitra%20Prajapati/Desktop/sih/app/app/templates/dashboard.html)**:
  - Added "Log Anomalies Flagged" KPI card.
  - Built **BUILT-IN LOG ANOMALY & RATE SPIKE DETECTOR** panel in the web UI displaying live Z-scores, volume burst counters, null field alerts, format deviation alerts, and live alert feeds.
  - Included a "Reset Baseline" action button.

### 4. Comprehensive Unit & Integration Tests
- **[NEW] [test_anomaly_detector.py](file:///c:/Users/Maitra%20Prajapati/Desktop/sih/app/tests/core/test_anomaly_detector.py)**:
  - 7 unit and integration tests covering Welford statistics calculation, null field detection, format deviation alerts, volume spike burst alerts, baseline resets, and end-to-end pipeline anomaly attachment.

---

## 🧪 Verification Results

### Unit & Integration Test Suite Execution

Executed `python -m pytest tests/core/test_anomaly_detector.py`:

```text
============================= test session starts =============================
platform win32 -- Python 3.14.2, pytest-8.4.2, pluggy-1.6.0
rootdir: C:\Users\Maitra Prajapati\Desktop\sih\app
plugins: anyio-4.14.2
collected 7 items

tests\core\test_anomaly_detector.py .......                              [100%]

============================== 7 passed in 0.41s ==============================
```

### Single Event Pipeline Anomaly Verification

```text
Event: ULPF-37ba14e3e76a
Anomalies: [{
  'anomaly_type': 'UNEXPECTED_NULL_FIELD',
  'severity': 'low',
  'message': 'Unexpected null/missing essential fields: event.action/category',
  'details': {'null_fields': ['event.action/category'], 'null_count': 1, 'parser': 'syslog', 'format': 'syslog'},
  'event_id': 'ULPF-37ba14e3e76a'
}]
```
