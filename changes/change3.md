# Walkthrough: Action Normalization Fix & Interactive Merkle Tree Audit UI

We have resolved the `event.action` normalization issue across vendor log formats (Cisco ASA, CheckPoint LEEF, Syslog, Generic) and built the **Interactive Merkle Tree & Blockchain Audit UI** in **ULPF**.

---

## 🛠️ Summary of Changes

### 1. Action Normalization & Inferencing Engine
- **[MODIFY] [actions.py](file:///c:/Users/Maitra%20Prajapati/Desktop/sih/app/app/normalization/actions.py)**:
  - Expanded `ACTION_MAP` with complete taxonomy mappings (`allow`, `deny`, `alert`, `login`, `logout`) covering verbs like `built`, `teardown`, `established`, `permit`, `accept`, `reject`, `drop`, `block`, `logon`, `sign-in`, etc.
  - Implemented `infer_action_from_fields_and_raw(fields_or_event, raw_text)` to dynamically infer event actions when explicit vendor action fields are missing or unmapped (e.g. Cisco ASA `%ASA-6-302013` `Built` connections, CheckPoint LEEF `Accept` class IDs).
- **[MODIFY] [normalizer.py](file:///c:/Users/Maitra%20Prajapati/Desktop/sih/app/app/normalization/normalizer.py)**:
  - Added fallback invocation of `infer_action_from_fields_and_raw()` during normalization stage whenever `event.action` is missing, `None`, or uncanonicalized.

### 2. Interactive Merkle Tree & Blockchain Audit UI
- **[MODIFY] [blockchain.py](file:///c:/Users/Maitra%20Prajapati/Desktop/sih/app/app/integrity/blockchain.py)**:
  - Implemented `get_block_merkle_tree(block_index)` to return complete binary DAG tree hierarchy (root, branch nodes, leaf nodes) and byte tamper status.
  - Implemented `tamper_event_byte(event_id, byte_index)` to corrupt event byte payload in SQLite, instantly triggering Merkle tree digest mismatch and red alert status.
- **[MODIFY] [routes.py](file:///c:/Users/Maitra%20Prajapati/Desktop/sih/app/app/api/routes.py)**:
  - Added REST endpoints:
    - `GET /api/v1/blockchain/blocks/{block_index}/merkle-tree`
    - `POST /api/v1/blockchain/tamper-event`
- **[MODIFY] [dashboard.html](file:///c:/Users/Maitra%20Prajapati/Desktop/sih/app/app/templates/dashboard.html)**:
  - Added **`🌲 Merkle Tree Inspector`** buttons in top header, Blockchain Ledger controls row, block cards, and event table rows.
  - Added **`#merkleTreeVisualModal`**:
    - Block selector dropdown to inspect any sealed block in the ledger.
    - Live Merkle Root status badge (`🛡️ 100% UNTAMPERED` green or `🚨 TAMPER DETECTED` red).
    - Visual Merkle DAG hierarchy representation with animated node cards.
    - **Interactive Byte Tamper Sandbox**: `⚡ Modify Byte` button for instant corrupt byte injection and `🛡️ Repair Block` button for hash re-synchronization.

---

## 🧪 Verification Results

### Unit Tests
- Executed `python -m pytest`:
```text
============================= test session starts =============================
platform win32 -- Python 3.14.2, pytest-8.4.2, pluggy-1.6.0
rootdir: C:\Users\Maitra Prajapati\Desktop\sih\app
plugins: anyio-4.14.2
collected 69 items

tests\api\test_blockchain_api.py .....                                   [  7%]
tests\api\test_dashboard_api.py ....                                     [ 13%]
tests\integration\test_edge_cases.py .................                   [ 37%]
tests\integration\test_parallel_processing.py .                          [ 39%]
tests\integration\test_pipeline_e2e.py .                                 [ 40%]
tests\integration\test_siem_forwarder.py ...                             [ 44%]
tests\integrity\test_blockchain.py ....                                  [ 50%]
tests\integrity\test_hashing.py ....                                     [ 56%]
tests\mapping\test_mapping_engine.py ...                                 [ 60%]
tests\normalization\test_action_normalization.py ...                     [ 65%]
tests\normalization\test_normalization.py ......                         [ 73%]
tests\parsers\test_all_parsers.py ..........                             [ 88%]
tests\plugins\test_plugins.py .                                          [ 89%]
tests\test_stream_listeners.py ...                                       [ 94%]
tests\validation\test_validation.py ....                                 [100%]

======================== 69 passed, 1 warning in 5.33s ========================
```

### Action Normalization Coverage
- Cisco ASA: `Built` -> `allow`, `Deny` -> `deny`
- CheckPoint LEEF: `Accept` -> `allow`, `Drop` -> `deny`
- Generic Syslog / Auth: `login`, `logout`, `alert`, `allow`, `deny`
