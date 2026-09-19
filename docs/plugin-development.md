# Dynamic Plugin Development Guide for ULPF

## Objective
This guide demonstrates **how to add support for a new vendor or custom log format without modifying a single line of ULPF core framework code**.

The ULPF plug-and-play architecture discovers third-party plugins dynamically at startup.

---

## Step 1: Create the Plugin File

Create a new directory under `plugins/` (e.g. `plugins/my_custom_firewall/`) and create `plugin.py`:

```
plugins/
└── my_custom_firewall/
    └── plugin.py
```

---

## Step 2: Implement `PluginInterface`

In `plugin.py`, subclass `PluginInterface` from `app.plugins.interface`:

```python
from typing import Dict, Any, List
from app.plugins.interface import PluginInterface, PluginMetadata

class MyCustomFirewallPlugin(PluginInterface):
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="my_custom_firewall_plugin",
            version="1.0.0",
            author="MySecurityTeam",
            description="Plugin providing native semantic translation for CustomFW-9000 appliances.",
            supported_vendors=["CustomFW"],
            supported_formats=["json", "syslog"]
        )

    def on_load(self) -> None:
        """Executed when ULPF discovers and activates the plugin."""
        print("[*] MyCustomFirewallPlugin initialized successfully!")

    def register_mappings(self) -> Dict[str, Dict[str, Any]]:
        """
        Maps custom vendor keys to the canonical Universal Event Schema targets.
        """
        return {
            "customfw": {
                "vendor": "CustomFW Technologies",
                "product": "CFW-9000",
                "device_type": "firewall",
                "fields": {
                    "cfw_source_ip": "source.ip",
                    "cfw_dest_ip": "destination.ip",
                    "cfw_src_port": "source.port",
                    "cfw_dst_port": "destination.port",
                    "cfw_decision": "event.action",
                    "cfw_alert_level": "event.severity",
                    "cfw_protocol": "network.protocol",
                    "cfw_event_time": "event.timestamp",
                    "cfw_operator": "user.name"
                }
            }
        }

    def custom_normalize(self, event_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Optional custom hook to enrich or mutate event fields."""
        if event_dict.get("device", {}).get("vendor") == "CustomFW Technologies":
            event_dict.setdefault("extensions", {})["cfw_verified_hardware"] = True
        return event_dict
```

---

## Step 3: Run ULPF and Verify Plugin Discovery

Check that ULPF detects your plugin using the CLI:

```powershell
python -m app.main plugins
```

**Output:**
```
[*] Scanning plugins directory: plugins
[*] Active Plugins (2):
  1. acme_guard_plugin v1.0.0 (Author: Acme Security Technologies)
  2. my_custom_firewall_plugin v1.0.0 (Author: MySecurityTeam)
     Description : Plugin providing native semantic translation for CustomFW-9000 appliances.
     Vendors     : CustomFW
     Formats     : json, syslog
```

---

## Step 4: Ingest a Custom Vendor Log

Create a sample log `test_data/custom_fw.json`:

```json
{
  "cfw_source_ip": "10.50.1.20",
  "cfw_dest_ip": "172.16.10.5",
  "cfw_src_port": 51234,
  "cfw_dst_port": 443,
  "cfw_decision": "BLOCK",
  "cfw_alert_level": "high",
  "cfw_protocol": "TCP",
  "cfw_event_time": "2026-09-02T18:00:00Z",
  "cfw_operator": "alice_admin",
  "vendor": "CustomFW",
  "unique_firmware_revision": "REV_9.4.2"
}
```

Process it through ULPF:

```powershell
python -m app.main process test_data/custom_fw.json --output output/custom_out.jsonl
```

---

## Step 5: Verify the Universal Event Output

View the resulting Universal Event in `output/custom_out.jsonl`:

```json
{
  "event_id": "ULPF-5a71c8f2b1d0",
  "schema_version": "1.0",
  "event": {
    "timestamp": "2026-09-02T18:00:00Z",
    "action": "deny",
    "severity": "high"
  },
  "source": {
    "ip": "10.50.1.20",
    "port": 51234
  },
  "destination": {
    "ip": "172.16.10.5",
    "port": 443
  },
  "network": {
    "protocol": "TCP"
  },
  "device": {
    "vendor": "CustomFW Technologies",
    "product": "CFW-9000",
    "device_type": "firewall"
  },
  "user": {
    "name": "alice_admin"
  },
  "metadata": {
    "parser": "json",
    "parser_version": "1.0",
    "raw_event_hash": "a4d3f...64chars"
  },
  "raw": {
    "data": "{\"cfw_source_ip\":\"10.50.1.20\"...}",
    "format": "json"
  },
  "extensions": {
    "unique_firmware_revision": "REV_9.4.2",
    "cfw_verified_hardware": true
  }
}
```

Notice:
1. `cfw_decision: BLOCK` became `event.action: "deny"`.
2. `cfw_alert_level: high` became `event.severity: "high"`.
3. `unique_firmware_revision` was preserved losslessly in `extensions`.
4. `cfw_verified_hardware: true` was appended by `custom_normalize()`.
5. **Zero lines of ULPF core code were touched!**
