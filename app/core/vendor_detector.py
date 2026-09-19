"""
Vendor / Log Source Identification Engine for ULPF.
Identifies device vendor and product to select the most accurate mapping configuration.
"""

from typing import Dict, Any, Optional
import re


class VendorDetector:
    """
    Infers the log generator vendor/product based on extracted fields,
    syslog message headers, CEF/LEEF device identifiers, and key signatures.
    """

    VENDOR_SIGNATURES = [
        # Cisco ASA
        {
            "vendor": "Cisco",
            "product": "ASA",
            "device_type": "firewall",
            "keywords": ["%ASA-", "cisco-asa", "%FTD-"],
            "field_matches": ["cisco_tag", "cisco_mnemonic"]
        },
        # Palo Alto Networks
        {
            "vendor": "Palo Alto Networks",
            "product": "PAN-OS",
            "device_type": "firewall",
            "keywords": ["PAN-OS", "PaloAlto", "TRAFFIC", "THREAT"],
            "field_matches": ["pan_device_name", "srcloc", "dstloc"]
        },
        # Fortinet FortiGate
        {
            "vendor": "Fortinet",
            "product": "FortiGate",
            "device_type": "firewall",
            "keywords": ["devname=FG", "type=traffic", "fortigate"],
            "field_matches": ["devname", "logid"]
        },
        # Vendor A (from SIH prompt)
        {
            "vendor": "VendorA",
            "product": "FirewallA",
            "device_type": "firewall",
            "keywords": ["VendorA", "FW-A"],
            "field_matches": ["src_ip", "dst_ip", "action"]
        },
        # Vendor B (from SIH prompt)
        {
            "vendor": "VendorB",
            "product": "FirewallB",
            "device_type": "firewall",
            "keywords": ["VendorB", "FW-B"],
            "field_matches": ["sourceAddress", "destinationAddress", "decision"]
        },
        # Snort / Suricata IDS
        {
            "vendor": "Snort",
            "product": "Snort IDS",
            "device_type": "ids",
            "keywords": ["[Priority:", "Classification:"],
            "field_matches": ["sig_generator", "sig_id"]
        }
    ]

    def detect_vendor(self, fields: Dict[str, Any], raw_text: str = "") -> Dict[str, Optional[str]]:
        """
        Returns a dict: {'vendor': ..., 'product': ..., 'device_type': ...}
        """
        # 1. Direct inspection of vendor fields extracted from CEF/LEEF/JSON
        for vendor_key in ("device_vendor", "vendor", "dev_vendor", "devVendor"):
            val = fields.get(vendor_key)
            if val and isinstance(val, str) and val.strip():
                prod = fields.get("device_product") or fields.get("product") or fields.get("dev_product") or fields.get("devName")
                return {
                    "vendor": val.strip(),
                    "product": str(prod).strip() if prod else None,
                    "device_type": fields.get("device_type") or "security_device"
                }

        # 2. Check vendor signatures against raw text keywords
        for sig in self.VENDOR_SIGNATURES:
            if any(kw in raw_text for kw in sig["keywords"]):
                return {
                    "vendor": sig["vendor"],
                    "product": sig["product"],
                    "device_type": sig["device_type"]
                }

        # 3. Check matching field combinations (e.g. sourceAddress + destinationAddress -> VendorB)
        for sig in self.VENDOR_SIGNATURES:
            if all(f in fields for f in sig["field_matches"]):
                return {
                    "vendor": sig["vendor"],
                    "product": sig["product"],
                    "device_type": sig["device_type"]
                }

        # Fallback if unknown
        return {
            "vendor": None,
            "product": None,
            "device_type": None
        }


default_vendor_detector = VendorDetector()
