"""
Unit and Integration Tests for Dynamic Plug-and-Play System.
"""

from pathlib import Path
from app.plugins.loader import PluginLoader
from app.plugins.registry import PluginRegistry
from app.core.registry import ComponentRegistry
from app.mapping.mapping_engine import MappingEngine
from app.models.parsed_event import ParsedEvent


def test_dynamic_plugin_loading():
    p_reg = PluginRegistry()
    c_reg = ComponentRegistry()
    m_engine = MappingEngine()

    loader = PluginLoader(
        plugin_registry=p_reg,
        component_registry=c_reg,
        mapping_engine=m_engine
    )

    plugins_dir = Path("plugins")
    count = loader.discover_and_load(plugins_dir)
    assert count >= 1

    # Verify Acme plugin was loaded
    acme_plugin = p_reg.get_plugin("acme_guard_plugin")
    assert acme_plugin is not None
    assert acme_plugin.metadata.version == "1.0.0"

    # Verify custom mapping registered by plugin
    parsed = ParsedEvent(
        raw_data="acme_src=192.168.1.50 acme_dst=10.0.0.1 acme_disposition=DENY",
        format="text",
        fields={
            "acme_src": "192.168.1.50",
            "acme_dst": "10.0.0.1",
            "acme_disposition": "DENY",
            "vendor": "AcmeSecurity"
        },
        detected_vendor="AcmeSecurity"
    )

    mapped, conf = m_engine.map_event(parsed, vendor_hint="acmesecurity")
    assert mapped["source"]["ip"] == "192.168.1.50"
    assert mapped["destination"]["ip"] == "10.0.0.1"
    assert mapped["event"]["action"] == "DENY"
