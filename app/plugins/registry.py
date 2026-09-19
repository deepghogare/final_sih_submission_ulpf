"""
Plugin Registry for ULPF.
Tracks active plugins, prevents conflicting duplicates,
and coordinates plugin lifecycle hooks.
"""

from typing import Dict, List, Optional
import logging
from app.plugins.interface import PluginInterface, PluginMetadata

logger = logging.getLogger("ULPF.PluginRegistry")


class PluginRegistry:
    def __init__(self):
        self._plugins: Dict[str, PluginInterface] = {}

    def register_plugin(self, plugin: PluginInterface) -> bool:
        """Register and activate a plugin instance."""
        meta = plugin.metadata
        plugin_id = meta.name.lower()

        if plugin_id in self._plugins:
            logger.warning(f"Plugin '{meta.name}' is already registered. Skipping duplicate.")
            return False

        try:
            plugin.on_load()
            self._plugins[plugin_id] = plugin
            logger.info(f"Successfully activated plugin '{meta.name}' v{meta.version} by {meta.author}")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize plugin '{meta.name}': {e}", exc_info=True)
            return False

    def unregister_plugin(self, name: str) -> bool:
        """Unload and unregister a plugin."""
        plugin_id = name.lower()
        if plugin_id in self._plugins:
            try:
                self._plugins[plugin_id].on_unload()
            except Exception as e:
                logger.warning(f"Error during plugin unload '{name}': {e}")
            del self._plugins[plugin_id]
            return True
        return False

    def get_plugin(self, name: str) -> Optional[PluginInterface]:
        return self._plugins.get(name.lower())

    def list_plugins(self) -> List[PluginMetadata]:
        return [p.metadata for p in self._plugins.values()]

    def execute_custom_normalizations(self, event_dict: dict) -> dict:
        """Runs all registered plugins' custom normalization hooks in isolation."""
        for name, plugin in self._plugins.items():
            try:
                event_dict = plugin.custom_normalize(event_dict)
            except Exception as e:
                logger.warning(f"Custom normalizer error in plugin '{name}': {e}")
        return event_dict


default_plugin_registry = PluginRegistry()
