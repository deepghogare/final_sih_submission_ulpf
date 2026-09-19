"""
Dynamic Plugin Loader for ULPF.
Scans plugin directories, securely imports Python modules,
verifies PluginInterface implementation, and registers extensions into the core framework.
"""

import sys
import inspect
import importlib.util
from pathlib import Path
from typing import List, Optional
import logging

from app.plugins.interface import PluginInterface
from app.plugins.registry import PluginRegistry, default_plugin_registry
from app.core.registry import ComponentRegistry, default_registry
from app.mapping.mapping_engine import MappingEngine, default_mapping_engine

logger = logging.getLogger("ULPF.PluginLoader")


class PluginLoader:
    def __init__(
        self,
        plugin_registry: PluginRegistry = default_plugin_registry,
        component_registry: ComponentRegistry = default_registry,
        mapping_engine: MappingEngine = default_mapping_engine,
    ):
        self.plugin_registry = plugin_registry
        self.component_registry = component_registry
        self.mapping_engine = mapping_engine

    def discover_and_load(self, plugins_dir: Path) -> int:
        """
        Recursively scans directory for plugins (plugin.py or *.py files)
        and registers them.
        Returns count of successfully loaded plugins.
        """
        if not plugins_dir.is_dir():
            logger.info(f"Plugins directory not found: {plugins_dir}")
            return 0

        loaded_count = 0
        candidate_files: List[Path] = []

        # Find any plugin.py or direct python files in plugins/
        for p in plugins_dir.rglob("*.py"):
            if p.name.startswith("__") or "test" in p.name.lower():
                continue
            candidate_files.append(p)

        for filepath in candidate_files:
            try:
                plugin_instance = self._load_plugin_from_file(filepath)
                if plugin_instance:
                    # Register into plugin registry
                    if self.plugin_registry.register_plugin(plugin_instance):
                        # Register custom parsers
                        for parser in plugin_instance.register_parsers():
                            self.component_registry.register_parser(parser)

                        # Register custom mappings
                        mappings = plugin_instance.register_mappings()
                        for vendor_name, mapping_dict in mappings.items():
                            self.mapping_engine.register_vendor_mapping(vendor_name, mapping_dict)

                        loaded_count += 1
            except Exception as e:
                logger.error(f"Error loading plugin from {filepath}: {e}", exc_info=True)

        return loaded_count

    def _load_plugin_from_file(self, filepath: Path) -> Optional[PluginInterface]:
        """Dynamically loads and instantiates PluginInterface subclass from file."""
        module_name = f"ulpf_ext_{filepath.stem}_{abs(hash(str(filepath)))}"
        spec = importlib.util.spec_from_file_location(module_name, filepath)
        if not spec or not spec.loader:
            return None

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module

        try:
            spec.loader.exec_module(module)
        except Exception as e:
            logger.error(f"Execution failed for module {filepath}: {e}")
            return None

        # Inspect classes implementing PluginInterface
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, PluginInterface) and obj is not PluginInterface:
                try:
                    instance = obj()
                    return instance
                except Exception as e:
                    logger.error(f"Failed to instantiate plugin class {obj.__name__}: {e}")

        return None


default_plugin_loader = PluginLoader()
