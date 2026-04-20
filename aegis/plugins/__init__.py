import importlib.util
import inspect
import logging
import os
import sys

from aegis.scanners.scan_base import BaseScanner

logger = logging.getLogger(__name__)


def load_plugins(plugin_dir: str) -> list[type[BaseScanner]]:
    """Scan *plugin_dir* for .py files and return all BaseScanner subclasses found.

    Each .py file in the directory is imported as a module. Any class that
    is a direct or indirect subclass of ``BaseScanner`` (and is not
    ``BaseScanner`` itself) is collected and returned.

    Files that fail to import are logged as warnings and skipped.

    Parameters
    ----------
    plugin_dir:
        Filesystem path to the directory containing plugin .py files.

    Returns
    -------
    list[type[BaseScanner]]:
        All discovered scanner classes, in the order they were found.
    """
    if not os.path.isdir(plugin_dir):
        logger.warning("Plugin directory does not exist: %s", plugin_dir)
        return []

    discovered: list[type[BaseScanner]] = []
    seen_names: set[str] = set()

    for filename in sorted(os.listdir(plugin_dir)):
        if not filename.endswith(".py") or filename.startswith("_"):
            continue

        filepath = os.path.join(plugin_dir, filename)
        module_name = f"aegis_plugin_{filename[:-3]}"

        try:
            spec = importlib.util.spec_from_file_location(module_name, filepath)
            if spec is None or spec.loader is None:
                logger.warning("Could not create module spec for %s", filepath)
                continue

            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)

            for _name, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(obj, BaseScanner)
                    and obj is not BaseScanner
                    and obj.__module__ == module_name
                    and _name not in seen_names
                ):
                    discovered.append(obj)
                    seen_names.add(_name)
                    logger.info("Loaded plugin scanner: %s from %s", _name, filename)

        except Exception as exc:
            logger.warning("Failed to load plugin %s: %s", filepath, exc)
            # Clean up partial import
            sys.modules.pop(module_name, None)

    return discovered
