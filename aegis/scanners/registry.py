import logging
from typing import Type

from aegis.scanners.scan_base import BaseScanner

logger = logging.getLogger(__name__)

_SCANNERS: dict[str, Type[BaseScanner]] = {}
_LOADED = False


def _try_import(module_path: str, class_name: str) -> Type[BaseScanner] | None:
    """Import a single scanner class; return None on failure."""
    try:
        import importlib
        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name)
        return cls
    except Exception as exc:
        logger.debug("Could not import %s.%s: %s", module_path, class_name, exc)
        return None


def _ensure_loaded() -> None:
    global _LOADED
    if _LOADED:
        return
    _LOADED = True

    scanner_defs: list[tuple[str, str]] = [
        ("aegis.scanners.llm01_prompt_injection.direct", "DirectInjectionScanner"),
        ("aegis.scanners.llm01_prompt_injection.encoding", "EncodingBypassScanner"),
        ("aegis.scanners.llm02_data_disclosure.system_prompt", "SystemPromptDisclosureScanner"),
        ("aegis.scanners.llm02_data_disclosure.pii_extraction", "PIIExtractionScanner"),
        ("aegis.scanners.llm02_data_disclosure.training_data", "TrainingDataExtractionScanner"),
        ("aegis.scanners.llm05_output_handling.xss_injection", "XSSInjectionScanner"),
        ("aegis.scanners.llm05_output_handling.sqli_injection", "SQLInjectionScanner"),
        ("aegis.scanners.llm07_prompt_leakage.extraction", "SystemPromptExtractionScanner"),
        ("aegis.scanners.llm10_resource_abuse.token_exhaustion", "TokenExhaustionScanner"),
        ("aegis.scanners.llm06_excessive_agency.tool_enum", "ToolEnumerationScanner"),
        ("aegis.scanners.llm02_data_disclosure.secret_extraction", "SecretExtractionScanner"),
        ("aegis.scanners.guardrail_assessment", "GuardrailAssessmentScanner"),
        ("aegis.scanners.llm01_prompt_injection.multi_turn", "MultiTurnInjectionScanner"),
        ("aegis.scanners.llm06_excessive_agency.agentic_attack", "AgenticAttackScanner"),
        ("aegis.scanners.llm02_data_disclosure.acrostic_extraction", "AcrosticExtractionScanner"),
        ("aegis.scanners.llm01_prompt_injection.output_manipulation", "OutputManipulationScanner"),
    ]

    for module_path, class_name in scanner_defs:
        cls = _try_import(module_path, class_name)
        if cls is not None:
            _SCANNERS[cls.name] = cls


def get_all_scanners() -> list[Type[BaseScanner]]:
    """Return all successfully imported scanner classes."""
    _ensure_loaded()
    return list(_SCANNERS.values())


def get_scanner(name: str) -> Type[BaseScanner]:
    """Return a scanner class by its registered name.

    Raises ``KeyError`` if not found.
    """
    _ensure_loaded()
    if name not in _SCANNERS:
        available = ", ".join(sorted(_SCANNERS)) or "(none loaded)"
        raise KeyError(f"Scanner '{name}' not found. Available: {available}")
    return _SCANNERS[name]
