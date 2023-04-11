from typing import Tuple, Type, List, TYPE_CHECKING

from tealer_math_plugin.detectors.mathploit import Mathploit

if TYPE_CHECKING:
    from tealer.detectors.abstract_detector import AbstractDetector
    from tealer.printers.abstract_printer import AbstractPrinter


def make_plugin() -> Tuple[List[Type["AbstractDetector"]], List[Type["AbstractPrinter"]]]:
    plugin_detectors: List[Type["AbstractDetector"]] = [Mathploit]
    plugin_printers: List[Type["AbstractPrinter"]] = []

    return plugin_detectors, plugin_printers
