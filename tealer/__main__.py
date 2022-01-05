import argparse
import inspect
import sys
from pathlib import Path
from typing import List, Any, Type

from tealer.detectors import all_detectors
from tealer.detectors.abstract_detector import AbstractDetector
from tealer.teal.parse_teal import parse_teal
from tealer.utils.command_line import output_detectors
from tealer.utils.output import cfg_to_dot
from tealer.exceptions import TealerException


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="TealAnalyzer",
        usage="teal_analyazer program.teal [flag]",
    )

    parser.add_argument("program", help="program.teal")

    parser.add_argument(
        "--print-cfg",
        help="Print the cfg",
        action="store_true",
    )

    parser.add_argument(
        "--list-detectors",
        help="List available detectors",
        action=ListDetectors,
        nargs=0,
        default=False,
    )

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    return args


class ListDetectors(argparse.Action):  # pylint: disable=too-few-public-methods
    def __call__(
        self, parser: argparse.ArgumentParser, *args: Any, **kwargs: Any
    ) -> None:  # pylint: disable=signature-differs
        detectors = get_detectors()
        output_detectors(detectors)
        parser.exit()


def get_detectors() -> List[Type[AbstractDetector]]:
    detectors = [getattr(all_detectors, name) for name in dir(all_detectors)]
    detectors = [d for d in detectors if inspect.isclass(d) and issubclass(d, AbstractDetector)]
    return detectors


def main() -> None:

    args = parse_args()

    with open(args.program, encoding="utf-8") as f:
        print(f"Analyze {args.program}")
        teal = parse_teal(f.read())

    if args.print_cfg:
        print("CFG exported: cfg.dot")
        cfg_to_dot(teal.bbs, Path("cfg.dot"))

    else:
        try:
            for Cls in get_detectors():
                teal.register_detector(Cls)
            results = teal.run_detectors()
            for r in results:
                print(*r, sep="\n")
        except TealerException as e:
            print(e)
            sys.exit(-1)


if __name__ == "__main__":
    main()
