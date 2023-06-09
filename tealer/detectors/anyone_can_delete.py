"""Detect paths missing validations on sender field AND allows to delete the application."""

from typing import List, TYPE_CHECKING

from tealer.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DetectorType,
)
from tealer.teal.basic_blocks import BasicBlock
from tealer.detectors.utils import (
    detect_missing_tx_field_validations,
    detector_terminal_description,
)
from tealer.utils.teal_enums import TealerTransactionType


if TYPE_CHECKING:
    from tealer.utils.output import SupportedOutput
    from tealer.teal.context.block_transaction_context import BlockTransactionContext


class AnyoneCanDelete(AbstractDetector):  # pylint: disable=too-few-public-methods
    """Detector to find execution paths missing validations on sender field AND allows to delete the application.

    Stateful smart contracts(application) can be deleted in Algorand. If the
    application transaction of type DeleteApplication is approved by the application,
    then the application will be deleted.

    This detector tries to find execution paths for which
        - OnCompletion can be DeleteApplication And
        - Transaction sender can be any address.
    """

    NAME = "unprotected-deletable"
    DESCRIPTION = "Unprotected Deletable Applications"
    TYPE = DetectorType.STATEFULL

    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI_URL = "https://github.com/crytic/tealer/wiki/Detector-Documentation#unprotected-deletable-application"
    WIKI_TITLE = "Unprotected Deletable Application"
    WIKI_DESCRIPTION = (
        "Application can be deleted by anyone. "
        "More at [building-secure-contracts/not-so-smart-contracts/algorand/access_controls]"
        "(https://github.com/crytic/building-secure-contracts/tree/master/not-so-smart-contracts/algorand/access_controls)."
    )
    WIKI_EXPLOIT_SCENARIO = """\
```py
@router.method(delete_application=CallConfig.CALL)
def delete_application() -> Expr:
    return Approve()
```

Eve calls `delete_application` method and deletes the application making its assets permanently inaccesible.
"""

    WIKI_RECOMMENDATION = """
- Avoid deletable applications.
- Add access controls to the vulnerable method.
"""

    def detect(self) -> "SupportedOutput":
        """Detect execution paths missing validations on sender field AND can delete the application .

        Returns:
            ExecutionPaths instance containing the list of vulnerable execution
            paths along with name, check, impact, confidence and other detector
            information.
        """

        def checks_field(block_ctx: "BlockTransactionContext") -> bool:
            # return False if Txn Type can be DeleteApplication AND sender can be any address.
            # return True otherwise
            return not (
                TealerTransactionType.ApplDeleteApplication in block_ctx.transaction_types
                and block_ctx.sender.any_addr
            )

        paths_without_check: List[List[BasicBlock]] = detect_missing_tx_field_validations(
            self.teal.bbs[0], checks_field
        )

        description = detector_terminal_description(self)
        filename = "anyone_can_delete"

        return self.generate_result(paths_without_check, description, filename)
