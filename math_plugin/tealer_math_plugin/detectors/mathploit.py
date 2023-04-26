from typing import List, TYPE_CHECKING

from tealer.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DetectorType,
)
from tealer.teal.teal import Teal
from tealer.teal.basic_blocks import BasicBlock
from tealer.teal.instructions.transaction_field import TypeEnum
from tealer.teal.instructions.instructions import (Global, BDiv, BMul,
                                                    Itob, Gtxn, AppGlobalGet,
                                                    AppGlobalGetEx, Mul, Mulw, 
                                                    Sub, BSubtract, Add, Addw, 
                                                    BAdd, BModulo, BZero, Dup, 
                                                    AppLocalPut)

if TYPE_CHECKING:
    from tealer.teal.instructions.instructions import Instruction
    from tealer.utils.output import SupportedOutput


class Mathploit(AbstractDetector):  # pylint: disable=too-few-public-methods

    NAME = "mathploit"
    DESCRIPTION = "Detect paths potentially vulnerable to mathploit"
    TYPE = DetectorType.STATEFULLGROUP

    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI_TITLE = "Vulnerable to mathploit"
    WIKI_DESCRIPTION = "Detect paths potentially vulnerable to mathploit"
    WIKI_EXPLOIT_SCENARIO = """
A contract sets a local storage (typically a ratio of a staking pool) to 1 * Precision
(a very large interger that is used for subtraction and division in defi as we don't
 have floating point numbers in TEAL). 
"""

    WIKI_RECOMMENDATION = """
    Ensure that this ratio does not cause the user to get a larger percentage of staking
    rewards.
    """
    WIKI_URL = "https://github.com/peterdouglas/math_tools/blob/master/mathploit.md"

    def __init__(self, teal: Teal):
        super().__init__(teal)
        self.results_number = 0
        self.count = 0
        self.math_start = []

    def _getLastItem(self, list):
        if len(list) > 0:
            return list[len(list) - 1]
        return None
    
    def _isMath(self, ins):
        if isinstance(ins, (Mul, Mulw, BMul, BDiv, Sub, BModulo, BSubtract, Add, 
                            Addw, BAdd, BZero, Dup)):
            return True
        return False
    
    
    def _check_mathploit(
        self,
        bb: BasicBlock,
        current_path: List[BasicBlock],
        checked_blocks: List[BasicBlock],
        paths_with_mathploit: List[List[BasicBlock]],
    ) -> None:
        # check for loops
        #print(bb.idx, bb.instructions[0]._line_num, bb.instructions[0]._comment)
        if bb in current_path or bb in checked_blocks:
            return
        
        current_path = current_path + [bb]
        checked_blocks = checked_blocks + [bb]
        has_mathploit = False
        math_stack = []
        for ins in bb.instructions:
            stack_ins = self._getLastItem(math_stack)

            if ins._comment == '// 1':
                if not isinstance(ins._prev[0], Global) and not (
                    isinstance(ins._prev[0],Gtxn) and isinstance(ins._prev[0].field,
                                                                  TypeEnum)):
                    math_stack = []
                    math_stack.append(ins)
                continue
            
            if stack_ins is None:
                continue

            if isinstance(ins, Itob) and stack_ins._comment =='// 1':
                math_stack.append(ins)
                continue

            if isinstance(ins, (AppGlobalGet, AppGlobalGetEx)):
                if isinstance(stack_ins, Itob) or stack_ins._comment == '// 1':
                    math_stack.append(ins)
                else: 
                    math_stack = []
                continue
            
            if self._isMath(ins):
                if isinstance(ins, (Mul, Mulw, BMul)):
                    if isinstance(stack_ins, (AppGlobalGet, AppGlobalGetEx)):
                        math_stack.append(ins)

                else:
                    math_stack = []
                continue
            
            if isinstance(ins, AppLocalPut):
                if isinstance(stack_ins, (Mul, Mulw, BMul)):
                    math_stack.append(ins)
                    
                    if math_stack[0]._line_num not in self.math_start:
                        self.math_start.append(math_stack[0]._line_num)
                        print('Mathsploit found starting on line: ', 
                              math_stack[0]._line_num) 
                        paths_with_mathploit.append(current_path)
                        has_mathploit = True
                        return
                else:
                    math_stack = []
                continue

        for next_bb in bb.next:
            self._check_mathploit(next_bb, current_path, checked_blocks, paths_with_mathploit)

    def detect(self) -> "SupportedOutput":

        paths_with_mathploit: List[List["BasicBlock"]] = []
        
        # self._check_bbnext(self.teal.bbs[0])

        self._check_mathploit(self.teal.bbs[0], [], [], paths_with_mathploit)

        description = "Math exploit with smart contract storage - "
        description += "this can allow an attacker to withdraw undue rewards."
        filename = "math_exploit"

        return self.generate_result(paths_with_mathploit, description, filename)