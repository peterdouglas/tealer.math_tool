"""Util functions to output dot files and detector results.

This modules contains functions, classes which are used to store
and display different types of output formats used by tealer detectors
and printers.

Functions:
    full_cfg_to_dot(bbs: List[BasicBlock], config: Optional[CFGDotConfig]=None, filename: Optional[Path]=None) -> None:
        Exports dot representation of CFG represented by :bbs: in
        dot format to given filename.

Classes:
    ExecutionPaths: Class to represent results of a detector, stores
        execution paths detected by the detector.

Types:
    SupportedOutput: Union of types used for representing detector results.
        For now, it is an alias for ExecutionPaths.

"""

import html
import re
from pathlib import Path
from typing import List, TYPE_CHECKING, Dict, Callable, Optional
from dataclasses import dataclass

from tealer.teal.instructions.instructions import BZ, BNZ, Callsub, Retsub

if TYPE_CHECKING:
    from tealer.teal.basic_blocks import BasicBlock
    from tealer.teal.subroutine import Subroutine
    from tealer.teal.teal import Teal
    from tealer.teal.instructions.instructions import Instruction


@dataclass
class CFGDotConfig:  # pylint: disable=too-many-instance-attributes
    ins_additional_comments: Callable[["Instruction"], List[str]] = lambda _x: []
    # include additional tealer comments at the top of the block.
    bb_additional_comments: Callable[["BasicBlock"], List[str]] = lambda _x: []
    # don't include edge bi -> bj in dot output?
    ignore_edge: Callable[["BasicBlock", "BasicBlock"], bool] = lambda _bi, _bj: False
    # Apply colors to different types of edges?
    color_edges: bool = True
    jump_branch_color: str = "#36d899"  # "green"
    default_branch_color: str = "#e0182b"  # "red"
    callsub_edge_color: str = "#ff8c00"  # "orange"
    remaining_edges_color: str = "BLACK"
    comments_cell_border_size: int = 2  # size of basic block comments cell
    bb_border_color: Callable[["BasicBlock"], str] = lambda _x: "BLACK"


def _instruction_to_dot(ins: "Instruction", config: CFGDotConfig) -> str:
    """Return dot representation of Teal instruction.

    string representation of the instruction is represented as
    a table cell(row) in dot.

    Args:
        ins: teal instruction to represent in dot format.
        config: configuration for dot output

    Returns:
        string containing the dot representation of the given
        instruction.

    ---------------
    // tealer comments
    //
    // source code comments
    // ...
    // instruction
    ---------------
    """

    # ins.source_code stores the indentation and whitespace. strip them
    ins_str = html.escape(ins.source_code.strip(), quote=True)  # original teal code
    # make callsub and retsub bold and italic
    if isinstance(ins, (Callsub, Retsub)):
        ins_str = f"<B><I>{ins_str}</I></B>"

    # format:
    # <B>
    #   // tealer_comment_1 <BR/>
    #   // tealer_comment_2 <BR/>
    # </B>
    # <BR/>
    tealer_comments = ""
    if ins.tealer_comments + config.ins_additional_comments(ins):
        sanitized_comments = [
            html.escape(comment.strip(), quote=True)
            for comment in ins.tealer_comments + config.ins_additional_comments(ins)
        ]
        tealer_comments = "<BR/>".join(f"// {comment}" for comment in sanitized_comments)
        tealer_comments = f"<B>{tealer_comments}</B><BR/>"  # make them bold

    # format:
    #   // source_comment_1 <BR/>
    #   // source_comment_2 <BR/>
    source_code_comments = ""
    if ins.comments_before_ins:
        sanitized_comments = [
            html.escape(comment.strip(), quote=True) for comment in ins.comments_before_ins
        ]
        source_code_comments = "<BR/>".join(f"{comment}" for comment in sanitized_comments)
        source_code_comments += "<BR/>"

    cell_i = (
        "<TR>"
        '<TD ALIGN="LEFT" BALIGN="LEFT" COLOR="BLACK">'
        f"{tealer_comments}"
        f"{source_code_comments}"
        f"{ins.line}. {ins_str}"
        "</TD>"
        "</TR>\n"
    )
    return cell_i


def _bb_to_dot(bb: "BasicBlock", config: CFGDotConfig) -> str:
    """Return dot representation of basic block.

    Basic Blocks are represented in the form of a tabel in dot.
    Each instruction in the basic block is represented as a row.

    Args:
        bb: basic block to represent in dot format.
        config: configuration for dot output

    Returns:
        string containing the dot representation of the given
        basic block.
    """

    # format: `{source_node}:s -> {dest_node}{dest_port}:n [color=""];`
    def graph_edge_str(src_bb: "BasicBlock", dest_bb: "BasicBlock", edge_color: str) -> str:
        if config.ignore_edge(src_bb, dest_bb):
            return ""
        return f'{src_bb.idx}:s -> {dest_bb.idx}:{dest_bb.entry_instr.line}:n [color="{edge_color}"];\n'

    # format:
    #     <TR> tealer_comments and additional_comments </TR>
    #     <TR> instruction_1                           </TR>
    #     <TR> instruction_2                           </TR>
    #     ...
    table_rows: List[str] = []

    santized_comments = [
        html.escape(comment.strip(), quote=True)
        for comment in bb.tealer_comments + config.bb_additional_comments(bb)
    ]
    comments_cell_str = (
        "<TR>"
        f'<TD COLOR="BLACK" ALIGN="LEFT" BALIGN="LEFT" PORT="{bb.entry_instr.line}" BORDER="{config.comments_cell_border_size}">'
        "<B>"
        f'{"<BR/>".join(f"// {comment}" for comment in santized_comments)}'
        "</B>"
        "</TD>"
        "</TR>\n"
    )

    table_rows.append(comments_cell_str)

    for ins in bb.instructions:
        table_rows.append(_instruction_to_dot(ins, config))

    graph_edges: List[str] = []
    if config.color_edges and isinstance(bb.exit_instr, (BZ, BNZ, Callsub)):
        if isinstance(bb.exit_instr, (BZ, BNZ)):
            # color graph edges if exit instruction is BZ or BNZ.
            if len(bb.next) == 1:
                # happens when bz/bnz is the last instruction in the contract and there is no default branch
                default_branch = None
                jump_branch = bb.next[0]
            else:
                default_branch = bb.next[0]
                jump_branch = bb.next[1]

            if default_branch is not None:
                graph_edges.append(graph_edge_str(bb, default_branch, config.default_branch_color))
            graph_edges.append(graph_edge_str(bb, jump_branch, config.jump_branch_color))
        elif isinstance(bb.exit_instr, Callsub):
            # make callsub instruction -> subroutine edge orange.
            callsub_branch = bb.next[0]
            graph_edges.append(graph_edge_str(bb, callsub_branch, config.callsub_edge_color))
    else:
        for next_bb in bb.next:
            graph_edges.append(graph_edge_str(bb, next_bb, config.remaining_edges_color))

    table_str = (
        f'<<TABLE ALIGN="LEFT" COLOR="{config.bb_border_color(bb)}">\n'
        f'{"".join(table_rows)}'
        "</TABLE>> labelloc=top shape=plain\n"
    )

    return f'{bb.idx}[label={table_str}] {"".join(graph_edges)}'


def subroutine_to_dot(subroutine: "Subroutine", config: Optional[CFGDotConfig] = None) -> str:
    if config is None:
        config = CFGDotConfig()
    # ignore edges from callsub and retsub.
    # replacing the ignore_edge function directly should be ok (?) for now
    config.ignore_edge = lambda bi, _: isinstance(bi.exit_instr, (Callsub, Retsub))

    def empty_subroutine_box(
        callsub_block: "BasicBlock",
        return_point_block: "BasicBlock",
        called_subroutine: "Subroutine",
    ) -> str:
        # Include a empty box between callsub and it's return point. Empty box represents
        # the subroutine called by `callsub`.
        content = (
            f'"Subroutine {called_subroutine.name}"'  # TODO: add other information in the future
        )
        node_name = f"x{callsub_block.idx}_{return_point_block.idx}"
        edge1 = f"{callsub_block.idx}:s -> {node_name}:n;\n"  # callsub to empty box
        # empty box to return point block
        edge2 = (
            f"{node_name}:s -> {return_point_block.idx}:{return_point_block.entry_instr.line}:n;\n"
        )
        return f"{node_name}[label={content},style=dashed,shape=box,fontname=bold] {edge1}{edge2}"

    nodes_dot: List[str] = []
    for bi in subroutine.blocks:
        nodes_dot.append(_bb_to_dot(bi, config))
        if isinstance(bi.exit_instr, Callsub):
            # add empty box to represent the graph of called subroutine
            # add edge from callsub to that box and box to callsub return point.
            # ignoring recursion here. adds empty box even if callsub calls the same subroutine.
            return_point_ins = bi.exit_instr.return_point
            assert return_point_ins is not None
            return_point_bb = return_point_ins.bb
            assert return_point_bb is not None
            called_subroutine = subroutine.contract.subroutine(bi.exit_instr.label)
            assert called_subroutine is not None
            nodes_dot.append(empty_subroutine_box(bi, return_point_bb, called_subroutine))

    nodes_str = "\n".join(nodes_dot)

    dot_output = "digraph g{\n ranksep = 1 \n overlap = scale \n" f"{nodes_str}\n" "}"  # .......

    return dot_output


def all_subroutines_to_dot(
    teal: "Teal",
    dest: Path,
    config: Optional[CFGDotConfig] = None,
    filename_prefix: str = "",
) -> None:
    """Export CFG of each subroutine to a dot file.

    Args:
        teal: contract instance
        dest: destination directory to save the dot files.
        filename_prefix: prefix to add before each filename to distinguish files generated
            by multiple calls to this function.
    """
    if filename_prefix:  # not empty string
        filename_prefix = f"{filename_prefix}_"
    main_entry_sub_filename = f"{teal.contract_name}_{filename_prefix}contract_shortened_cfg.dot"

    with open(dest / Path(main_entry_sub_filename), "w", encoding="utf-8") as f:
        f.write(subroutine_to_dot(teal.main, config))
        print(f"Exported contract's shortened cfg to: {dest / Path(main_entry_sub_filename)}")

    for sub_name, subroutine in teal.subroutines.items():
        filename = f"{teal.contract_name}_{filename_prefix}subroutine_{sub_name}_cfg.dot"
        with open(dest / Path(filename), "w", encoding="utf-8") as f:
            f.write(subroutine_to_dot(subroutine, config))
            print(f'Exported cfg of "{sub_name}" subroutine to: {dest / Path(filename)}')


def full_cfg_to_dot(  # pylint: disable=too-many-locals
    bbs: List["BasicBlock"], config: Optional[CFGDotConfig] = None, filename: Optional[Path] = None
) -> Optional[str]:
    """Export control flow graph to a dot file.

    The control flow graph is represented as a digraph in dot.
    basic blocks are represented as a table with it's instructions
    as rows.

    Args:
        bbs: list of basic blocks representing the control
            flow graph.
        config: optional configuration for dot output.
        filename: name of the file to save the dot representation
            of control flow graph in.

    """

    teal = bbs[0].teal
    assert teal is not None
    subroutine_block_idx = set(bb.idx for bb in teal.bbs if bb in teal.main.blocks)
    # responsible for "box" around each subroutine.
    subroutine_clusters: List[str] = []
    for i, (subroutine_name, subroutine) in enumerate(teal.subroutines.items()):
        subroutine_bbs = subroutine.blocks
        cluster_name = i
        cluster_nodes = " ".join(str(bb.idx) for bb in subroutine_bbs)
        # TODO: Add number of args and return values to label in the future.
        subgraph_dot = f"""
            subgraph cluster_{cluster_name} {{
                label = "Subroutine {subroutine_name}";
                graph[style=dashed];
                {cluster_nodes};
            }}
        """
        subroutine_clusters.append(subgraph_dot)

    # default config
    if not config:
        config = CFGDotConfig()
        # border color for subroutine blocks
        subroutine_blocks_border_color = "#000066"
        config.bb_border_color = (
            lambda bb: "BLACK"
            if bb.idx not in subroutine_block_idx
            else subroutine_blocks_border_color
        )

    bb_nodes_dot: List[str] = []
    for bb in bbs:
        bb_nodes_dot.append(_bb_to_dot(bb, config))

    subroutine_clusters_str = "\n".join(subroutine_clusters)
    bb_nodes_str = "\n".join(bb_nodes_dot)

    dot_output = (
        "digraph g{\n ranksep = 1 \n overlap = scale \n"
        f"{subroutine_clusters_str}\n"
        f"{bb_nodes_str}\n"
        "}"
    )

    if filename is None:
        return dot_output

    with open(filename, "w", encoding="utf-8") as f:
        f.write(dot_output)
    return None


class ExecutionPaths:  # pylint: disable=too-many-instance-attributes
    """Detector output class to store list of execution paths.

    Args:
        cfg: Control Flow Graph of the teal contract.
        description: Description of the execution path detected by
            the detector.
        filename: The dot representation of execution paths will be
            saved in the filenames starting with :filename: prefix.
    """

    def __init__(self, cfg: List["BasicBlock"], description: str, filename: str):
        self._cfg = cfg
        self._description = description
        self._filename = filename
        self._paths: List[List["BasicBlock"]] = []
        self._check: str = ""
        self._impact: str = ""
        self._confidence: str = ""
        self._help: str = ""

    def add_path(self, path: List["BasicBlock"]) -> None:
        """Add given execution path to current list of execution paths.

        Args:
            path: new execution path detected by the detector which
                will be added to the list of execution paths.
        """

        self._paths.append(path)

    @property
    def paths(self) -> List[List["BasicBlock"]]:
        """List of execution paths stored in the result."""
        return self._paths

    @property
    def cfg(self) -> List["BasicBlock"]:
        """Control Flow of the teal contract."""
        return self._cfg

    @property
    def description(self) -> str:
        """Description of execution paths stored in this result"""
        return self._description

    @property
    def check(self) -> str:
        """Name of the detector whose result is being represented."""
        return self._check

    @check.setter
    def check(self, c: str) -> None:
        self._check = c

    @property
    def impact(self) -> str:
        """Impact of the detector whose result is being represented."""
        return self._impact

    @impact.setter
    def impact(self, i: str) -> None:
        self._impact = i

    @property
    def confidence(self) -> str:
        """Confidence of the detector whose result is being represented."""
        return self._confidence

    @confidence.setter
    def confidence(self, c: str) -> None:
        self._confidence = c

    @property
    def help(self) -> str:
        """Help message to remove detected issues from the contract."""
        return self._help

    @help.setter
    def help(self, h: str) -> None:
        self._help = h

    @staticmethod
    def _short_notation(path_bbs: List["BasicBlock"]) -> str:
        """Return short notation representation of path"""
        return " -> ".join(map(str, [bb.idx for bb in path_bbs]))

    def filter_paths(self, filter_regex: str) -> None:
        if filter_regex == "":
            return
        filtered_paths: List[List["BasicBlock"]] = []
        for path in self._paths:
            if re.search(filter_regex, self._short_notation(path)) is None:
                # short notation does not contain string matching the regex
                filtered_paths.append(path)
        self._paths = filtered_paths
        return

    def write_to_files(self, dest: Path, all_paths_in_one: bool = False) -> None:
        """Export execution paths to dot files.

        The execution paths are highlighted in the dot representation
        of CFG. Each execution path is indexed based on the order they
        are added to the result and index will be used in the filename.

        Args:
            dest: The dot files will be saved in the given :dest: destination
                directory.
            all_paths_in_one: if this is set to True, all the execution
                paths will be highlighted in a single file. if this is
                False, each execution path is saved in a different file.
                Default False.
        """

        print(self.description)
        if len(self.paths) == 0:
            print("\tDetector didn't find any vulnerable paths.")
            print("-" * 100)
            return
        # cfg_to_dot config
        config = CFGDotConfig()
        config.color_edges = False
        print("\tFollowing are the vulnerable paths found:")
        if not all_paths_in_one:

            for idx, path in enumerate(self._paths, start=1):

                short = self._short_notation(path)
                print(f"\n\t\t path: {short}")

                filename = dest / Path(f"{self._filename}_{idx}.dot")
                print(f"\t\t check file: {filename}")

                config.bb_border_color = (
                    lambda bb: "BLACK"
                    if bb not in path  # pylint: disable=cell-var-from-loop
                    else "RED"
                )
                full_cfg_to_dot(self.cfg, config, filename)
            print("-" * 100)
        else:
            bbs_to_highlight = []

            for path in self._paths:
                short = self._short_notation(path)
                print(f"\t\t path: {short}")
                for bb in path:
                    if bb not in bbs_to_highlight:
                        bbs_to_highlight.append(bb)

            filename = dest / Path(f"{self._filename}.dot")
            print(f"\t\t check file: {filename}")

            config.bb_border_color = lambda bb: "BLACK" if bb not in bbs_to_highlight else "RED"
            full_cfg_to_dot(self.cfg, config, filename)

    def to_json(self) -> Dict:
        """Return json representation of detector result.

        The execution paths are represented as a list of basic blocks,
        which themselves are list of string representation of it's
        instructions.

        Returns:
            JSON encodable dictionary representing the detector result.
        """

        result = {
            "type": "ExecutionPaths",
            "count": len(self.paths),
            "description": self.description,
            "check": self.check,
            "impact": self.impact,
            "confidence": self.confidence,
            "help": self.help,
        }
        paths = []
        for path in self.paths:
            short = " -> ".join(map(str, [bb.idx for bb in path]))
            blocks = []
            for bb in path:
                block = []
                for ins in bb.instructions:
                    block.append(f"{ins.line}: {ins}")
                blocks.append(block)

            paths.append({"short": short, "blocks": blocks})

        result["paths"] = paths
        return result


SupportedOutput = ExecutionPaths
