"""Validate the explicit apply_patch grammar before and after restoration.

This deliberately accepts the documented Begin/Add/Update/Delete/Move/hunk
format, not unified diffs or arbitrary patch programs. Newlines in restored
values are refused: a replacement must remain within its original patch line.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

# Public Codex rust-v0.161.0, commit
# 979011409de0a60b52f179721948e65531d26144:
# codex-rs/core/assets/tools/apply_patch.lark. Exact allowlisting avoids executing
# user-chosen grammars or treating an arbitrary grammar as reviewed patch syntax.
# Copyright 2025 OpenAI. Licensed under Apache-2.0; attribution and the immutable
# source URL are recorded in THIRD_PARTY_NOTICES.md.
APPLY_PATCH_LARK_GRAMMAR = """start: begin_patch hunk+ end_patch
begin_patch: "*** Begin Patch" LF
end_patch: "*** End Patch" LF?

hunk: add_hunk | delete_hunk | update_hunk
add_hunk: "*** Add File: " filename LF add_line+
delete_hunk: "*** Delete File: " filename LF
update_hunk: "*** Update File: " filename LF change_move? change?

filename: /(.+)/
add_line: "+" /(.*)/ LF -> line

change_move: "*** Move to: " filename LF
change: (change_context | change_line)+ eof_line?
change_context: ("@@" | "@@ " /(.+)/) LF
change_line: ("+" | "-" | " ") /(.*)/ LF
eof_line: "*** End of File" LF

%import common.LF
"""


class PatchValidationError(ValueError):
    """The patch is outside the supported grammar."""


def validate_apply_patch_format(value: Any) -> dict:
    """Return the reviewed text format or the exact public Codex Lark format."""
    if value == {"type": "text"}:
        return {"type": "text"}
    known = {"type": "grammar", "syntax": "lark", "definition": APPLY_PATCH_LARK_GRAMMAR}
    if value != known:
        raise PatchValidationError("Unsupported patch grammar")
    return known


def restore_patch(
    patch: str,
    restore_path: Callable[[str], str],
    restore_content: Callable[[str], str],
) -> str:
    """Parse, restore approved line locations, and preserve the patch envelope."""
    if "\r" in patch or "\x00" in patch:
        raise PatchValidationError("Unsupported patch grammar")
    lines = patch.split("\n")
    if lines[-1] == "":
        lines.pop()
    if len(lines) < 3 or lines[0] != "*** Begin Patch" or lines[-1] != "*** End Patch":
        raise PatchValidationError("Unsupported patch grammar")

    def single_line(value: str) -> str:
        if any(character in value for character in "\r\n\x00"):
            raise PatchValidationError("Unsupported patch grammar")
        return value

    result = [lines[0]]
    index = 1
    seen_paths: set[str] = set()
    while index < len(lines) - 1:
        header = lines[index]
        operation = next(
            (op for op in ("Add", "Update", "Delete") if header.startswith(f"*** {op} File: ")),
            None,
        )
        if operation is None:
            raise PatchValidationError("Unsupported patch grammar")
        path = single_line(restore_path(header[len(f"*** {operation} File: ") :]))
        if path in seen_paths:
            raise PatchValidationError("Unsupported patch grammar")
        seen_paths.add(path)
        result.append(f"*** {operation} File: {path}")
        index += 1
        if operation == "Delete":
            continue
        if operation == "Update" and lines[index].startswith("*** Move to: "):
            target = single_line(restore_path(lines[index][len("*** Move to: ") :]))
            if target in seen_paths:
                raise PatchValidationError("Unsupported patch grammar")
            seen_paths.add(target)
            result.append(f"*** Move to: {target}")
            index += 1

        hunks = 0
        hunk_lines = 0
        ended = False
        while index < len(lines) - 1 and not lines[index].startswith("*** "):
            line = lines[index]
            if operation == "Update" and (line == "@@" or line.startswith("@@ ")):
                if hunks and not hunk_lines:
                    raise PatchValidationError("Unsupported patch grammar")
                hunks += 1
                hunk_lines = 0
                result.append("@@" + single_line(restore_content(line[2:])))
            elif line and line[0] in ("+" if operation == "Add" else " +-"):
                if operation == "Update" and not hunks:
                    # apply_patch also permits an initial hunk without @@.
                    hunks = 1
                hunk_lines += 1
                result.append(line[0] + single_line(restore_content(line[1:])))
            else:
                raise PatchValidationError("Unsupported patch grammar")
            index += 1
        if operation == "Update" and index < len(lines) - 1:
            if lines[index] == "*** End of File":
                ended = True
                result.append(lines[index])
                index += 1
        if operation == "Add" and not hunk_lines:
            raise PatchValidationError("Unsupported patch grammar")
        if operation == "Update" and hunks and not hunk_lines:
            raise PatchValidationError("Unsupported patch grammar")
        if ended and index < len(lines) - 1 and not lines[index].startswith("*** "):
            raise PatchValidationError("Unsupported patch grammar")
    result.append(lines[-1])
    return "\n".join(result) + ("\n" if patch.endswith("\n") else "")
