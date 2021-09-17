#!/usr/bin/env python3.8
# Copyright 2021 The Fuchsia Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Wraps a command so that its outputs are timestamp-fresh only if their contents change.

Every declared output is renamed with a temporary suffix in the command.
If the command succeeds, the temporary file is moved over the original declared
output if the output did not already exist or the contents are different.
This conditional move is done for every declared output that appears in the
arguments list.

Assumptions:
  Output files can be whole shell tokens in the command's arguments.
    We also support filenames as lexical substrings in tokens like
    "--flag=out1,out2" or just "out1,out2".

  If x is a writeable path (output), then x.any_suffix is also writeable.

  If x is a writeable path (output), then dirname(x) is also writeable.

  Command being wrapped does not change behavior with the name of its output
  arguments.

If any of the above assumptions do not hold, then we recommend --disable
wrapping.
"""

import argparse
import filecmp
import os
import shutil
import subprocess
import sys
from typing import Any, Callable, Collection, Dict, FrozenSet, Iterable, Sequence, Tuple
import dataclasses


def _partition(
        iterable: Iterable[Any],
        predicate: Callable[[Any],
                            bool]) -> Tuple[Sequence[Any], Sequence[Any]]:
    """Splits sequence into two sequences based on predicate function."""
    trues = []
    falses = []
    for item in iterable:
        if predicate(item):
            trues.append(item)
        else:
            falses.append(item)
    return trues, falses


def files_match(file1: str, file2: str):
    """Compares two files, returns True if they both exist and match."""
    # filecmp.cmp does not invoke any subprocesses.
    return filecmp.cmp(file1, file2, shallow=False)


def move_if_different(src: str, dest: str, verbose: bool = False):
    if not os.path.exists(src):
        # Then original command failed to produce this file.
        return
    if not os.path.exists(dest) or not files_match(dest, src):
        if verbose:
            print(f"  === Updated: {dest}")
        shutil.move(src, dest)
    else:
        if verbose:
            print(f"  === Cached: {dest}")
        os.remove(src)


@dataclasses.dataclass
class TempFileTransform(object):
    """Represents a file name transform.

     At least temp_dir or suffix or basename_prefix must be non-blank.

    temp_dir: Write temporary files in here.
      If blank, paths are relative to working directory.
    suffix: Add this suffix to temporary files, e.g. ".tmp".
    basename_prefix: Add this prefix to the basename of the path.
      This can be a good choice over suffix when the underlying tool behavior
      is sensitive to the output file extension.
      Example: "foo/bar.txt", with prefix="tmp-" -> foo/tmp-bar.txt
    """
    temp_dir: str = ""
    suffix: str = ""
    basename_prefix: str = ""

    @property
    def valid(self):
        return self.temp_dir or self.suffix or self.basename_prefix

    def transform(self, path: str) -> str:
        return os.path.join(
            self.temp_dir, os.path.dirname(path),
            self.basename_prefix + os.path.basename(path) + self.suffix)


def split_transform_join(
        token: str, sep: str, transform: Callable[[str], str]) -> str:
    return sep.join(transform(x) for x in token.split(sep))


def lexically_rewrite_token(token: str, transform: Callable[[str], str]) -> str:
    """Lexically replaces substrings between delimiters.

    This is useful for transforming substrings of text.

    This can transform "--foo=bar,baz" into
    f("--foo") + "=" + f("bar") + "," + f("baz")

    Args:
      token: text to transform, like a shell token.
      transform: text transformation.

    Returns:
      text with substrings transformed.
    """

    def inner_transform(text: str) -> str:
        return split_transform_join(text, ",", transform)

    return split_transform_join(token, "=", inner_transform)


@dataclasses.dataclass
class Action(object):
    """Represents a set of parameters of a single build action."""
    command: Sequence[str] = dataclasses.field(default_factory=list)
    outputs: FrozenSet[str] = dataclasses.field(default_factory=set)
    label: str = ""

    def run_cached(
            self,
            tempfile_transform: TempFileTransform,
            verbose: bool = False,
            dry_run: bool = False) -> int:
        """Runs a modified command and conditionally moves outputs in-place.

        Args:
          tempfile_transform: describes transformation to temporary file name.
          verbose: If True, print substituted command before running it.
          dry_run: If True, print substituted command and stop.
    """

        # renamed_outputs: keys: original file names, values: transformed temporary file names
        renamed_outputs = {}

        def replace_output_filename(arg: str) -> str:
            if arg in self.outputs:
                new_arg = tempfile_transform.transform(arg)
                if arg != new_arg:
                    renamed_outputs[arg] = new_arg
                return new_arg
            else:
                return arg

        substituted_command = [
            lexically_rewrite_token(tok, replace_output_filename)
            for tok in self.command
        ]

        if verbose or dry_run:
            cmd_str = " ".join(substituted_command)
            print(f"=== substituted command: {cmd_str}")

        if dry_run:
            return 0

        # mkdir when needed.
        if tempfile_transform.temp_dir:
            for new_arg in renamed_outputs.values():
                os.makedirs(os.path.dirname(new_arg), exist_ok=True)

        # Run the modified command.
        retval = subprocess.call(substituted_command)

        if retval != 0:
            # Option: clean-up .tmp files or leave them for inspection
            return retval

        # Otherwise command succeeded, so conditionally move outputs in-place.
        # TODO(fangism): This loop could be parallelized.
        for orig_out, temp_out in renamed_outputs.items():
            move_if_different(src=temp_out, dest=orig_out, verbose=verbose)

        if verbose:
            unrenamed_outputs = self.outputs - set(renamed_outputs.keys())
            if unrenamed_outputs:
                # Having un-renamed outputs is not an error, but rather an indicator
                # of a potentially missed opportunity to cache unchanged outputs.
                unrenamed_formatted = " ".join(unrenamed_outputs)
                print(f"  === Un-renamed outputs: {unrenamed_formatted}")

        return 0

    def run_twice_and_compare_outputs(
            self,
            tempfile_transform: TempFileTransform,
            verbose: bool = False) -> int:
        """Runs a command twice, copying declared outputs in between.

        Compare both sets of outputs, and error out if any differ.
        The advantage of this variant over others is that it eliminates
        output-path sensitivities by running the *same* command twice.
        One possible disadvantage is that this may expose behavioral
        differences due to the non/pre-existence of outputs ahead of
        running the command.

        Args:
          tempfile_transform: used to rename backup copies of outputs.
          verbose: if True, print more diagnostics.

        Returns:
          exit code 0 on command success and outputs match, else nonzero.
        """

        # Run the command the first time.
        retval = subprocess.call(self.command)

        # If the command failed, skip re-running.
        if retval != 0:
            return retval

        # Backup a copy of all declared outputs.
        renamed_outputs = {}
        for out in self.outputs:
            # TODO(fangism): what do we do about symlinks?
            # TODO(fangism): An output *directory* is unexpected, coming from GN,
            # but has been observed.  For now skip it.
            if os.path.isfile(out):
                renamed_outputs[out] = tempfile_transform.transform(out)
            # A nonexistent output would be caught by action_tracer.py.

        for out, backup in renamed_outputs.items():
            if tempfile_transform.temp_dir:
                os.makedirs(os.path.dirname(backup), exist_ok=True)
            # preserve metadata such as timestamp
            shutil.copy2(out, backup, follow_symlinks=False)

        rerun_retval = subprocess.call(self.command)
        if rerun_retval != 0:
            print(
                f"""Re-run of command {self.command} failed, while first time succeeded!?"""
            )
            return rerun_retval

        return verify_files_match(fileset=renamed_outputs, label=self.label)

    def run_twice_with_substitution_and_compare_outputs(
            self,
            tempfile_transform: TempFileTransform,
            verbose: bool = False) -> int:
        """Runs a command twice, the second time with renamed outputs, and compares.

        Caveat: If the contents if the outputs are sensitive to the names of the
        outputs, this will find too many differences.

        Args:
          tempfile_transform: used to rename backup copies of outputs.
          verbose: if True, print more diagnostics.

        Returns:
          exit code 0 on command success and outputs match, else nonzero.
        """

        # renamed_outputs: keys: original file names, values: transformed temporary file names
        renamed_outputs = {}

        def replace_output_filename(arg: str) -> str:
            if arg in self.outputs:
                new_arg = tempfile_transform.transform(arg)
                if arg != new_arg:
                    renamed_outputs[arg] = new_arg
                return new_arg
            else:
                return arg

        substituted_command = [
            lexically_rewrite_token(tok, replace_output_filename)
            for tok in self.command
        ]

        if verbose:
            cmd_str = " ".join(substituted_command)
            print(f"=== substituted command: {cmd_str}")

        # mkdir when needed.
        if tempfile_transform.temp_dir:
            for new_arg in renamed_outputs.values():
                os.makedirs(os.path.dirname(new_arg), exist_ok=True)

        # Run the original command.
        retval = subprocess.call(self.command)

        # If the command failed, skip re-running.
        if retval != 0:
            return retval

        # Otherwise command succeeded, re-run with different output locations.
        rerun_retval = subprocess.call(substituted_command)
        if rerun_retval != 0:
            print(
                f"Re-run failed with substituted outputs of target [{self.label}]: {substituted_command}"
            )
            return rerun_retval

        return verify_files_match(fileset=renamed_outputs, label=self.label)


def verify_files_match(fileset: Dict[str, str], label: str) -> int:
    """Compare outputs and report differences.

    Remove matching copies.

    Args:
      fileset: {file: backup} key-value pairs of files to compare. Backup files
        that match are removed to save space, while the .keys() files are kept.
      label: An identifier for the action that was run, for diagnostics.

    Returns:
      exit code 0 if all files matched, else 1.
    """
    matching_files, different_files = _partition(
        fileset.items(),
        # If either file is missing, this will fail, which indicates that
        # something is not working as expected.
        lambda pair: files_match(pair[0], pair[1]))

    # Remove any files that matched to save space.
    for _, temp_out in matching_files:
        os.remove(temp_out)

    if different_files:
        print(
            f"Repeating command for target [{label}] with renamed outputs produces different results:"
        )
        for orig, temp in different_files:
            print(f"  {orig} vs. {temp}")

        # Keep around different outputs for analysis.

        # Note: Even though the original command succeeded, forcing this to
        # fail may influence tools that examine the freshness of outputs
        # relative to the last succeeded command.
        return 1

    return 0


def main_arg_parser() -> argparse.ArgumentParser:
    """Construct the argument parser, called by main()."""
    parser = argparse.ArgumentParser(
        description="Wraps a GN action to preserve unchanged outputs",
        argument_default=[],
    )
    # label is only used for diagnostics
    parser.add_argument(
        "--label",
        type=str,
        default="",
        help="The wrapped target's label",
    )
    parser.add_argument(
        "--outputs", nargs="*", help="An action's declared outputs")
    parser.add_argument(
        "--depfile", help="A depfile that is written by the command")
    parser.add_argument(
        "--temp-suffix",
        type=str,
        default="",
        help="Suffix to use for temporary outputs",
    )
    parser.add_argument(
        "--temp-prefix",
        type=str,
        default="tmp-",
        help="Basename prefix to use for temporary outputs",
    )
    parser.add_argument(
        "--temp-dir",
        type=str,
        default="",
        help=
        "Temporary directory for writing, can be relative to working directory or absolute.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Print information about which outputs were renamed/cached.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Show transformed command and exit.",
    )
    parser.add_argument(
        "--disable",
        action="store_false",
        dest="enable",
        default=True,
        help="If disabled, run the original command as-is.",
    )
    parser.add_argument(
        "--check-repeatability",
        action="store_true",
        default=False,
        help=
        "Check for repeatability: run the command twice, with different outputs, and compare.",
    )
    parser.add_argument(
        "--rename-outputs",
        action="store_true",
        default=False,
        help=
        "When checking for repeatability: rename command-line outputs on the second run.",
    )

    # Positional args are the command and arguments to run.
    parser.add_argument("command", nargs="*", help="The command to run")
    return parser


def main():
    parser = main_arg_parser()
    args = parser.parse_args()

    tempfile_transform = TempFileTransform(
        temp_dir=args.temp_dir,
        suffix=args.temp_suffix,
        basename_prefix=args.temp_prefix,
    )
    if not tempfile_transform.valid:
        raise ValueError(
            "Need either --temp-dir or --temp-suffix, but both are missing.")

    wrap = args.enable
    # Decided whether or not to wrap the action script.
    ignored_scripts = {
        # If the action is only copying or linking, don't bother wrapping.
        "ln",
        "cp",  # TODO: Could conditionally copy if different.
        "rsync",
    }
    script = args.command[0]
    if os.path.basename(script) in ignored_scripts:
        wrap = False

    # If disabled, run the original command as-is.
    if not wrap:
        return subprocess.call(args.command)

    # Otherwise, rewrite the command using temporary outputs.
    outputs = set(args.outputs)
    if args.depfile:
        outputs.add(args.depfile)

    # Run a modified command that can leave unchanged outputs untouched.
    action = Action(
        command=args.command,
        outputs=outputs,
        label=args.label,
    )

    # Run one of the following modes:
    # check_repeatability: run the command twice, and compare the outputs.
    # [default]: redirect outputs to temporary locations, and move them
    #   in-place to their original locations if contents have not changed.

    if args.check_repeatability:
        if args.rename_outputs:
            # This check variant will find path-sensitive outputs,
            # and nondeterminstic outputs.
            return action.run_twice_with_substitution_and_compare_outputs(
                tempfile_transform=tempfile_transform, verbose=args.verbose)
        else:
            # This check will only find nondeterministic outputs.
            # For example, those affected by the current time.
            return action.run_twice_and_compare_outputs(
                tempfile_transform=tempfile_transform, verbose=args.verbose)

    return action.run_cached(
        tempfile_transform=tempfile_transform,
        verbose=args.verbose,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    sys.exit(main())
