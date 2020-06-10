#!/usr/bin/env python2.7
# Copyright 2020 The Fuchsia Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import errno

from args import ArgParser
from cli import CommandLineInterface
from host import Host
from device import Device
from fuzzer import Fuzzer


class Factory(object):
    """Facility for creating associated objects.

       The factory can create CommandLineInterfaces, Hosts, Devices, and
       Fuzzers. More importantly, it can construct them with references to
       each other, i.e. a Factory-constructed Fuzzer automatically gets a
       reference to a Factory-constructed Device, which has a reference to a
       Factory-constructed Host.

       Attributes:
         cli:       Command line interface object for user interactions.
    """

    def __init__(self, cli=None):
        if not cli:
            cli = CommandLineInterface()
        self._cli = cli

    @property
    def cli(self):
        return self._cli

    def create_parser(self):
        """Returns an argument parser."""
        parser = ArgParser()
        parser.factory = self
        parser.add_parsers()
        return parser

    def create_host(self, **kwargs):
        """Constructs a Host from a local build directory."""
        fuchsia_dir = kwargs.pop('fuchsia_dir', self.cli.getenv('FUCHSIA_DIR'))
        if not fuchsia_dir:
            self.host.error(
                'FUCHSIA_DIR not set.', 'Have you sourced "scripts/fx-env.sh"?')
        assert not kwargs, 'Unexpected keyword arguments: {}'.format(kwargs)
        host = Host(self.cli, fuchsia_dir)
        pathname = host.fxpath('.fx-build-dir')
        build_dir = self.cli.readfile(
            pathname,
            on_error=[
                'Failed to read build directory from {}.'.format(pathname),
                'Have you run "fx set ... --fuzz-with <sanitizer>"?'
            ])
        host.configure(build_dir)
        host.read_fuzzers(host.fxpath(build_dir, 'fuzzers.json'))
        return host

    def create_device(self, host=None):
        """Constructs a Device from the build environment"""
        if not host:
            host = self.create_host()
        pathname = '{}.device'.format(host.build_dir)
        device_name = self.cli.readfile(pathname, missing_ok=True)
        addr = host.find_device(device_name)
        device = Device(host, addr)
        device.configure()
        return device

    def _resolve_fuzzer(self, host, name):
        """Matches a fuzzer name pattern to a fuzzer."""
        matches = host.fuzzers(name)
        if not matches:
            self.cli.error('No matching fuzzers found.', 'Try "fx fuzz list".')
        if len(matches) > 1:
            choices = ["/".join(m) for m in matches]
            self.cli.echo('More than one match found.')
            prompt = 'Please pick one from the list:'
            return self.cli.choose(prompt, choices).split('/')
        else:
            return matches[0]

    def create_fuzzer(self, args, device=None):
        """Constructs a Fuzzer from command line arguments, showing a
        disambiguation menu if specified name matches more than one fuzzer."""
        if not device:
            device = self.create_device()

        package, executable = self._resolve_fuzzer(device.host, args.name)
        fuzzer = Fuzzer(device, package, executable)

        keys = [
            key for key, val in vars(Fuzzer).items()
            if isinstance(val, property) and val.fset
        ]
        for key, val in vars(args).items():
            if key in keys and val is not None:
                setattr(fuzzer, key, val)

        return fuzzer
