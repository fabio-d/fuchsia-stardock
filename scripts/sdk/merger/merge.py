#!/usr/bin/env python3
# Copyright 2018 The Fuchsia Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import contextlib
import errno
import json
import os
import shutil
import sys
import tarfile
import tempfile

from functools import total_ordering

all_outputs = []
all_inputs = []
follow_symlinks = False
has_hermetic_inputs_file = False


def _add_output(path):
    all_outputs.append(os.path.relpath(path))


def _add_input(path):
    all_inputs.append(os.path.relpath(path))


@total_ordering
class Part(object):

    def __init__(self, json):
        self.meta = json['meta']
        self.type = json['type']

    def __lt__(self, other):
        return self.meta < other.meta and self.type < other.type

    def __eq__(self, other):
        return (
            isinstance(other, self.__class__) and self.meta == other.meta and
            self.type == other.type)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.meta, self.type))


@contextlib.contextmanager
def _open_archive(archive, directory):
    '''Manages a directory in which an existing SDK is laid out.'''
    if directory:
        yield directory
    elif archive:
        temp_dir = tempfile.mkdtemp(prefix='fuchsia-merger')
        # Extract the tarball into the temporary directory.
        # This is vastly more efficient than accessing files one by one via
        # the tarfile API.
        with tarfile.open(archive) as archive_file:
            def is_within_directory(directory, target):
                
                abs_directory = os.path.abspath(directory)
                abs_target = os.path.abspath(target)
            
                prefix = os.path.commonprefix([abs_directory, abs_target])
                
                return prefix == abs_directory
            
            def safe_extract(tar, path=".", members=None, *, numeric_owner=False):
            
                for member in tar.getmembers():
                    member_path = os.path.join(path, member.name)
                    if not is_within_directory(path, member_path):
                        raise Exception("Attempted Path Traversal in Tar File")
            
                tar.extractall(path, members, numeric_owner=numeric_owner) 
                
            
            safe_extract(archive_file, temp_dir)
        try:
            yield temp_dir
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
    else:
        raise Exception('Error: archive or directory must be set')


@contextlib.contextmanager
def _open_output(archive, directory):
    '''Manages the output of this script.'''
    if directory:
        # Remove any existing output.
        shutil.rmtree(directory, ignore_errors=True)
        yield directory
    elif archive:
        temp_dir = tempfile.mkdtemp(prefix='fuchsia-merger')
        try:
            yield temp_dir
            # Write the archive file.
            if not has_hermetic_inputs_file:
                with tarfile.open(archive, "w:gz") as archive_file:
                    archive_file.add(temp_dir, arcname='')
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
    else:
        raise Exception('Error: archive or directory must be set')


def _get_manifest(sdk_dir):
    manifest_path = os.path.join(sdk_dir, 'meta', 'manifest.json')
    _add_input(manifest_path)
    '''Returns the set of elements in the given SDK.'''
    with open(manifest_path, 'r') as manifest:
        return json.load(manifest)


def _get_meta(element, sdk_dir):
    '''Returns the contents of the given element's manifest in a given SDK.'''
    meta_path = os.path.join(sdk_dir, element)
    _add_input(meta_path)
    with open(meta_path, 'r') as meta:
        return json.load(meta)


def _get_type(element):
    '''Returns the SDK element type.'''
    # For versioned SDK elements, the type is inside the data field.
    if 'schema_id' in element:
        return element['data']['type']
    return element['type']


def _get_files(element_meta):
    '''Extracts the files associated with the given element.
    Returns a 2-tuple containing:
     - the set of arch-independent files;
     - the sets of arch-dependent files, indexed by architecture.
    '''
    type = _get_type(element_meta)
    common_files = set()
    arch_files = {}
    if type == 'cc_prebuilt_library':
        common_files.update(element_meta['headers'])
        for arch, binaries in element_meta['binaries'].items():
            contents = set()
            contents.add(binaries['link'])
            if 'dist' in binaries:
                contents.add(binaries['dist'])
            if 'debug' in binaries:
                contents.add(binaries['debug'])
            arch_files[arch] = contents
    elif type == 'cc_source_library':
        common_files.update(element_meta['headers'])
        common_files.update(element_meta['sources'])
    elif type == 'dart_library':
        common_files.update(element_meta['sources'])
    elif type == 'fidl_library':
        common_files.update(element_meta['sources'])
    elif type in ['host_tool', 'companion_host_tool']:
        if 'files' in element_meta:
            common_files.update(element_meta['files'])
        if 'target_files' in element_meta:
            arch_files.update(element_meta['target_files'])
    elif type == 'loadable_module':
        common_files.update(element_meta['resources'])
        arch_files.update(element_meta['binaries'])
    elif type == 'sysroot':
        for arch, version in element_meta['versions'].items():
            contents = set()
            contents.update(version['headers'])
            contents.update(version['link_libs'])
            contents.update(version['dist_libs'])
            contents.update(version['debug_libs'])
            arch_files[arch] = contents
    elif type == 'documentation':
        common_files.update(element_meta['docs'])
    elif type in ('config', 'license', 'component_manifest'):
        common_files.update(element_meta['data'])
    elif type in ('version_history'):
        # These types are pure metadata.
        pass
    elif type == 'bind_library':
        common_files.update(element_meta['sources'])
    else:
        raise Exception('Unknown element type: ' + type)
    return (common_files, arch_files)


def _ensure_directory(path):
    '''Ensures that the directory hierarchy of the given path exists.'''
    target_dir = os.path.dirname(path)
    try:
        os.makedirs(target_dir)
    except OSError as exception:
        if exception.errno == errno.EEXIST and os.path.isdir(target_dir):
            pass
        else:
            raise


def _copy_file(file, source_dir, dest_dir):
    '''Copies a file to a given path, taking care of creating directories if
    needed.
    '''
    source = os.path.join(source_dir, file)
    destination = os.path.join(dest_dir, file)
    if not has_hermetic_inputs_file:
        _ensure_directory(destination)
        shutil.copy2(source, destination, follow_symlinks=follow_symlinks)
    _add_input(source)
    _add_output(destination)


def _copy_files(files, source_dir, dest_dir):
    '''Copies a set of files to a given directory.'''
    for file in files:
        _copy_file(file, source_dir, dest_dir)


def _copy_identical_files(set_one, source_dir_one, set_two, dest_dir):
    '''Verifies that two sets of files are absolutely identical and then copies
    them to the output directory.
    '''
    if set_one != set_two:
        return False
    # Not verifying that the contents of the files are the same, as builds are
    # not exactly stable at the moment.
    _copy_files(set_one, source_dir_one, dest_dir)
    return True


def _copy_element(element, source_dir, dest_dir):
    '''Copy an entire SDK element to a given directory.'''
    meta = _get_meta(element, source_dir)
    common_files, arch_files = _get_files(meta)
    files = common_files
    for more_files in arch_files.values():
        files.update(more_files)
    _copy_files(files, source_dir, dest_dir)
    # Copy the metadata file as well.
    _copy_file(element, source_dir, dest_dir)


def _write_meta(element, source_dir_one, source_dir_two, dest_dir):
    '''Writes a meta file for the given element, resulting from the merge of the
    meta files for that element in the two given SDK directories.
    '''
    meta_one = _get_meta(element, source_dir_one)
    meta_two = _get_meta(element, source_dir_two)
    # TODO(fxbug.dev/5362): verify that the common parts of the metadata files are in
    # fact identical.
    type = _get_type(meta_one)
    meta = {}
    if type in ('cc_prebuilt_library', 'loadable_module'):
        meta = meta_one
        meta['binaries'].update(meta_two['binaries'])
    elif type == 'sysroot':
        meta = meta_one
        meta['versions'].update(meta_two['versions'])
    elif type in ['host_tool', 'companion_host_tool']:
        meta = meta_one
        if not 'target_files' in meta:
            meta['target_files'] = {}
        if 'target_files' in meta_two:
            meta['target_files'].update(meta_two['target_files'])
    elif type in ('cc_source_library', 'dart_library', 'fidl_library',
                  'documentation', 'device_profile', 'config', 'license',
                  'component_manifest', 'bind_library', 'version_history'):
        # These elements are arch-independent, the metadata does not need any
        # update.
        meta = meta_one
    else:
        raise Exception('Unknown element type: ' + type)
    meta_path = os.path.join(dest_dir, element)
    if not has_hermetic_inputs_file:
        _ensure_directory(meta_path)
        with open(meta_path, 'w') as meta_file:
            json.dump(
                meta,
                meta_file,
                indent=2,
                sort_keys=True,
                separators=(',', ': '))
    _add_output(meta_path)
    return True


def _has_host_content(parts):
    '''Returns true if the given list of SDK parts contains an element with
    content built for a host.
    '''
    return 'host_tool' in [part.type for part in parts]


def _write_manifest(source_dir_one, source_dir_two, dest_dir):
    '''Writes a manifest file resulting from the merge of the manifest files for
    the two given SDK directories.
    '''
    manifest_one = _get_manifest(source_dir_one)
    manifest_two = _get_manifest(source_dir_two)
    parts_one = set([Part(p) for p in manifest_one['parts']])
    parts_two = set([Part(p) for p in manifest_two['parts']])

    manifest = {'arch': {}}

    # Schema version.
    if manifest_one['schema_version'] != manifest_two['schema_version']:
        print('Error: mismatching schema version')
        return False
    manifest['schema_version'] = manifest_one['schema_version']

    # Host architecture.
    host_archs = set()
    if _has_host_content(parts_one):
        host_archs.add(manifest_one['arch']['host'])
    if _has_host_content(parts_two):
        host_archs.add(manifest_two['arch']['host'])
    if not host_archs:
        # The archives do not have any host content. The architecture is not
        # meaningful in that case but is still needed: just pick one.
        host_archs.add(manifest_one['arch']['host'])
    if len(host_archs) != 1:
        print(
            'Error: mismatching host architecture: %s' % ', '.join(host_archs))
        return False
    manifest['arch']['host'] = list(host_archs)[0]

    # Id.
    if manifest_one['id'] != manifest_two['id']:
        print('Error: mismatching id')
        return False
    manifest['id'] = manifest_one['id']

    # Root.
    if manifest_one['root'] != manifest_two['root']:
        print('Error: mismatching root')
        return False
    manifest['root'] = manifest_one['root']

    # Target architectures.
    manifest['arch']['target'] = sorted(
        set(manifest_one['arch']['target']) |
        set(manifest_two['arch']['target']))

    # Parts.
    manifest['parts'] = [vars(p) for p in sorted(parts_one | parts_two)]

    manifest_path = os.path.join(dest_dir, 'meta', 'manifest.json')
    if not has_hermetic_inputs_file:
        _ensure_directory(manifest_path)
        with open(manifest_path, 'w') as manifest_file:
            json.dump(
                manifest,
                manifest_file,
                indent=2,
                sort_keys=True,
                separators=(',', ': '))
    _add_output(manifest_path)
    return True


def main():
    parser = argparse.ArgumentParser(
        description=('Merges the contents of two SDKs'))
    first_group = parser.add_mutually_exclusive_group(required=True)
    first_group.add_argument(
        '--first-archive',
        help='Path to the first SDK - as an archive',
        default='')
    first_group.add_argument(
        '--first-directory',
        help='Path to the first SDK - as a directory',
        default='')
    second_group = parser.add_mutually_exclusive_group(required=True)
    second_group.add_argument(
        '--second-archive',
        help='Path to the second SDK - as an archive',
        default='')
    second_group.add_argument(
        '--second-directory',
        help='Path to the second SDK - as a directory',
        default='')
    output_group = parser.add_mutually_exclusive_group(required=True)
    output_group.add_argument(
        '--output-archive',
        help='Path to the merged SDK - as an archive',
        default='')
    output_group.add_argument(
        '--output-directory',
        help='Path to the merged SDK - as a directory',
        default='')
    parser.add_argument('--stamp-file', help='Path to the stamp file')
    hermetic_group = parser.add_mutually_exclusive_group()
    hermetic_group.add_argument('--depfile', help='Path to the stamp file')
    hermetic_group.add_argument(
        '--hermetic-inputs-file', help='Path to the hermetic inputs file')
    args = parser.parse_args()

    # When producing an archive, we need to copy the symlink targets, not the symlinks themselves.
    global follow_symlinks
    follow_symlinks = bool(args.output_archive)

    global has_hermetic_inputs_file
    has_hermetic_inputs_file = bool(args.hermetic_inputs_file)

    has_errors = False

    with _open_archive(args.first_archive, args.first_directory) as first_dir, \
         _open_archive(args.second_archive, args.second_directory) as second_dir, \
         _open_output(args.output_archive, args.output_directory) as out_dir:

        first_elements = set(
            [Part(p) for p in _get_manifest(first_dir)['parts']])
        second_elements = set(
            [Part(p) for p in _get_manifest(second_dir)['parts']])
        common_elements = first_elements & second_elements

        # Copy elements that appear in a single SDK.
        for element in sorted(first_elements - common_elements):
            _copy_element(element.meta, first_dir, out_dir)
        for element in (second_elements - common_elements):
            _copy_element(element.meta, second_dir, out_dir)

        # Verify and merge elements which are common to both SDKs.
        for raw_element in sorted(common_elements):
            element = raw_element.meta
            first_meta = _get_meta(element, first_dir)
            second_meta = _get_meta(element, second_dir)
            first_common, first_arch = _get_files(first_meta)
            second_common, second_arch = _get_files(second_meta)

            # Common files should not vary.
            if not _copy_identical_files(first_common, first_dir, second_common,
                                         out_dir):
                print('Error: different common files for %s' % (element))
                has_errors = True
                continue

            # Arch-dependent files need to be merged in the metadata.
            all_arches = set(first_arch.keys()) | set(second_arch.keys())
            for arch in all_arches:
                if arch in first_arch and arch in second_arch:
                    if not _copy_identical_files(first_arch[arch], first_dir,
                                                 second_arch[arch], out_dir):
                        print(
                            'Error: different %s files for %s' %
                            (arch, element))
                        has_errors = True
                        continue
                elif arch in first_arch:
                    _copy_files(first_arch[arch], first_dir, out_dir)
                elif arch in second_arch:
                    _copy_files(second_arch[arch], second_dir, out_dir)

            if not _write_meta(element, first_dir, second_dir, out_dir):
                print('Error: unable to merge meta for %s' % (element))
                has_errors = True

        if not _write_manifest(first_dir, second_dir, out_dir):
            print('Error: could not write manifest file')
            has_errors = True

        # TODO(fxbug.dev/5362): verify that metadata files are valid.

    if args.stamp_file and not has_hermetic_inputs_file:
        with open(args.stamp_file, 'w') as stamp_file:
            stamp_file.write('')

    if args.hermetic_inputs_file:
        with open(args.hermetic_inputs_file, 'w') as hermetic_inputs_file:
            hermetic_inputs_file.write('\n'.join(all_inputs))

    if args.depfile:
        with open(args.depfile, 'w') as depfile:
            depfile.write(
                '{} {}: {}'.format(
                    args.stamp_file, ' '.join(all_outputs),
                    ' '.join(all_inputs)))

    return 1 if has_errors else 0


if __name__ == '__main__':
    sys.exit(main())
