// Copyright 2021 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use crate::fs::{proc::directory::*, *};
use crate::mm::{ProcMapsFile, ProcStatFile};
use crate::task::{CurrentTask, Task};
use crate::types::*;

use parking_lot::Mutex;

/// Creates an [`FsNode`] that represents the `/proc/<pid>` directory for `task`.
pub fn pid_directory(fs: &FileSystemHandle, task: Arc<Task>) -> Arc<FsNode> {
    StaticDirectoryBuilder::new(fs)
        .add_node_entry(b"exe", ExeSymlink::new(fs, task.clone()))
        .add_node_entry(b"fd", dynamic_directory(fs, FdDirectory { task: task.clone() }))
        .add_node_entry(b"fdinfo", dynamic_directory(fs, FdInfoDirectory { task: task.clone() }))
        .add_node_entry(b"maps", ProcMapsFile::new(fs, task.clone()))
        .add_node_entry(b"stat", ProcStatFile::new(fs, task.clone()))
        .add_node_entry(b"cmdline", CmdlineFile::new(fs, task.clone()))
        .build()
}

/// `FdDirectory` implements the directory listing operations for a `proc/<pid>/fd` directory.
///
/// Reading the directory returns a list of all the currently open file descriptors for the
/// associated task.
struct FdDirectory {
    task: Arc<Task>,
}

impl DirectoryDelegate for FdDirectory {
    fn list(&self, _fs: &Arc<FileSystem>) -> Result<Vec<DynamicDirectoryEntry>, Errno> {
        Ok(fds_to_directory_entries(self.task.files.get_all_fds()))
    }

    fn lookup(&self, fs: &Arc<FileSystem>, name: &FsStr) -> Result<Arc<FsNode>, Errno> {
        let fd = FdNumber::from_fs_str(name).map_err(|_| errno!(ENOENT))?;
        // Make sure that the file descriptor exists before creating the node.
        let _ = self.task.files.get(fd).map_err(|_| errno!(ENOENT))?;
        Ok(fs.create_node(FdSymlink::new(self.task.clone(), fd), FdSymlink::file_mode()))
    }
}

/// `FdInfoDirectory` implements the directory listing operations for a `proc/<pid>/fdinfo`
/// directory.
///
/// Reading the directory returns a list of all the currently open file descriptors for the
/// associated task.
struct FdInfoDirectory {
    task: Arc<Task>,
}

impl DirectoryDelegate for FdInfoDirectory {
    fn list(&self, _fs: &Arc<FileSystem>) -> Result<Vec<DynamicDirectoryEntry>, Errno> {
        Ok(fds_to_directory_entries(self.task.files.get_all_fds()))
    }

    fn lookup(&self, fs: &Arc<FileSystem>, name: &FsStr) -> Result<Arc<FsNode>, Errno> {
        let fd = FdNumber::from_fs_str(name).map_err(|_| errno!(ENOENT))?;
        let file = self.task.files.get(fd).map_err(|_| errno!(ENOENT))?;
        let pos = *file.offset.lock();
        let flags = file.flags();
        let data = format!("pos:\t{}flags:\t0{:o}\n", pos, flags.bits()).into_bytes();
        Ok(fs.create_node_with_ops(ByteVecFile::new(data), mode!(IFREG, 0o444)))
    }
}

fn fds_to_directory_entries(fds: Vec<FdNumber>) -> Vec<DynamicDirectoryEntry> {
    fds.into_iter()
        .map(|fd| DynamicDirectoryEntry {
            entry_type: DirectoryEntryType::DIR,
            name: fd.raw().to_string().into_bytes(),
            inode: None,
        })
        .collect()
}

/// An `ExeSymlink` points to the `executable_node` (the node that contains the task's binary) of
/// the task that reads it.
pub struct ExeSymlink {
    task: Arc<Task>,
}

impl ExeSymlink {
    fn new(fs: &FileSystemHandle, task: Arc<Task>) -> FsNodeHandle {
        fs.create_node_with_ops(ExeSymlink { task }, FileMode::IFLNK | FileMode::ALLOW_ALL)
    }
}

impl FsNodeOps for ExeSymlink {
    fs_node_impl_symlink!();

    fn readlink(
        &self,
        _node: &FsNode,
        _current_task: &CurrentTask,
    ) -> Result<SymlinkTarget, Errno> {
        if let Some(node) = self.task.mm.executable_node() {
            Ok(SymlinkTarget::Node(node))
        } else {
            error!(ENOENT)
        }
    }
}

/// `FdSymlink` is a symlink that points to a specific file descriptor in a task.
pub struct FdSymlink {
    /// The file descriptor that this symlink targets.
    fd: FdNumber,

    /// The task that `fd` is to be read from.
    task: Arc<Task>,
}

impl FdSymlink {
    fn new(task: Arc<Task>, fd: FdNumber) -> Box<dyn FsNodeOps> {
        Box::new(FdSymlink { fd, task })
    }

    fn file_mode() -> FileMode {
        FileMode::IFLNK | FileMode::ALLOW_ALL
    }
}

impl FsNodeOps for FdSymlink {
    fs_node_impl_symlink!();

    fn readlink(
        &self,
        _node: &FsNode,
        _current_task: &CurrentTask,
    ) -> Result<SymlinkTarget, Errno> {
        let file = self.task.files.get(self.fd).map_err(|_| errno!(ENOENT))?;
        Ok(SymlinkTarget::Node(file.name.clone()))
    }
}

/// `CmdlineFile` implements the `FsNodeOps` for a `proc/<pid>/cmdline` file.
pub struct CmdlineFile {
    /// The task from which the `CmdlineFile` fetches the command line parameters.
    task: Arc<Task>,
    seq: Mutex<SeqFileState<()>>,
}

impl CmdlineFile {
    fn new(fs: &FileSystemHandle, task: Arc<Task>) -> FsNodeHandle {
        fs.create_node_with_ops(
            SimpleFileNode::new(move || {
                Ok(CmdlineFile { task: Arc::clone(&task), seq: Mutex::new(SeqFileState::new()) })
            }),
            mode!(IFREG, 0o444),
        )
    }
}

impl FileOps for CmdlineFile {
    fileops_impl_seekable!();
    fileops_impl_nonblocking!();

    fn read_at(
        &self,
        _file: &FileObject,
        current_task: &CurrentTask,
        offset: usize,
        data: &[UserBuffer],
    ) -> Result<usize, Errno> {
        let mut seq = self.seq.lock();
        let iter = |_cursor, sink: &mut SeqFileBuf| {
            let argv = self.task.argv.read();
            for arg in &*argv {
                sink.write(arg.as_bytes_with_nul());
            }
            Ok(None)
        };
        seq.read_at(current_task, iter, offset, data)
    }

    fn write_at(
        &self,
        _file: &FileObject,
        _current_task: &CurrentTask,
        _offset: usize,
        _data: &[UserBuffer],
    ) -> Result<usize, Errno> {
        Err(ENOSYS)
    }
}
