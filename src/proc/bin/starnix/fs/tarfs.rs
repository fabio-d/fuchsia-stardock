// Copyright 2021 Fabio D'Urso. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Error;
use fuchsia_zircon as zx;
use std::collections::HashMap;
use std::convert::TryInto;
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;
use std::sync::RwLock;

use super::*;
use crate::errno;
use crate::error;
use crate::types::*;

struct ZxioReader<'a> {
    file: &'a syncio::Zxio,
}

impl<'a> ZxioReader<'a> {
    fn new(file: &'a syncio::Zxio) -> ZxioReader<'a> {
        ZxioReader { file }
    }
}

impl<'a> std::io::Read for ZxioReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf).map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))
    }
}

pub struct TarFilesystem {
    tar_file: syncio::Zxio,
    inodes: RwLock<HashMap<ino_t, TarInode>>,
}

impl TarFilesystem {
    pub fn new(tar_file: syncio::Zxio) -> Result<FileSystemHandle, Error> {
        let tar_fs = Arc::new(TarFilesystem { tar_file, inodes: RwLock::new(HashMap::new()) });

        let tar_root = TarDirectory::new(Arc::clone(&tar_fs));
        tar_fs.add_inode(TarInode::Directory(Arc::clone(&tar_root)));

        let fs_handle = FileSystem::new(TarFileSystemOps);
        fs_handle.set_root(tar_root.build_ops());

        let mut archive = tar::Archive::new(ZxioReader::new(&tar_fs.tar_file));
        let mut path_to_inode = HashMap::new(); // to resolve hard links

        for tar_entry in archive.entries()? {
            let tar_entry = tar_entry?;

            // Split path into ancestors and name
            let path = tar_entry.path()?;
            let (ancestors, name) = parse_path(&path)?;

            let parent = get_or_create_parent_directory(Arc::clone(&tar_root), &ancestors)?;
            let mut dentries_w = parent.dentries.write().unwrap();

            // Store and resolve tar entry to inode number
            let inode_num = match tar_entry.header().entry_type() {
                tar::EntryType::Directory => {
                    let dir = TarDirectory::new(Arc::clone(&tar_fs));
                    tar_fs.add_inode(TarInode::Directory(dir))
                }
                tar::EntryType::Regular => {
                    let file = TarFile::new(
                        Arc::clone(&tar_fs),
                        tar_entry.raw_file_position(),
                        tar_entry.header().size()?,
                    );
                    tar_fs.add_inode(TarInode::File(file))
                }
                tar::EntryType::Link => {
                    let inode_num =
                        path_to_inode.get(&tar_entry.link_name_bytes().unwrap().into_owned());
                    if let Some(inode_num) = inode_num {
                        *inode_num
                    } else {
                        anyhow::bail!("Hard link does not refer to an already-seen file");
                    }
                }
                _ => {
                    unimplemented!("Tar entry type: {:?}", tar_entry.header().entry_type())
                }
            };

            path_to_inode.insert(tar_entry.path_bytes().into_owned(), inode_num);
            dentries_w.insert(name.to_owned(), inode_num);
        }

        // These directories must always exist
        get_or_create_parent_directory(Arc::clone(&tar_root), &[b"dev"])?;
        get_or_create_parent_directory(Arc::clone(&tar_root), &[b"proc"])?;
        get_or_create_parent_directory(Arc::clone(&tar_root), &[b"tmp"])?;

        Ok(fs_handle)
    }

    fn add_inode(self: &Arc<TarFilesystem>, inode: TarInode) -> ino_t {
        let mut inodes_w = self.inodes.write().unwrap();
        let num = inodes_w.len() as ino_t + 1;
        let r = inodes_w.insert(num, inode);
        assert!(r.is_none()); // inode numbers must be unique
        num
    }

    fn get_or_create_node(
        self: &Arc<TarFilesystem>,
        fs: &FileSystemHandle,
        inode_num: ino_t,
    ) -> Result<FsNodeHandle, Errno> {
        fs.get_or_create_node(Some(inode_num), |inode_num| {
            let inodes_r = self.inodes.read().unwrap();
            let inode = inodes_r.get(&inode_num).unwrap();
            let (ops, mode) = match inode {
                TarInode::Directory(dir) => (
                    Box::new(dir.build_ops()) as Box<dyn FsNodeOps>,
                    FileMode::IFDIR | FileMode::ALLOW_ALL,
                ),
                TarInode::File(file) => (
                    Box::new(file.build_ops()) as Box<dyn FsNodeOps>,
                    FileMode::IFREG | FileMode::ALLOW_ALL,
                ),
            };

            let fs_node = FsNode::new(ops, fs, inode_num, mode);
            if let TarInode::File(file) = inode {
                fs_node.info_write().size = file.size.try_into().expect("file too big");
            }

            Ok(fs_node)
        })
    }
}

struct TarFileSystemOps;

impl FileSystemOps for TarFileSystemOps {}

enum TarInode {
    Directory(Arc<TarDirectory>),
    File(Arc<TarFile>),
}

struct TarDirectory {
    fs: Arc<TarFilesystem>,
    dentries: RwLock<HashMap<FsString, ino_t>>,
}

impl TarDirectory {
    fn new(fs: Arc<TarFilesystem>) -> Arc<TarDirectory> {
        Arc::new(TarDirectory { fs, dentries: RwLock::new(HashMap::new()) })
    }

    fn build_ops(self: &Arc<TarDirectory>) -> TarDirectoryOps {
        TarDirectoryOps { inner: Arc::clone(self) }
    }
}

struct TarDirectoryOps {
    inner: Arc<TarDirectory>,
}

impl FsNodeOps for TarDirectoryOps {
    fn open(&self, _node: &FsNode, _flags: OpenFlags) -> Result<Box<dyn FileOps>, Errno> {
        error!(ENOSYS)
    }

    fn lookup(&self, node: &FsNode, name: &FsStr) -> Result<FsNodeHandle, Errno> {
        let inode_num =
            if let Some(inode_num) = self.inner.dentries.read().unwrap().get(name) {
                *inode_num
            } else {
                return error!(ENOENT);
            };

        self.inner.fs.get_or_create_node(&node.fs(), inode_num)
    }
}

struct TarFile {
    fs: Arc<TarFilesystem>,
    offset: u64,
    size: u64,
}

impl TarFile {
    fn new(fs: Arc<TarFilesystem>, offset: u64, size: u64) -> Arc<TarFile> {
        Arc::new(TarFile { fs, offset, size })
    }

    fn build_ops(self: &Arc<TarFile>) -> TarFileOps {
        TarFileOps { inner: Arc::clone(self) }
    }
}

struct TarFileOps {
    inner: Arc<TarFile>,
}

// based on ExtFile::open
impl FsNodeOps for TarFileOps {
    fn open(&self, _node: &FsNode, _flags: OpenFlags) -> Result<Box<dyn FileOps>, Errno> {
        let tar_file = &self.inner.fs.tar_file;

        let vmo = zx::Vmo::create(self.inner.size).map_err(|_| errno!(ENOMEM))?;

        // TODO: read in chunks to avoid allocating a single big buffer
        let mut buffer = vec![0; self.inner.size as usize];
        if tar_file.read_at(self.inner.offset, &mut buffer) != Ok(buffer.len()) {
            panic!();
        }
        vmo.write(&buffer, 0).unwrap();

        Ok(Box::new(VmoFileObject::new(Arc::new(vmo))))
    }
}

fn parse_path(path: &std::path::Path) -> Result<(Vec<&FsStr>, &FsStr), Error> {
    let mut ancestors = Vec::new();
    for c in path.components() {
        if let std::path::Component::Normal(os_str) = c {
            ancestors.push(os_str.as_bytes());
        }
    }

    if let Some(name) = ancestors.pop() {
        Ok((ancestors, name))
    } else {
        anyhow::bail!("path cannot be empty");
    }
}

fn get_or_create_parent_directory(
    current_dir: Arc<TarDirectory>,
    path: &[&FsStr],
) -> Result<Arc<TarDirectory>, Error> {
    if path.len() == 0 {
        return Ok(current_dir);
    }

    let fs = &current_dir.fs;
    let head = path[0];
    let tail = &path[1..];

    // Lookup head
    let mut dentries_w = current_dir.dentries.write().unwrap();
    let head_dir =
        if let Some(inode_num) = dentries_w.get(head) {
            let inodes_r = fs.inodes.read().unwrap();
            if let TarInode::Directory(ref dir) = inodes_r.get(inode_num).unwrap() {
                Arc::clone(dir)
            } else {
                anyhow::bail!("Cannot traverse non-directory {:?}", head);
            }
        } else {
            let tar_directory = TarDirectory::new(Arc::clone(&fs));
            let inode_num = fs.add_inode(TarInode::Directory(Arc::clone(&tar_directory)));
            dentries_w.insert(head.to_owned(), inode_num);
            tar_directory
        };

    get_or_create_parent_directory(head_dir, tail)
}
