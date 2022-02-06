// Copyright 2021 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use fuchsia_zircon::{self as zx, HandleBased};
use log::warn;
use parking_lot::{Mutex, RwLockReadGuard, RwLockWriteGuard};
use std::sync::Arc;
use syncio::{
    zxio, zxio::zxio_get_posix_mode, zxio_node_attributes_t, DirentIterator, Zxio, ZxioDirent,
    ZxioSignals,
};

use crate::errno;
use crate::error;
use crate::fd_impl_directory;
use crate::fd_impl_nonblocking;
use crate::fd_impl_nonseekable;
use crate::fd_impl_seekable;
use crate::from_status_like_fdio;
use crate::fs::*;
use crate::logging::impossible_error;
use crate::syscalls::*;
use crate::task::*;
use crate::types::*;
use crate::vmex_resource::VMEX_RESOURCE;

pub struct RemoteFs;
impl FileSystemOps for RemoteFs {
    fn generate_node_ids(&self) -> bool {
        true
    }
}

impl RemoteFs {
    pub fn new(root: zx::Channel, rights: u32) -> Result<FileSystemHandle, Errno> {
        let remote_node = RemoteNode::new(root.into_handle(), rights)?;
        let attrs = remote_node.zxio.attr_get().map_err(|_| errno!(EIO))?;
        let mut root_node = FsNode::new_root(remote_node);
        root_node.inode_num = attrs.id;
        Ok(FileSystem::new_with_root(RemoteFs, root_node))
    }
}

struct RemoteNode {
    /// The underlying Zircon I/O object for this remote node.
    ///
    /// We delegate to the zxio library for actually doing I/O with remote
    /// objects, including fuchsia.io.Directory and fuchsia.io.File objects.
    /// This structure lets us share code with FDIO and other Fuchsia clients.
    zxio: Arc<syncio::Zxio>,

    /// The fuchsia.io rights for the dir handle. Subdirs will be opened with
    /// the same rights.
    rights: u32,
}

impl RemoteNode {
    fn new(handle: zx::Handle, rights: u32) -> Result<RemoteNode, Errno> {
        let zxio = Arc::new(Zxio::create(handle).map_err(|status| from_status_like_fdio!(status))?);
        Ok(RemoteNode { zxio, rights })
    }
}

pub fn create_fuchsia_pipe(kern: &Kernel, handle: zx::Handle) -> Result<FileHandle, Errno> {
    let zxio = Zxio::create(handle).map_err(|status| from_status_like_fdio!(status))?;
    let ops = Box::new(RemotePipeObject::new(zxio)?);
    Ok(Anon::new_file(anon_fs(kern), ops, OpenFlags::RDWR))
}

fn update_into_from_attrs(info: &mut FsNodeInfo, attrs: zxio_node_attributes_t) {
    /// st_blksize is measured in units of 512 bytes.
    const BYTES_PER_BLOCK: usize = 512;

    // TODO - store these in FsNodeState and convert on fstat
    info.size = attrs.content_size as usize;
    info.storage_size = attrs.storage_size as usize;
    info.blksize = BYTES_PER_BLOCK;
    info.link_count = attrs.link_count;
}

fn get_zxio_signals_from_events(events: FdEvents) -> zxio::zxio_signals_t {
    let mut signals = ZxioSignals::NONE;
    if events & FdEvents::POLLIN {
        signals |= ZxioSignals::READABLE | ZxioSignals::PEER_CLOSED | ZxioSignals::READ_DISABLED;
    }
    if events & FdEvents::POLLOUT {
        signals |= ZxioSignals::WRITABLE | ZxioSignals::WRITE_DISABLED;
    }
    if events & FdEvents::POLLRDHUP {
        signals |= ZxioSignals::READ_DISABLED | ZxioSignals::PEER_CLOSED;
    }
    return signals.bits();
}

fn get_events_from_zxio_signals(signals: zxio::zxio_signals_t) -> FdEvents {
    let zxio_signals = ZxioSignals::from_bits_truncate(signals);

    let mut events = FdEvents::empty();

    if zxio_signals
        .intersects(ZxioSignals::READABLE | ZxioSignals::PEER_CLOSED | ZxioSignals::READ_DISABLED)
    {
        events |= FdEvents::POLLIN;
    }
    if zxio_signals.intersects(ZxioSignals::WRITABLE | ZxioSignals::WRITE_DISABLED) {
        events |= FdEvents::POLLOUT;
    }
    if zxio_signals.intersects(ZxioSignals::READ_DISABLED | ZxioSignals::PEER_CLOSED) {
        events |= FdEvents::POLLRDHUP;
    }

    events
}

impl FsNodeOps for RemoteNode {
    fn open(&self, node: &FsNode, _flags: OpenFlags) -> Result<Box<dyn FileOps>, Errno> {
        let zxio = (&*self.zxio).clone().map_err(|status| from_status_like_fdio!(status))?;
        if node.is_dir() {
            return Ok(Box::new(RemoteDirectoryObject::new(zxio)));
        }

        Ok(Box::new(RemoteFileObject::new(zxio)))
    }

    fn lookup(&self, node: &FsNode, name: &FsStr) -> Result<FsNodeHandle, Errno> {
        let name = std::str::from_utf8(name).map_err(|_| {
            warn!("bad utf8 in pathname! remote filesystems can't handle this");
            EINVAL
        })?;
        let zxio = Arc::new(
            self.zxio
                .open(self.rights, 0, name)
                .map_err(|status| from_status_like_fdio!(status))?,
        );

        // TODO: It's unfortunate to have another round-trip. We should be able
        // to set the mode based on the information we get during open.
        let attrs = zxio.attr_get().map_err(|status| from_status_like_fdio!(status))?;

        let ops = Box::new(RemoteNode { zxio, rights: self.rights });
        let mode =
            FileMode::from_bits(unsafe { zxio_get_posix_mode(attrs.protocols, attrs.abilities) });

        let child = node.fs().create_node_with_id(ops, mode, attrs.id);

        update_into_from_attrs(&mut child.info_write(), attrs);
        Ok(child)
    }

    fn truncate(&self, _node: &FsNode, length: u64) -> Result<(), Errno> {
        self.zxio.truncate(length).map_err(|status| from_status_like_fdio!(status))
    }

    fn update_info<'a>(&self, node: &'a FsNode) -> Result<RwLockReadGuard<'a, FsNodeInfo>, Errno> {
        let attrs = self.zxio.attr_get().map_err(|status| from_status_like_fdio!(status))?;
        let mut info = node.info_write();
        update_into_from_attrs(&mut info, attrs);
        Ok(RwLockWriteGuard::downgrade(info))
    }
}

fn zxio_read(zxio: &Zxio, current_task: &CurrentTask, data: &[UserBuffer]) -> Result<usize, Errno> {
    let total = UserBuffer::get_total_length(data)?;
    let mut bytes = vec![0u8; total];
    let actual = zxio.read(&mut bytes).map_err(|status| from_status_like_fdio!(status))?;
    current_task.mm.write_all(data, &bytes[0..actual])?;
    Ok(actual)
}

fn zxio_read_at(
    zxio: &Zxio,
    current_task: &CurrentTask,
    offset: usize,
    data: &[UserBuffer],
) -> Result<usize, Errno> {
    let total = UserBuffer::get_total_length(data)?;
    let mut bytes = vec![0u8; total];
    let actual =
        zxio.read_at(offset as u64, &mut bytes).map_err(|status| from_status_like_fdio!(status))?;
    current_task.mm.write_all(data, &bytes[0..actual])?;
    Ok(actual)
}

fn zxio_write(
    zxio: &Zxio,
    current_task: &CurrentTask,
    data: &[UserBuffer],
) -> Result<usize, Errno> {
    let total = UserBuffer::get_total_length(data)?;
    let mut bytes = vec![0u8; total];
    current_task.mm.read_all(data, &mut bytes)?;
    let actual = zxio.write(&bytes).map_err(|status| from_status_like_fdio!(status))?;
    Ok(actual)
}

fn zxio_write_at(
    zxio: &Zxio,
    current_task: &CurrentTask,
    offset: usize,
    data: &[UserBuffer],
) -> Result<usize, Errno> {
    let total = UserBuffer::get_total_length(data)?;
    let mut bytes = vec![0u8; total];
    current_task.mm.read_all(data, &mut bytes)?;
    let actual =
        zxio.write_at(offset as u64, &bytes).map_err(|status| from_status_like_fdio!(status))?;
    Ok(actual)
}

fn zxio_wait_async(
    zxio: &Arc<Zxio>,
    waiter: &Arc<Waiter>,
    events: FdEvents,
    handler: EventHandler,
) {
    let zxio_clone = zxio.clone();
    let signal_handler = move |signals: zx::Signals| {
        let observed_zxio_signals = zxio_clone.wait_end(signals);
        let observed_events = get_events_from_zxio_signals(observed_zxio_signals);
        handler(observed_events);
    };

    let (handle, signals) = zxio.wait_begin(get_zxio_signals_from_events(events));

    // unwrap OK here as errors are only generated from misuse
    waiter.wake_on_signals(&handle, signals, Box::new(signal_handler)).unwrap();
}

fn zxio_query_events(zxio: &Arc<Zxio>) -> FdEvents {
    let signals = get_zxio_signals_from_events(FdEvents::POLLIN | FdEvents::POLLOUT);
    let (handle, signals) = zxio.wait_begin(signals);
    let observed_signals = handle.wait(signals, zx::Time::INFINITE_PAST).unwrap();
    let observed_zxio_signals = zxio.wait_end(observed_signals);
    get_events_from_zxio_signals(observed_zxio_signals)
}

/// Helper struct to track the context necessary to iterate over dir entries.
#[derive(Default)]
struct RemoteDirectoryIterator {
    iterator: Option<DirentIterator>,

    /// If the last attempt to write to the sink failed, this contains the entry
    /// that is pending to be added.
    pending_entry: Option<ZxioDirent>,
}

impl RemoteDirectoryIterator {
    fn get_or_init_iterator(&mut self, zxio: &Zxio) -> Result<&mut DirentIterator, Errno> {
        if self.iterator.is_none() {
            let iterator =
                zxio.create_dirent_iterator().map_err(|status| from_status_like_fdio!(status))?;
            self.iterator = Some(iterator);
        }
        if let Some(iterator) = &mut self.iterator {
            return Ok(iterator);
        }

        // Should be an impossible error, because we just created the iterator above.
        error!(EIO)
    }

    /// Returns the next dir entry. If no more entries are found, returns None.
    /// Returns an error if the iterator fails for other reasons described by
    /// the zxio library.
    pub fn next(&mut self, zxio: &Zxio) -> Option<Result<ZxioDirent, Errno>> {
        match self.pending_entry.take() {
            Some(entry) => Some(Ok(entry)),
            None => {
                let iterator = match self.get_or_init_iterator(zxio) {
                    Ok(iter) => iter,
                    Err(e) => return Some(Err(e)),
                };
                let result = iterator.next();
                match result {
                    Some(Ok(v)) => return Some(Ok(v)),
                    Some(Err(status)) => return Some(Err(from_status_like_fdio!(status))),
                    None => return None,
                }
            }
        }
    }
}

struct RemoteDirectoryObject {
    /// The underlying Zircon I/O object.
    zxio: Zxio,

    iterator: Mutex<RemoteDirectoryIterator>,
}

impl RemoteDirectoryObject {
    pub fn new(zxio: Zxio) -> RemoteDirectoryObject {
        RemoteDirectoryObject {
            zxio: zxio,
            iterator: Mutex::new(RemoteDirectoryIterator::default()),
        }
    }
}

impl FileOps for RemoteDirectoryObject {
    fd_impl_directory!();
    fd_impl_nonblocking!();

    fn seek(
        &self,
        file: &FileObject,
        _current_task: &CurrentTask,
        offset: off_t,
        whence: SeekOrigin,
    ) -> Result<off_t, Errno> {
        let mut current_offset = file.offset.lock();
        let mut iterator = self.iterator.lock();
        let new_offset = match whence {
            SeekOrigin::SET => Some(offset),
            SeekOrigin::CUR => (*current_offset).checked_add(offset),
            SeekOrigin::END => None,
        }
        .ok_or(errno!(EINVAL))?;

        if new_offset < 0 {
            return error!(EINVAL);
        }

        let mut iterator_position = *current_offset;

        if new_offset < iterator_position {
            // Our iterator only goes forward, so reset it here.
            *iterator = RemoteDirectoryIterator::default();
            iterator_position = 0;
        }

        if iterator_position != new_offset {
            iterator.pending_entry = None;
        }

        // Advance the iterator to catch up with the offset.
        for i in iterator_position..new_offset {
            match iterator.next(&self.zxio) {
                Some(Ok(_)) => continue,
                None => break, // No more entries.
                Some(Err(_)) => {
                    // In order to keep the offset and the iterator in sync, set the new offset
                    // to be as far as we could get.
                    // Note that failing the seek here would also cause the iterator and the
                    // offset to not be in sync, because the iterator has already moved from
                    // where it was.
                    *current_offset = i;
                    return Ok(*current_offset);
                }
            }
        }

        *current_offset = new_offset;

        Ok(*current_offset)
    }

    fn readdir(
        &self,
        file: &FileObject,
        _current_task: &CurrentTask,
        sink: &mut dyn DirentSink,
    ) -> Result<(), Errno> {
        // It is important to acquire the lock to the offset before the context,
        //  to avoid a deadlock where seek() tries to modify the context.
        let mut offset = file.offset.lock();
        let mut iterator = self.iterator.lock();

        let mut add_entry = |entry: &ZxioDirent| {
            let inode_num: ino_t = entry.id.ok_or(errno!(EIO))?;
            let entry_type = DirectoryEntryType::UNKNOWN;
            let new_offset = *offset + 1;
            sink.add(inode_num, new_offset, entry_type, &entry.name)?;
            *offset = new_offset;
            Ok(())
        };

        while let Some(entry) = iterator.next(&self.zxio) {
            if entry.is_ok() {
                if let Err(e) = add_entry(&entry.as_ref().unwrap()) {
                    iterator.pending_entry = Some(entry.unwrap());
                    return Err(e);
                }
            }
        }
        Ok(())
    }
}

struct RemoteFileObject {
    /// The underlying Zircon I/O object.
    zxio: Arc<Zxio>,
}

impl RemoteFileObject {
    pub fn new(zxio: Zxio) -> RemoteFileObject {
        RemoteFileObject { zxio: Arc::new(zxio) }
    }
}

impl FileOps for RemoteFileObject {
    fd_impl_seekable!();

    fn read_at(
        &self,
        _file: &FileObject,
        current_task: &CurrentTask,
        offset: usize,
        data: &[UserBuffer],
    ) -> Result<usize, Errno> {
        zxio_read_at(&self.zxio, current_task, offset, data)
    }

    fn write_at(
        &self,
        _file: &FileObject,
        current_task: &CurrentTask,
        offset: usize,
        data: &[UserBuffer],
    ) -> Result<usize, Errno> {
        zxio_write_at(&self.zxio, current_task, offset, data)
    }

    fn get_vmo(
        &self,
        _file: &FileObject,
        _current_task: &CurrentTask,
        mut prot: zx::VmarFlags,
    ) -> Result<zx::Vmo, Errno> {
        let has_execute = prot.contains(zx::VmarFlags::PERM_EXECUTE);
        prot -= zx::VmarFlags::PERM_EXECUTE;
        let (mut vmo, _size) =
            self.zxio.vmo_get(prot).map_err(|status| from_status_like_fdio!(status))?;
        if has_execute {
            vmo = vmo.replace_as_executable(&VMEX_RESOURCE).map_err(impossible_error)?;
        }
        Ok(vmo)
    }

    fn wait_async(
        &self,
        _file: &FileObject,
        _current_task: &CurrentTask,
        waiter: &Arc<Waiter>,
        events: FdEvents,
        handler: EventHandler,
    ) {
        zxio_wait_async(&self.zxio, waiter, events, handler)
    }

    fn query_events(&self, _current_task: &CurrentTask) -> FdEvents {
        zxio_query_events(&self.zxio)
    }
}

struct TtyConfiguration {
    icrnl: bool,
    echo: bool,
}

impl TtyConfiguration {
    fn set_from_termios(&mut self, data: &termios) {
        self.icrnl = (data.c_iflag & ICRNL) != 0;
        self.echo = (data.c_lflag & ECHO) != 0;
    }

    fn to_termios(&self) -> termios {
        let mut c_iflag = 0;
        if self.icrnl {
            c_iflag |= ICRNL;
        }

        let mut c_lflag = 0;
        if self.echo {
            c_lflag |= ECHO;
        }

        termios { c_iflag, c_lflag, ..termios::default() }
    }
}

impl Default for TtyConfiguration {
    fn default() -> Self {
        Self { icrnl: true, echo: true }
    }
}

struct RemotePipeObject {
    /// The underlying Zircon I/O object.
    zxio: Arc<syncio::Zxio>,

    /// Only present if zxio is a TTY
    tty_config: Option<Mutex<TtyConfiguration>>,
}

impl RemotePipeObject {
    fn new(zxio: Zxio) -> Result<RemotePipeObject, Errno> {
        let tty_config = if zxio.isatty().map_err(|status| from_status_like_fdio!(status))? {
            Some(Mutex::new(TtyConfiguration::default()))
        } else {
            None
        };
        Ok(RemotePipeObject { zxio: Arc::new(zxio), tty_config })
    }
}

impl FileOps for RemotePipeObject {
    fd_impl_nonseekable!();

    fn read(
        &self,
        _file: &FileObject,
        current_task: &CurrentTask,
        data: &[UserBuffer],
    ) -> Result<usize, Errno> {
        if let Some(tty_config) = self.tty_config.as_ref().map(|m| m.lock()) {
            let mut bytes = vec![0u8; UserBuffer::get_total_length(data)?];
            let actual =
                self.zxio.read(&mut bytes).map_err(|status| from_status_like_fdio!(status))?;
            bytes.truncate(actual);

            if tty_config.icrnl {
                for c in &mut bytes {
                    if *c == b'\r' {
                        *c = b'\n';
                    }
                }
            }

            if tty_config.echo {
                if self.zxio.write(&bytes) != Ok(actual) {
                    warn!("Failed to echo one or more characters on a tty with the ECHO flag");
                }
            }

            current_task.mm.write_all(data, &bytes)?;
            Ok(actual)
        } else {
            zxio_read(&self.zxio, current_task, data)
        }
    }

    fn write(
        &self,
        _file: &FileObject,
        current_task: &CurrentTask,
        data: &[UserBuffer],
    ) -> Result<usize, Errno> {
        zxio_write(&self.zxio, current_task, data)
    }

    fn wait_async(
        &self,
        _file: &FileObject,
        _current_task: &CurrentTask,
        waiter: &Arc<Waiter>,
        events: FdEvents,
        handler: EventHandler,
    ) {
        zxio_wait_async(&self.zxio, waiter, events, handler)
    }

    fn query_events(&self, _current_task: &CurrentTask) -> FdEvents {
        zxio_query_events(&self.zxio)
    }

    fn ioctl(
        &self,
        _file: &FileObject,
        current_task: &CurrentTask,
        request: u32,
        in_addr: UserAddress,
        _out_addr: UserAddress,
    ) -> Result<SyscallResult, Errno> {
        match request {
            TCGETS => {
                if let Some(tty_config) = self.tty_config.as_ref().map(|m| m.lock()) {
                    let response = tty_config.to_termios();
                    current_task.mm.write_object(UserRef::new(in_addr), &response)?;
                    Ok(SyscallResult::Success(0))
                } else {
                    error!(ENOTTY)
                }
            }
            TCSETS | TCSETSF | TCSETSW => {
                if let Some(ref mut tty_config) = self.tty_config.as_ref().map(|m| m.lock()) {
                    let mut command = termios::default();
                    current_task.mm.read_object(UserRef::new(in_addr), &mut command)?;
                    tty_config.set_from_termios(&command);
                    Ok(SyscallResult::Success(0))
                } else {
                    error!(ENOTTY)
                }
            }
            _ => default_ioctl(request),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use fidl::endpoints::Proxy;
    use fidl_fuchsia_io as fio;
    use fuchsia_async as fasync;

    use crate::errno;
    use crate::mm::PAGE_SIZE;
    use crate::testing::*;

    #[::fuchsia::test]
    async fn test_tree() -> Result<(), anyhow::Error> {
        let (kernel, current_task) = create_kernel_and_task();
        let rights = fio::OPEN_RIGHT_READABLE | fio::OPEN_RIGHT_EXECUTABLE;
        let root = io_util::directory::open_in_namespace("/pkg", rights)?;
        let fs = RemoteFs::new(root.into_channel().unwrap().into_zx_channel(), rights)?;
        let ns = Namespace::new(fs.clone());
        let root = ns.root();
        let mut context = LookupContext::default();
        assert_eq!(
            root.lookup_child(&current_task, &mut context, b"nib").err(),
            Some(errno!(ENOENT))
        );
        let mut context = LookupContext::default();
        root.lookup_child(&current_task, &mut context, b"lib").unwrap();

        let mut context = LookupContext::default();
        let _test_file = root
            .lookup_child(&current_task, &mut context, b"bin/hello_starnix")?
            .open(&*kernel, OpenFlags::RDONLY)?;
        Ok(())
    }

    #[fasync::run_singlethreaded(test)]
    async fn test_blocking_io() -> Result<(), anyhow::Error> {
        let (kernel, current_task) = create_kernel_and_task();

        let address = map_memory(&current_task, UserAddress::default(), *PAGE_SIZE);
        let (client, server) = zx::Socket::create(zx::SocketOpts::empty())?;
        let pipe = create_fuchsia_pipe(&kernel, client.into_handle())?;

        let thread = std::thread::spawn(move || {
            assert_eq!(
                64,
                pipe.read(&current_task, &[UserBuffer { address, length: 64 }]).unwrap()
            );
        });

        // Wait for the thread to become blocked on the read.
        zx::Duration::from_seconds(2).sleep();

        let bytes = [0u8; 64];
        assert_eq!(64, server.write(&bytes)?);

        // The thread should unblock and join us here.
        let _ = thread.join();

        Ok(())
    }
}
