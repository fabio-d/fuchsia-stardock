// Copyright 2021 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::{anyhow, format_err, Context, Error};
use fidl::endpoints::ServerEnd;
use fidl::HandleBased;
use fidl_fuchsia_component as fcomponent;
use fidl_fuchsia_component_decl as fdecl;
use fidl_fuchsia_component_runner::{
    self as fcrunner, ComponentControllerMarker, ComponentStartInfo,
};
use fidl_fuchsia_io as fio;
use fidl_fuchsia_process as fprocess;
use fidl_fuchsia_starnix_developer as fstardev;
use fuchsia_async as fasync;
use fuchsia_component::client as fclient;
use fuchsia_runtime::{HandleInfo, HandleType};
use fuchsia_zircon::{
    self as zx, sys::zx_exception_info_t, sys::zx_thread_state_general_regs_t,
    sys::ZX_EXCEPTION_STATE_HANDLED, sys::ZX_EXCEPTION_STATE_THREAD_EXIT,
    sys::ZX_EXCEPTION_STATE_TRY_NEXT, sys::ZX_EXCP_FATAL_PAGE_FAULT,
    sys::ZX_EXCP_POLICY_CODE_BAD_SYSCALL, sys::ZX_EXCP_POLICY_ERROR, AsHandleRef, Task as zxTask,
};
use futures::TryStreamExt;
use log::{error, info};
use rand::Rng;
use std::convert::TryFrom;
use std::ffi::CString;
use std::mem;
use std::sync::Arc;

use crate::auth::Credentials;
use crate::device::run_features;
use crate::errno;
use crate::fs::ext4::ExtFilesystem;
use crate::fs::fuchsia::{create_file_from_handle, RemoteFs, SyslogFile};
use crate::fs::tarfs::TarFilesystem;
use crate::fs::tmpfs::TmpFs;
use crate::fs::*;
use crate::mm::{PageFaultAccessType, PageFaultViolationType};
use crate::signals::{signal_handling::*, SignalInfo};
use crate::strace;
use crate::syscalls::decls::SyscallDecl;
use crate::syscalls::table::dispatch_syscall;
use crate::syscalls::*;
use crate::task::*;
use crate::types::*;

// TODO: Should we move this code into fuchsia_zircon? It seems like part of a better abstraction
// for exception channels.
fn as_exception_info(buffer: &zx::MessageBuf) -> zx_exception_info_t {
    let mut tmp = [0; mem::size_of::<zx_exception_info_t>()];
    tmp.clone_from_slice(buffer.bytes());
    unsafe { mem::transmute(tmp) }
}

fn read_channel_sync(chan: &zx::Channel, buf: &mut zx::MessageBuf) -> Result<(), zx::Status> {
    let res = chan.read(buf);
    if let Err(zx::Status::SHOULD_WAIT) = res {
        chan.wait_handle(
            zx::Signals::CHANNEL_READABLE | zx::Signals::CHANNEL_PEER_CLOSED,
            zx::Time::INFINITE,
        )?;
        chan.read(buf)
    } else {
        res
    }
}

/// Runs the given task.
///
/// The task is expected to already have been started. This function listens to
/// the exception channel for the process (`exceptions`) and handles each
///  exception by:
///
///   - verifying that the exception represents a `ZX_EXCP_POLICY_CODE_BAD_SYSCALL`
///   - reading the thread's registers
///   - executing the appropriate syscall
///   - setting the thread's registers to their post-syscall values
///   - setting the exception state to `ZX_EXCEPTION_STATE_HANDLED`
///
/// Once this function has completed, the process' exit code (if one is available) can be read from
/// `process_context.exit_code`.
fn run_task(mut current_task: CurrentTask, exceptions: zx::Channel) -> Result<ExitStatus, Error> {
    let mut buffer = zx::MessageBuf::new();
    let exit_status = loop {
        read_channel_sync(&exceptions, &mut buffer)?;

        let info = as_exception_info(&buffer);
        assert!(buffer.n_handles() == 1);
        let exception = zx::Exception::from(buffer.take_handle(0).unwrap());

        let thread = exception.get_thread()?;
        assert!(
            thread.get_koid() == current_task.thread.get_koid(),
            "Exception thread did not match task thread."
        );

        let report = thread.get_exception_report()?;
        match info.type_ {
            ZX_EXCP_POLICY_ERROR => {
                if report.context.synth_code != ZX_EXCP_POLICY_CODE_BAD_SYSCALL {
                    info!("exception synth_code: {}", report.context.synth_code);
                    exception.set_exception_state(&ZX_EXCEPTION_STATE_TRY_NEXT)?;
                    continue;
                }

                let syscall_number = report.context.synth_data as u64;
                current_task.registers = thread.read_state_general_regs()?;

                let regs = &current_task.registers;
                let args = (regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
                strace!(
                    current_task,
                    "{}({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x})",
                    SyscallDecl::from_number(syscall_number).name,
                    args.0,
                    args.1,
                    args.2,
                    args.3,
                    args.4,
                    args.5
                );
                match dispatch_syscall(&mut current_task, syscall_number, args) {
                    Ok(SyscallResult::Exit(error_code)) => {
                        exception.set_exception_state(&ZX_EXCEPTION_STATE_THREAD_EXIT)?;
                        break ExitStatus::Exited(error_code);
                    }
                    Ok(SyscallResult::Success(return_value)) => {
                        strace!(current_task, "-> {:#x}", return_value);
                        current_task.registers.rax = return_value;
                    }
                    Ok(SyscallResult::SigReturn) => {
                        // Do not modify the register state of the thread. The sigreturn syscall has
                        // restored the proper register state for the thread to continue with.
                        strace!(current_task, "-> sigreturn");
                    }
                    Err(errno) => {
                        strace!(current_task, "!-> {}", errno);
                        current_task.registers.rax = (-errno.value()) as u64;
                    }
                }

                if let Some(exit_status) = deliver_signal(&mut current_task, None) {
                    exception.set_exception_state(&ZX_EXCEPTION_STATE_THREAD_EXIT)?;
                    break exit_status;
                }

                thread.write_state_general_regs(current_task.registers)?;
                exception.set_exception_state(&ZX_EXCEPTION_STATE_HANDLED)?;
            }

            ZX_EXCP_FATAL_PAGE_FAULT => {
                const ERRCODE_PROTECTION_VIOLATION: u64 = 1 << 0;
                const ERRCODE_WRITE: u64 = 1 << 1;
                const ERRCODE_INSTRUCTION_FETCH: u64 = 1 << 4;

                let exc_data = unsafe { report.context.arch.x86_64 };
                let fault_addr = UserAddress::from(exc_data.cr2);
                let access_type = if (exc_data.err_code & ERRCODE_INSTRUCTION_FETCH) != 0 {
                    PageFaultAccessType::Execute
                } else if (exc_data.err_code & ERRCODE_WRITE) != 0 {
                    PageFaultAccessType::Write
                } else {
                    PageFaultAccessType::Read
                };
                let violation_type = if (exc_data.err_code & ERRCODE_PROTECTION_VIOLATION) != 0 {
                    PageFaultViolationType::Protection
                } else {
                    PageFaultViolationType::NotPresent
                };

                current_task.registers = thread.read_state_general_regs()?;
                strace!(
                    current_task,
                    "page_fault({:#x}, {:?}, {:?})",
                    fault_addr.ptr(),
                    access_type,
                    violation_type
                );

                match current_task.mm.page_fault(fault_addr, access_type, violation_type) {
                    Ok(()) => {
                        strace!(current_task, " -> handled");
                    }
                    Err(errno) => {
                        strace!(current_task, "!-> {}", errno);

                        let siginfo = SignalInfo::default(SIGSEGV);
                        if let Some(exit_status) = deliver_signal(&mut current_task, Some(siginfo))
                        {
                            exception.set_exception_state(&ZX_EXCEPTION_STATE_THREAD_EXIT)?;
                            break exit_status;
                        }
                    }
                }

                thread.write_state_general_regs(current_task.registers)?;
                exception.set_exception_state(&ZX_EXCEPTION_STATE_HANDLED)?;
            }

            _ => {
                info!("exception type: 0x{:x}", info.type_);
                exception.set_exception_state(&ZX_EXCEPTION_STATE_TRY_NEXT)?;
            }
        }
    };

    strace!(current_task, "-> exit_status {:?}", exit_status);
    return Ok(exit_status);
}

fn start_task(
    current_task: &CurrentTask,
    registers: zx_thread_state_general_regs_t,
) -> Result<zx::Channel, zx::Status> {
    let exceptions = current_task.thread.create_exception_channel()?;
    let suspend_token = current_task.thread.suspend()?;
    if current_task.id == current_task.thread_group.leader {
        current_task.thread_group.process.start(
            &current_task.thread,
            0,
            0,
            zx::Handle::invalid(),
            0,
        )?;
    } else {
        current_task.thread.start(0, 0, 0, 0)?;
    }
    current_task.thread.wait_handle(zx::Signals::THREAD_SUSPENDED, zx::Time::INFINITE)?;
    current_task.thread.write_state_general_regs(registers)?;
    mem::drop(suspend_token);
    Ok(exceptions)
}

pub fn spawn_task<F>(
    current_task: CurrentTask,
    registers: zx_thread_state_general_regs_t,
    task_complete: F,
) where
    F: FnOnce(Result<ExitStatus, Error>) + Send + Sync + 'static,
{
    std::thread::spawn(move || {
        task_complete(|| -> Result<ExitStatus, Error> {
            let exceptions = start_task(&current_task, registers)?;
            run_task(current_task, exceptions)
        }());
    });
}

struct StartupHandles {
    shell_controller: Option<ServerEnd<fstardev::ShellControllerMarker>>,
}

/// Creates a `StartupHandles` from the provided handles.
///
/// The `numbered_handles` of type `HandleType::FileDescriptor` are used to
/// create files, and the handles are required to be of type `zx::Socket`.
///
/// If there is a `numbered_handles` of type `HandleType::User0`, that is
/// interpreted as the server end of the ShellController protocol.
fn parse_numbered_handles(
    numbered_handles: Option<Vec<fprocess::HandleInfo>>,
    files: &Arc<FdTable>,
    kernel: &Kernel,
) -> Result<StartupHandles, Error> {
    let mut shell_controller = None;
    if let Some(numbered_handles) = numbered_handles {
        for numbered_handle in numbered_handles {
            let info = HandleInfo::try_from(numbered_handle.id)?;
            if info.handle_type() == HandleType::FileDescriptor {
                files.insert(
                    FdNumber::from_raw(info.arg().into()),
                    create_file_from_handle(kernel, numbered_handle.handle)?,
                );
            } else if info.handle_type() == HandleType::User0 {
                shell_controller = Some(ServerEnd::<fstardev::ShellControllerMarker>::from(
                    numbered_handle.handle,
                ));
            }
        }
    } else {
        // If no numbered handles are provided default 0, 1, and 2 to a syslog file.
        let stdio = SyslogFile::new(&kernel);
        files.insert(FdNumber::from_raw(0), stdio.clone());
        files.insert(FdNumber::from_raw(1), stdio.clone());
        files.insert(FdNumber::from_raw(2), stdio);
    }
    Ok(StartupHandles { shell_controller })
}

fn create_filesystem_from_spec<'a>(
    kernel: &Arc<Kernel>,
    task: Option<&CurrentTask>,
    pkg: &fio::DirectorySynchronousProxy,
    spec: &'a str,
) -> Result<(&'a [u8], WhatToMount), Error> {
    use WhatToMount::*;
    let mut iter = spec.splitn(3, ':');
    let mount_point =
        iter.next().ok_or_else(|| anyhow!("mount point is missing from {:?}", spec))?;
    let fs_type = iter.next().ok_or_else(|| anyhow!("fs type is missing from {:?}", spec))?;
    let fs_src = iter.next().unwrap_or("");

    // The filesystem types handled in this match are the ones that can only be specified in a
    // manifest file, for whatever reason. Anything else is passed to create_filesystem, which is
    // common code that also handles the mount() system call.
    let fs = match fs_type {
        "bind" => {
            let task = task.ok_or(errno!(ENOENT))?;
            Dir(task.lookup_path_from_root(fs_src.as_bytes())?.entry)
        }
        "remotefs" => {
            let rights = fio::OPEN_RIGHT_READABLE | fio::OPEN_RIGHT_EXECUTABLE;
            let root = syncio::directory_open_directory_async(&pkg, &fs_src, rights)
                .map_err(|e| anyhow!("Failed to open root: {}", e))?;
            Fs(RemoteFs::new(root.into_channel(), rights)?)
        }
        "ext4" => {
            let vmo =
                syncio::directory_open_vmo(&pkg, &fs_src, fio::VMO_FLAG_READ, zx::Time::INFINITE)?;
            Fs(ExtFilesystem::new(vmo)?)
        }
        "tarfs" => {
            let mut tar_files = Vec::new();
            for filename in fs_src.split(':') {
                let (c, s) = fidl::endpoints::create_endpoints::<fio::NodeMarker>().unwrap();
                pkg.open(fio::OPEN_RIGHT_READABLE | fio::OPEN_FLAG_NOT_DIRECTORY, 0, &filename, s)?;
                tar_files.push(syncio::Zxio::create(c.into_handle())?);
            }
            Fs(TarFilesystem::new(tar_files)?)
        }
        _ => create_filesystem(&kernel, fs_src.as_bytes(), fs_type.as_bytes(), b"")?,
    };
    Ok((mount_point.as_bytes(), fs))
}

fn start_component(
    start_info: ComponentStartInfo,
    controller: ServerEnd<ComponentControllerMarker>,
) -> Result<(), Error> {
    info!(
        "start_component: {}\narguments: {:?}\nmanifest: {:?}",
        start_info.resolved_url.clone().unwrap_or("<unknown>".to_string()),
        start_info.numbered_handles,
        start_info.program,
    );

    let mounts =
        runner::get_program_strvec(&start_info, "mounts").map(|a| a.clone()).unwrap_or(vec![]);
    let binary_path = CString::new(
        runner::get_program_string(&start_info, "binary")
            .ok_or_else(|| anyhow!("Missing \"binary\" in manifest"))?,
    )?;
    let args = runner::get_program_strvec(&start_info, "args")
        .map(|args| {
            args.iter().map(|arg| CString::new(arg.clone())).collect::<Result<Vec<CString>, _>>()
        })
        .unwrap_or(Ok(vec![]))?;
    let environ = runner::get_program_strvec(&start_info, "environ")
        .map(|args| {
            args.iter().map(|arg| CString::new(arg.clone())).collect::<Result<Vec<CString>, _>>()
        })
        .unwrap_or(Ok(vec![]))?;
    let user_passwd = runner::get_program_string(&start_info, "user").unwrap_or("fuchsia:x:42:42");
    let credentials = Credentials::from_passwd(user_passwd)?;
    let apex_hack = runner::get_program_strvec(&start_info, "apex_hack").map(|v| v.clone());
    let cmdline = runner::get_program_string(&start_info, "kernel_cmdline").unwrap_or("");
    let features = runner::get_program_strvec(&start_info, "features").map(|f| f.clone());

    info!("start_component environment: {:?}", environ);

    let kernel_name = if let Some(ref url) = start_info.resolved_url {
        if let Ok(url) = fuchsia_url::pkg_url::PkgUrl::parse(&url) {
            let name = url.resource().unwrap_or(url.name().as_ref());
            Some(CString::new(if let Some(i) = name.rfind('/') { &name[i + 1..] } else { name }))
        } else {
            None
        }
    } else {
        None
    };
    let mut kernel = Kernel::new(&kernel_name.unwrap_or_else(|| CString::new("kernel"))?)?;
    kernel.cmdline = cmdline.as_bytes().to_vec();
    *kernel.outgoing_dir.lock() =
        start_info.outgoing_dir.map(|server_end| server_end.into_channel());
    let kernel = Arc::new(kernel);

    let ns = start_info.ns.ok_or_else(|| anyhow!("Missing namespace"))?;

    let pkg = fio::DirectorySynchronousProxy::new(
        ns.into_iter()
            .find(|entry| entry.path == Some("/pkg".to_string()))
            .ok_or_else(|| anyhow!("Missing /pkg entry in namespace"))?
            .directory
            .ok_or_else(|| anyhow!("Missing directory handlee in pkg namespace entry"))?
            .into_channel(),
    );

    // The mounts are appplied in the order listed. Mounting will fail if the designated mount
    // point doesn't exist in a previous mount. The root must be first so other mounts can be
    // applied on top of it.
    let mut mounts_iter = mounts.iter();
    let (root_point, root_fs) = create_filesystem_from_spec(
        &kernel,
        None,
        &pkg,
        mounts_iter.next().ok_or_else(|| anyhow!("Mounts list is empty"))?,
    )?;
    if root_point != b"/" {
        anyhow::bail!("First mount in mounts list is not the root");
    }
    let root_fs = if let WhatToMount::Fs(fs) = root_fs {
        fs
    } else {
        anyhow::bail!("how did a bind mount manage to get created as the root?")
    };

    let fs = FsContext::new(root_fs);

    let current_task =
        Task::create_process_without_parent(&kernel, binary_path.clone(), fs.clone())?;
    *current_task.creds.write() = credentials;
    let startup_handles =
        parse_numbered_handles(start_info.numbered_handles, &current_task.files, &kernel)?;
    let shell_controller = startup_handles.shell_controller;

    for mount_spec in mounts_iter {
        let (mount_point, child_fs) =
            create_filesystem_from_spec(&kernel, Some(&current_task), &pkg, mount_spec)?;
        let mount_point = current_task.lookup_path_from_root(mount_point)?;
        mount_point.mount(child_fs)?;
    }

    // Hack to allow mounting apexes before apexd is working.
    // TODO(tbodt): Remove once apexd works.
    if let Some(apexes) = apex_hack {
        current_task.lookup_path_from_root(b"apex")?.mount(WhatToMount::Fs(TmpFs::new()))?;
        let apex_dir = current_task.lookup_path_from_root(b"apex")?;
        for apex in apexes {
            let apex = apex.as_bytes();
            let apex_subdir = apex_dir.create_node(
                apex,
                FileMode::IFDIR | FileMode::from_bits(0o700),
                DeviceType::NONE,
            )?;
            let apex_source =
                current_task.lookup_path_from_root(&[b"system/apex/", apex].concat())?;
            apex_subdir.mount(WhatToMount::Dir(apex_source.entry))?;
        }
    }

    // Run all the features (e.g., wayland) that were specified in the .cml.
    if let Some(features) = features {
        run_features(&features, &current_task)
            .map_err(|e| anyhow!("Failed to initialize features: {:?}", e))?;
    }

    let mut argv = vec![binary_path];
    argv.extend(args.into_iter());

    let start_info = current_task.exec(&argv[0], &argv, &environ)?;

    spawn_task(current_task, start_info.to_registers(), |result| {
        // TODO(fxb/74803): Using the component controller's epitaph may not be the best way to
        // communicate the exit code. The component manager could interpret certain epitaphs as starnix
        // being unstable, and chose to terminate starnix as a result.
        // Errors when closing the controller with an epitaph are disregarded, since there are
        // legitimate reasons for this to fail (like the client having closed the channel).
        if let Some(shell_controller) = shell_controller {
            let _ = shell_controller.close_with_epitaph(zx::Status::OK);
        }
        let _ = match result {
            Ok(ExitStatus::Exited(0)) => controller.close_with_epitaph(zx::Status::OK),
            _ => controller.close_with_epitaph(zx::Status::from_raw(
                fcomponent::Error::InstanceDied.into_primitive() as i32,
            )),
        };
    });

    Ok(())
}

pub async fn start_runner(
    mut request_stream: fcrunner::ComponentRunnerRequestStream,
) -> Result<(), Error> {
    while let Some(event) = request_stream.try_next().await? {
        match event {
            fcrunner::ComponentRunnerRequest::Start { start_info, controller, .. } => {
                fasync::Task::local(async move {
                    if let Err(e) = start_component(start_info, controller) {
                        error!("failed to start component: {:?}", e);
                    }
                })
                .detach();
            }
        }
    }
    Ok(())
}

async fn start(url: String, args: fcomponent::CreateChildArgs) -> Result<(), Error> {
    // TODO(fxbug.dev/74511): The amount of setup required here is a bit lengthy. Ideally,
    // fuchsia-component would provide native bindings for the Realm API that could reduce this
    // logic to a few lines.

    const COLLECTION: &str = "playground";
    let realm = fclient::realm().context("failed to connect to Realm service")?;
    let mut collection_ref = fdecl::CollectionRef { name: COLLECTION.into() };
    let id: u64 = rand::thread_rng().gen();
    let child_name = format!("starnix-{}", id);
    let child_decl = fdecl::Child {
        name: Some(child_name.clone()),
        url: Some(url),
        startup: Some(fdecl::StartupMode::Lazy),
        environment: None,
        ..fdecl::Child::EMPTY
    };
    let () = realm
        .create_child(&mut collection_ref, child_decl, args)
        .await?
        .map_err(|e| format_err!("failed to create child: {:?}", e))?;
    // The component is run in a `SingleRun` collection instance, and will be automatically
    // deleted when it exits.
    Ok(())
}

/// Creates a `HandleInfo` from the provided socket and file descriptor.
///
/// The file descriptor is encoded as a `PA_HND(PA_FD, <file_descriptor>)` before being stored in
/// the `HandleInfo`.
///
/// Returns an error if `socket` is `None`.
fn handle_info_from_socket(
    socket: Option<fidl::Socket>,
    file_descriptor: u16,
) -> Result<fprocess::HandleInfo, Error> {
    if let Some(socket) = socket {
        let info = HandleInfo::new(HandleType::FileDescriptor, file_descriptor);
        Ok(fprocess::HandleInfo { handle: socket.into_handle(), id: info.as_raw() })
    } else {
        Err(anyhow!("Failed to create HandleInfo for {}", file_descriptor))
    }
}

pub async fn start_manager(
    mut request_stream: fstardev::ManagerRequestStream,
) -> Result<(), Error> {
    while let Some(event) = request_stream.try_next().await? {
        match event {
            fstardev::ManagerRequest::Start { url, responder } => {
                let args = fcomponent::CreateChildArgs {
                    numbered_handles: None,
                    ..fcomponent::CreateChildArgs::EMPTY
                };
                if let Err(e) = start(url, args).await {
                    error!("failed to start component: {}", e);
                }
                responder.send()?;
            }
            fstardev::ManagerRequest::StartShell { params, controller, .. } => {
                let controller_handle_info = fprocess::HandleInfo {
                    handle: controller.into_channel().into_handle(),
                    id: HandleInfo::new(HandleType::User0, 0).as_raw(),
                };
                let numbered_handles = vec![
                    handle_info_from_socket(params.standard_in, 0)?,
                    handle_info_from_socket(params.standard_out, 1)?,
                    handle_info_from_socket(params.standard_err, 2)?,
                    controller_handle_info,
                ];
                let args = fcomponent::CreateChildArgs {
                    numbered_handles: Some(numbered_handles),
                    ..fcomponent::CreateChildArgs::EMPTY
                };
                if let Err(e) = start(
                    "fuchsia-pkg://fuchsia.com/test_android_distro#meta/sh.cm".to_string(),
                    args,
                )
                .await
                {
                    error!("failed to start shell: {}", e);
                }
            }
        }
    }
    Ok(())
}
