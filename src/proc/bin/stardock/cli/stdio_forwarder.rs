// Copyright 2021 Fabio D'Urso. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::{Context as _, Error};
use fidl::endpoints::{create_endpoints, Proxy};
use fidl_fuchsia_hardware_pty as fpty;
use fidl_fuchsia_stardock as fstardock;
use fuchsia_async as fasync;
use fuchsia_component::client::connect_to_protocol;
use fuchsia_zircon::{self as zx, AsHandleRef, HandleBased};
use futures::AsyncReadExt;
use std::io::{Read, Write};
use std::pin::Pin;
use syncio::{zxio, Zxio};

fn clone_fd(fd: i32) -> Result<zx::Handle, Error> {
    let mut handle = zx::sys::ZX_HANDLE_INVALID;
    zx::ok(unsafe { fdio::fdio_sys::fdio_fd_clone(fd, &mut handle as *mut zx::sys::zx_handle_t) })?;
    Ok(unsafe { zx::Handle::from_raw(handle) })
}

async fn make_tty_forwarder(local_tty: Zxio) -> Result<fidl::Channel, Error> {
    // Create a new PTY
    let pty_server =
        connect_to_protocol::<fpty::DeviceMarker>().context("Failed to connect to PTY service")?;
    let (pty_client, chan) = create_endpoints::<fpty::DeviceMarker>()?;
    zx::ok(pty_server.open_client(0, chan).await?)?;

    // Start forwarding to/from the PTY
    let remote_tty = Zxio::create(pty_server.into_channel().unwrap().into_zx_channel().into())?;

    const ERROR: zxio::zxio_signals_t =
        zxio::ZXIO_SIGNAL_READ_DISABLED | zxio::ZXIO_SIGNAL_PEER_CLOSED | zxio::ZXIO_SIGNAL_ERROR;
    const READABLE_OR_ERROR: zxio::zxio_signals_t = zxio::ZXIO_SIGNAL_READABLE | ERROR;

    std::thread::spawn(move || {
        let mut buf = [0; 1];

        loop {
            let (local_wait_handle, local_wait_signals) = local_tty.wait_begin(READABLE_OR_ERROR);
            let (remote_wait_handle, remote_wait_signals) = remote_tty.wait_begin(READABLE_OR_ERROR);
            let mut wait_items = vec![
                zx::WaitItem {
                    handle: local_wait_handle.as_handle_ref(),
                    waitfor: local_wait_signals,
                    pending: zx::Signals::NONE,
                },
                zx::WaitItem {
                    handle: remote_wait_handle.as_handle_ref(),
                    waitfor: remote_wait_signals,
                    pending: zx::Signals::NONE,
                },
            ];

            zx::object_wait_many(&mut wait_items, zx::Time::INFINITE).unwrap();
            let local_events = local_tty.wait_end(wait_items[0].pending);
            let remote_events = remote_tty.wait_end(wait_items[1].pending);

            if (local_events | remote_events) & ERROR != 0 {
                break;
            }

            if local_events & zxio::ZXIO_SIGNAL_READABLE != 0 {
                if local_tty.read(&mut buf).unwrap_or(0) == 0 {
                    break;
                }

                if remote_tty.write(&buf).is_err() {
                    // TODO: we should probably block and retry
                    break;
                }
            }

            if remote_events & zxio::ZXIO_SIGNAL_READABLE != 0 {
                if remote_tty.read(&mut buf).unwrap_or(0) == 0 {
                    break;
                }

                if local_tty.write(&buf).is_err() {
                    // TODO: we should probably block and retry
                    break;
                }
            }
        }
    });

    Ok(pty_client.into_channel())
}

fn make_input_forwarder() -> Result<fidl::Socket, Error> {
    let (r, w) = zx::Socket::create(zx::SocketOpts::empty()).unwrap();
    let mut stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    std::thread::spawn(move || {
        let mut buf = [0; 1];

        while stdin.read(&mut buf).unwrap_or(0) != 0 {
            // Convert CR to LF
            if buf[0] == b'\r' {
                buf[0] = b'\n';
            }

            // Echo
            stdout.write(&buf).unwrap();
            stdout.flush().unwrap();

            if w.write(&buf).is_err() {
                break;
            }
        }
    });

    Ok(r)
}

fn make_output_forwarder(
    mut sink: Box<dyn Write>,
) -> Result<(fidl::Socket, Pin<Box<impl futures::Future>>), Error> {
    let (r, w) = zx::Socket::create(zx::SocketOpts::empty()).unwrap();

    let mut r = fasync::Socket::from_socket(r).unwrap();
    let worker_fut = Box::pin(async move {
        let mut buf = [0; 1];

        while r.read(&mut buf).await.unwrap_or(0) != 0 {
            if sink.write(&buf).is_err() {
                break;
            } else {
                sink.flush().unwrap();
            }
        }
    });

    Ok((w, worker_fut))
}

async fn run_tty(container: &fstardock::ContainerProxy, local_tty: Zxio) -> Result<(), Error> {
    let pty_client = make_tty_forwarder(local_tty).await?;

    let pty_client0 = Zxio::create(pty_client.into_handle())?;
    let pty_client1 = pty_client0.clone()?;
    let pty_client2 = pty_client0.clone()?;
    container.run(pty_client0.release()?, pty_client1.release()?, pty_client2.release()?).await?;

    Ok(())
}

async fn run_notty(container: &fstardock::ContainerProxy) -> Result<(), Error> {
    let stdin_socket = make_input_forwarder().unwrap();
    let (stdout_socket, stdout_fut) = make_output_forwarder(Box::new(std::io::stdout())).unwrap();
    let (stderr_socket, stderr_fut) = make_output_forwarder(Box::new(std::io::stderr())).unwrap();

    let done_fut = container.run(
        stdin_socket.into_handle(),
        stdout_socket.into_handle(),
        stderr_socket.into_handle(),
    );
    let (done_fut, _, _) = futures::join!(done_fut, stdout_fut, stderr_fut);
    done_fut?;

    Ok(())
}

/// Run container with stdio redirection.
///
/// In principle, we could clone this process' own stdio handles and transfer them. However, such an
/// approach would result in the container still being able to read input and write output even
/// after this process (the stardock cli) is killed by CTRL-C.
///
/// Instead, the following implementation creates a new set of sockets (or PTY) for the container
/// and then actively forwards data to/from them. As a bonus, if this process is killed, the
/// application running in the container will see its stdio being closed and (depending on the
/// application) exit itself.
pub async fn run_container_with_stdio(
    container: &fstardock::ContainerProxy,
    forward_tty: bool,
) -> Result<(), Error> {
    if forward_tty {
        let stdin_zxio = Zxio::create(clone_fd(0)?)?;

        if stdin_zxio.isatty()? {
            run_tty(container, stdin_zxio).await
        } else {
            anyhow::bail!("Stdin is not a TTY");
        }
    } else {
        run_notty(container).await
    }
}
