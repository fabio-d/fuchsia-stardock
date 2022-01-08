// Copyright 2021 Fabio D'Urso. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Error;
use fidl_fuchsia_stardock as fstardock;
use fuchsia_async as fasync;
use fuchsia_zircon::{self as zx, HandleBased};
use futures::AsyncReadExt;
use std::io::{Read, Write};
use std::pin::Pin;

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

/// Run container with stdio redirection
pub async fn run_container_with_stdio(
    container: &fstardock::ContainerProxy,
) -> Result<(), Error> {
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
