// Copyright 2020 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{
    convert::TryInto as _, io, mem, num::TryFromIntError, os::unix::io::AsRawFd as _,
    time::Duration,
};

pub trait TcpStreamExt {
    /// Sets TCP_USER_TIMEOUT. Fuchsia supports `1..=i32::max_value()`
    /// milliseconds.
    fn set_user_timeout(&self, timeout: Duration) -> io::Result<()>;

    /// Gets TCP_USER_TIMEOUT.
    fn user_timeout(&self) -> Result<Duration, Error>;
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("netstack returned an error: {0}")]
    Netstack(io::Error),
    #[error("netstack returned a negative duration: {0}")]
    NegativeDuration(i32),
}

impl TcpStreamExt for std::net::TcpStream {
    fn set_user_timeout(&self, timeout: Duration) -> io::Result<()> {
        set_tcp_option(
            self,
            libc::TCP_USER_TIMEOUT,
            timeout.as_millis().try_into().map_err(|TryFromIntError { .. }| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "user timeout duration milliseconds does not fit in an i32",
                )
            })?,
        )
    }

    fn user_timeout(&self) -> Result<Duration, Error> {
        get_tcp_option(self, libc::TCP_USER_TIMEOUT).map_err(Error::Netstack).and_then(|timeout| {
            Ok(Duration::from_millis(
                timeout
                    .try_into()
                    .map_err(|TryFromIntError { .. }| Error::NegativeDuration(timeout))?,
            ))
        })
    }
}

fn set_option(
    stream: &std::net::TcpStream,
    option_level: libc::c_int,
    option_name: libc::c_int,
    option_value: i32,
) -> io::Result<()> {
    let fd = stream.as_raw_fd();
    // Safe because `setsockopt` does not retain memory passed to it.
    if unsafe {
        libc::setsockopt(
            fd,
            option_level,
            option_name,
            &option_value as *const _ as *const libc::c_void,
            mem::size_of_val(&option_value) as libc::socklen_t,
        )
    } != 0
    {
        Err(io::Error::last_os_error())?;
    }
    Ok(())
}

fn set_tcp_option(
    stream: &std::net::TcpStream,
    option_name: libc::c_int,
    option_value: i32,
) -> io::Result<()> {
    set_option(stream, libc::IPPROTO_TCP, option_name, option_value)
}

fn get_option(
    stream: &std::net::TcpStream,
    option_level: libc::c_int,
    option_name: libc::c_int,
) -> io::Result<i32> {
    let fd = stream.as_raw_fd();
    let mut option_value = 0i32;
    let mut option_value_size = mem::size_of_val(&option_value) as libc::socklen_t;
    // Safe because `getsockopt` does not retain memory passed to it.
    if unsafe {
        libc::getsockopt(
            fd,
            option_level,
            option_name,
            &mut option_value as *mut _ as *mut libc::c_void,
            &mut option_value_size,
        )
    } != 0
    {
        Err(io::Error::last_os_error())?;
    }
    Ok(option_value)
}

fn get_tcp_option(stream: &std::net::TcpStream, option_name: libc::c_int) -> io::Result<i32> {
    get_option(stream, libc::IPPROTO_TCP, option_name)
}

#[cfg(test)]
mod test {
    use {super::*, proptest::prelude::*};

    fn stream() -> std::io::Result<std::net::TcpStream> {
        use socket2::{Domain, Socket, Type};

        let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
        Ok(socket.into())
    }

    proptest! {
        #[test]
        fn user_timeout_roundtrip
            (timeout in 0..=i32::max_value() as u64)
        {
            let stream = stream().expect("failed to create stream");
            let timeout = Duration::from_millis(timeout);

            let () = stream.set_user_timeout(timeout).expect("failed to set user timeout");
            prop_assert_eq!(stream.user_timeout().expect("failed to get user timeout"), timeout);
        }
    }
}
