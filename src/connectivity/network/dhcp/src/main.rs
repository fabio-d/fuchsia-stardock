// Copyright 2018 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(warnings)]

use {
    dhcp::{
        configuration,
        protocol::{Message, SERVER_PORT},
        server::{Server, ServerAction, ServerDispatcher, DEFAULT_STASH_ID, DEFAULT_STASH_PREFIX},
    },
    failure::{Error, Fail, ResultExt},
    fuchsia_async::{self as fasync, net::UdpSocket, Interval},
    fuchsia_component::server::ServiceFs,
    fuchsia_syslog::{self as fx_syslog, fx_log_err, fx_log_info},
    fuchsia_zircon::{self as zx, DurationNum, Status},
    futures::{Future, StreamExt, TryFutureExt, TryStreamExt},
    getopts::Options,
    std::{
        cell::RefCell,
        env,
        net::{IpAddr, SocketAddr},
    },
    void::Void,
};

/// A buffer size in excess of the maximum allowable DHCP message size.
const BUF_SZ: usize = 1024;
const DEFAULT_CONFIG_PATH: &str = "/pkg/data/config.json";
/// The rate in seconds at which expiration DHCP leases are recycled back into the managed address
/// pool. The current value of 5 is meant to facilitate manual testing.
// TODO(atait): Replace with Duration type after it has been updated to const fn.
const EXPIRATION_INTERVAL_SECS: i64 = 5;

enum IncomingService {
    Server(fidl_fuchsia_net_dhcp::Server_RequestStream),
}

#[fasync::run_singlethreaded]
async fn main() -> Result<(), Error> {
    fx_syslog::init_with_tags(&["dhcpd"])?;

    let path = get_server_config_file_path()?;
    let config = configuration::load_server_config_from_file(path)?;
    let server_ip = config.server_ip;
    let socket_addr = SocketAddr::new(IpAddr::V4(server_ip), SERVER_PORT);
    let udp_socket = UdpSocket::bind(&socket_addr).context("unable to bind socket")?;
    udp_socket.set_broadcast(true).context("unable to set broadcast")?;
    let server = Server::from_config(
        config,
        || zx::Time::get(zx::ClockId::UTC).into_nanos() / 1_000_000_000,
        DEFAULT_STASH_ID,
        DEFAULT_STASH_PREFIX,
    )
    .await
    .context("failed to create server")?;
    let server = RefCell::new(server);
    let msg_handling_loop = define_msg_handling_loop_future(udp_socket, &server);
    let lease_expiration_handler = define_lease_expiration_handler_future(&server);

    let mut fs = ServiceFs::new_local();
    fs.dir("svc").add_fidl_service(IncomingService::Server);
    fs.take_and_serve_directory_handle()?;
    let server_dispatcher = RefCell::new(CannedDispatcher {});
    let admin_fut = fs
        .then(|incoming_service| {
            async {
                match incoming_service {
                    IncomingService::Server(stream) => {
                        run_server(stream, &server_dispatcher)
                            .inspect_err(|e| log::info!("{:?}", e))
                            .await?;
                        Ok(())
                    }
                }
            }
        })
        .try_for_each_concurrent(None, |()| futures::future::ok(()));

    fx_log_info!("starting server");
    let (_void, (), ()) =
        futures::try_join!(msg_handling_loop, admin_fut, lease_expiration_handler)?;
    Ok(())
}

fn get_server_config_file_path() -> Result<String, Error> {
    let args: Vec<String> = env::args().collect();
    let program = &args[0];
    let mut opts = Options::new();
    opts.optopt("c", "config", "dhcpd configuration file path", "FILE");
    let matches = match opts.parse(args[1..].iter()) {
        Ok(m) => m,
        Err(e) => {
            opts.short_usage(program);
            return Err(e.context("failed to parse options").into());
        }
    };
    match matches.opt_str("c") {
        Some(p) => Ok(p),
        None => Ok(DEFAULT_CONFIG_PATH.to_string()),
    }
}

async fn define_msg_handling_loop_future<F: Fn() -> i64>(
    sock: UdpSocket,
    server: &RefCell<Server<F>>,
) -> Result<Void, Error> {
    let mut buf = vec![0u8; BUF_SZ];
    loop {
        let (received, mut sender) =
            sock.recv_from(&mut buf).await.context("failed to read from socket")?;
        fx_log_info!("received message from: {}", sender);
        let msg = Message::from_buffer(&buf[..received]).ok_or_else(|| {
            failure::format_err!("unable to parse buffer {:#x?}", &buf[..received])
        })?;
        fx_log_info!("parsed message: {:?}", msg);

        // This call should not block because the server is single-threaded.
        let result = server.borrow_mut().dispatch(msg);
        match result {
            Err(e) => fx_log_err!("error processing client message: {}", e),
            Ok(ServerAction::AddressRelease(addr)) => fx_log_info!("released address: {}", addr),
            Ok(ServerAction::AddressDecline(addr)) => fx_log_info!("allocated address: {}", addr),
            Ok(ServerAction::SendResponse(message, dest)) => {
                fx_log_info!("generated response: {:?}", message);

                // Check if server returned an explicit destination ip.
                if let Some(addr) = dest {
                    sender.set_ip(IpAddr::V4(addr));
                }

                let response_buffer = message.serialize();

                sock.send_to(&response_buffer, sender).await.context("unable to send response")?;
                fx_log_info!("response sent to: {}", sender);
            }
        }
    }
}

fn define_lease_expiration_handler_future<'a, F: Fn() -> i64>(
    server: &'a RefCell<Server<F>>,
) -> impl Future<Output = Result<(), Error>> + 'a {
    let expiration_interval = Interval::new(EXPIRATION_INTERVAL_SECS.seconds());
    expiration_interval
        .map(move |()| server.borrow_mut().release_expired_leases())
        .map(|_| Ok(()))
        .try_collect::<()>()
}

// CannedDispatcher will be moved to the tests module once Server implements ServerDispatcher. In
// the meantime, this struct provides a fake implementation of ServerDispatcher.
struct CannedDispatcher {}

impl ServerDispatcher for CannedDispatcher {
    fn dispatch_get_option(
        &self,
        _code: fidl_fuchsia_net_dhcp::OptionCode,
    ) -> Result<fidl_fuchsia_net_dhcp::Option_, Status> {
        Ok(fidl_fuchsia_net_dhcp::Option_::SubnetMask(fidl_fuchsia_net::Ipv4Address {
            addr: [0, 0, 0, 0],
        }))
    }
    fn dispatch_get_parameter(
        &self,
        _name: fidl_fuchsia_net_dhcp::ParameterName,
    ) -> Result<fidl_fuchsia_net_dhcp::Parameter, Status> {
        Ok(fidl_fuchsia_net_dhcp::Parameter::Lease(fidl_fuchsia_net_dhcp::LeaseLength {
            default: None,
            max: None,
        }))
    }
    fn dispatch_set_option(&self, _value: fidl_fuchsia_net_dhcp::Option_) -> Result<(), Status> {
        Ok(())
    }
    fn dispatch_set_parameter(
        &self,
        _value: fidl_fuchsia_net_dhcp::Parameter,
    ) -> Result<(), Status> {
        Ok(())
    }
    fn dispatch_list_options(&self) -> Result<Vec<fidl_fuchsia_net_dhcp::Option_>, Status> {
        Ok(vec![])
    }
    fn dispatch_list_parameters(&self) -> Result<Vec<fidl_fuchsia_net_dhcp::Parameter>, Status> {
        Ok(vec![])
    }
}

async fn run_server<S: ServerDispatcher>(
    stream: fidl_fuchsia_net_dhcp::Server_RequestStream,
    server: &RefCell<S>,
) -> Result<(), fidl::Error> {
    stream
        .try_for_each(|request| {
            async {
                match request {
                    fidl_fuchsia_net_dhcp::Server_Request::GetOption { code: c, responder: r } => r
                        .send(
                            &mut server.borrow().dispatch_get_option(c).map_err(|e| e.into_raw()),
                        ),
                    fidl_fuchsia_net_dhcp::Server_Request::GetParameter {
                        name: n,
                        responder: r,
                    } => r.send(
                        &mut server.borrow().dispatch_get_parameter(n).map_err(|e| e.into_raw()),
                    ),
                    fidl_fuchsia_net_dhcp::Server_Request::SetOption { value: v, responder: r } => {
                        r.send(
                            &mut server.borrow().dispatch_set_option(v).map_err(|e| e.into_raw()),
                        )
                    }
                    fidl_fuchsia_net_dhcp::Server_Request::SetParameter {
                        value: v,
                        responder: r,
                    } => r.send(
                        &mut server.borrow().dispatch_set_parameter(v).map_err(|e| e.into_raw()),
                    ),
                    fidl_fuchsia_net_dhcp::Server_Request::ListOptions { responder: r } => r.send(
                        &mut server.borrow().dispatch_list_options().map_err(|e| e.into_raw()),
                    ),
                    fidl_fuchsia_net_dhcp::Server_Request::ListParameters { responder: r } => r
                        .send(
                            &mut server
                                .borrow()
                                .dispatch_list_parameters()
                                .map_err(|e| e.into_raw()),
                        ),
                }
            }
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[fasync::run_singlethreaded(test)]
    async fn get_option_with_subnet_mask_returns_subnet_mask() -> Result<(), Error> {
        let (proxy, stream) =
            fidl::endpoints::create_proxy_and_stream::<fidl_fuchsia_net_dhcp::Server_Marker>()?;
        let server = RefCell::new(CannedDispatcher {});

        let res = proxy.get_option(fidl_fuchsia_net_dhcp::OptionCode::SubnetMask);
        fasync::spawn_local(async move {
            let () = run_server(stream, &server).await.unwrap_or(());
        });
        let res = res.await?;

        let expected_result =
            Ok(fidl_fuchsia_net_dhcp::Option_::SubnetMask(fidl_fuchsia_net::Ipv4Address {
                addr: [0, 0, 0, 0],
            }));
        assert_eq!(res, expected_result);
        Ok(())
    }

    #[fasync::run_until_stalled(test)]
    async fn get_parameter_with_lease_length_returns_lease_length() -> Result<(), Error> {
        let (proxy, stream) =
            fidl::endpoints::create_proxy_and_stream::<fidl_fuchsia_net_dhcp::Server_Marker>()?;
        let server = RefCell::new(CannedDispatcher {});

        let res = proxy.get_parameter(fidl_fuchsia_net_dhcp::ParameterName::LeaseLength);
        fasync::spawn_local(async move {
            let () = run_server(stream, &server).await.unwrap_or(());
        });
        let res = res.await?;

        let expected_result =
            Ok(fidl_fuchsia_net_dhcp::Parameter::Lease(fidl_fuchsia_net_dhcp::LeaseLength {
                default: None,
                max: None,
            }));
        assert_eq!(res, expected_result);
        Ok(())
    }

    #[fasync::run_singlethreaded(test)]
    async fn set_option_with_subnet_mask_returns_unit() -> Result<(), Error> {
        let (proxy, stream) =
            fidl::endpoints::create_proxy_and_stream::<fidl_fuchsia_net_dhcp::Server_Marker>()?;
        let server = RefCell::new(CannedDispatcher {});

        let res = proxy.set_option(&mut fidl_fuchsia_net_dhcp::Option_::SubnetMask(
            fidl_fuchsia_net::Ipv4Address { addr: [0, 0, 0, 0] },
        ));
        fasync::spawn_local(async move {
            let () = run_server(stream, &server).await.unwrap_or(());
        });
        let res = res.await?;

        assert_eq!(res, Ok(()));
        Ok(())
    }

    #[fasync::run_singlethreaded(test)]
    async fn set_parameter_with_lease_length_returns_unit() -> Result<(), Error> {
        let (proxy, stream) =
            fidl::endpoints::create_proxy_and_stream::<fidl_fuchsia_net_dhcp::Server_Marker>()?;
        let server = RefCell::new(CannedDispatcher {});

        let res = proxy.set_parameter(&mut fidl_fuchsia_net_dhcp::Parameter::Lease(
            fidl_fuchsia_net_dhcp::LeaseLength { default: None, max: None },
        ));
        fasync::spawn_local(async move {
            let () = run_server(stream, &server).await.unwrap_or(());
        });
        let res = res.await?;

        assert_eq!(res, Ok(()));
        Ok(())
    }

    #[fasync::run_singlethreaded(test)]
    async fn list_options_returns_empty_vec() -> Result<(), Error> {
        let (proxy, stream) =
            fidl::endpoints::create_proxy_and_stream::<fidl_fuchsia_net_dhcp::Server_Marker>()?;
        let server = RefCell::new(CannedDispatcher {});

        let res = proxy.list_options();
        fasync::spawn_local(async move {
            let () = run_server(stream, &server).await.unwrap_or(());
        });
        let res = res.await?;

        assert_eq!(res, Ok(vec![]));
        Ok(())
    }

    #[fasync::run_singlethreaded(test)]
    async fn list_parameters_returns_empty_vec() -> Result<(), Error> {
        let (proxy, stream) =
            fidl::endpoints::create_proxy_and_stream::<fidl_fuchsia_net_dhcp::Server_Marker>()?;
        let server = RefCell::new(CannedDispatcher {});

        let res = proxy.list_parameters();
        fasync::spawn_local(async move {
            let () = run_server(stream, &server).await.unwrap_or(());
        });
        let res = res.await?;

        assert_eq!(res, Ok(vec![]));
        Ok(())
    }
}
