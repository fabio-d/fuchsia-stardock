// Copyright 2019 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use {
    crate::host_identifier::HostIdentifier,
    anyhow::{Context as _, Result},
    fidl::endpoints::Proxy as _,
    fidl_fuchsia_developer_remotecontrol as rcs,
    fidl_fuchsia_diagnostics::Selector,
    fidl_fuchsia_io as io,
    fidl_fuchsia_net_ext::SocketAddress as SocketAddressExt,
    fuchsia_async as fasync, fuchsia_zircon as zx,
    futures::future::join,
    futures::prelude::*,
    std::cell::RefCell,
    std::net::SocketAddr,
    std::rc::Rc,
    tracing::*,
};

mod host_identifier;
mod service_discovery;

const HUB_ROOT: &str = "/discovery_root";

pub struct RemoteControlService {
    ids: RefCell<Vec<u64>>,
    id_allocator: fn() -> Result<HostIdentifier>,
}

impl RemoteControlService {
    pub fn new() -> Result<Self> {
        return Ok(Self::new_with_allocator(|| HostIdentifier::new()));
    }

    pub(crate) fn new_with_allocator(id_allocator: fn() -> Result<HostIdentifier>) -> Self {
        return Self { id_allocator, ids: Default::default() };
    }

    pub async fn serve_stream(
        self: Rc<Self>,
        stream: rcs::RemoteControlRequestStream,
    ) -> Result<()> {
        stream
            .map_err(|err| anyhow::Error::new(err).context("RemoteControl stream"))
            .try_for_each_concurrent(None, |request| async {
                match request {
                    rcs::RemoteControlRequest::AddId { id, responder } => {
                        self.ids.borrow_mut().push(id);
                        responder.send()?;
                        Ok(())
                    }
                    rcs::RemoteControlRequest::IdentifyHost { responder } => {
                        self.clone().identify_host(responder).await?;
                        Ok(())
                    }
                    rcs::RemoteControlRequest::Connect { selector, service_chan, responder } => {
                        responder.send(
                            &mut self.clone().connect_to_service(selector, service_chan).await,
                        )?;
                        Ok(())
                    }
                    rcs::RemoteControlRequest::Select { selector, responder } => {
                        responder.send(&mut self.clone().select(selector).await)?;
                        Ok(())
                    }
                    rcs::RemoteControlRequest::OpenHub { server, responder } => {
                        responder.send(
                            &mut io_util::connect_in_namespace(
                                HUB_ROOT,
                                server.into_channel(),
                                io::OPEN_RIGHT_READABLE | io::OPEN_RIGHT_WRITABLE,
                            )
                            .map_err(|i| i.into_raw()),
                        )?;
                        Ok(())
                    }
                    rcs::RemoteControlRequest::ForwardTcp { addr, socket, responder } => {
                        let addr: SocketAddressExt = addr.into();
                        let addr = addr.0;
                        let mut result = match fasync::Socket::from_socket(socket) {
                            Ok(socket) => match self.connect_forwarded_port(addr, socket).await {
                                Ok(()) => Ok(()),
                                Err(e) => {
                                    log::error!("Port forward connection failed: {:?}", e);
                                    Err(rcs::TunnelError::ConnectFailed)
                                }
                            },
                            Err(e) => {
                                log::error!("Could not use socket asynchronously: {:?}", e);
                                Err(rcs::TunnelError::SocketFailed)
                            }
                        };
                        responder.send(&mut result)?;
                        Ok(())
                    }
                    rcs::RemoteControlRequest::ReverseTcp { addr, client, responder } => {
                        let addr: SocketAddressExt = addr.into();
                        let addr = addr.0;
                        let client = match client.into_proxy() {
                            Ok(proxy) => proxy,
                            Err(e) => {
                                log::error!("Could not communicate with callback: {:?}", e);
                                responder.send(&mut Err(rcs::TunnelError::CallbackError))?;
                                return Ok(());
                            }
                        };
                        let mut result = match self.listen_reversed_port(addr, client).await {
                            Ok(()) => Ok(()),
                            Err(e) => {
                                log::error!("Port forward connection failed: {:?}", e);
                                Err(rcs::TunnelError::ConnectFailed)
                            }
                        };
                        responder.send(&mut result)?;
                        Ok(())
                    }
                }
            })
            .await
    }

    async fn listen_reversed_port(
        &self,
        listen_addr: SocketAddr,
        client: rcs::ForwardCallbackProxy,
    ) -> Result<(), std::io::Error> {
        let mut listener = fasync::net::TcpListener::bind(&listen_addr)?.accept_stream();

        fasync::Task::local(async move {
            let mut client_closed = client.on_closed().fuse();

            loop {
                // Listen for a connection, or exit if the client has gone away.
                let (stream, addr) = futures::select! {
                    result = listener.next().fuse() => {
                        match result {
                            Some(Ok(x)) => x,
                            Some(Err(e)) => {
                                log::warn!("Error accepting connection: {:?}", e);
                                continue;
                            }
                            None => {
                                log::warn!("reverse tunnel to {:?} listener socket closed", listen_addr);
                                break;
                            }
                        }
                    }
                    _ = client_closed => {
                        log::info!("reverse tunnel {:?} client has closed", listen_addr);
                        break;
                    }
                };

                log::info!("reverse tunnel connection from {:?} to {:?}", addr, listen_addr);

                let (local, remote) = match zx::Socket::create(zx::SocketOpts::STREAM) {
                    Ok(x) => x,
                    Err(e) => {
                        log::warn!("Error creating socket: {:?}", e);
                        continue;
                    }
                };

                let local = match fasync::Socket::from_socket(local) {
                    Ok(x) => x,
                    Err(e) => {
                        log::warn!("Error converting socket to async: {:?}", e);
                        continue;
                    }
                };

                Self::spawn_tcp_forward_task(stream, local);

                // Send the socket to the client.
                if let Err(e) = client.forward(remote, &mut SocketAddressExt(addr).into()) {
                    // The client has gone away, so stop the task.
                    if let fidl::Error::ClientChannelClosed { .. } = e {
                        log::warn!("tunnel client channel closed while forwarding socket");
                        break;
                    }

                    log::warn!("Could not return forwarded socket to client: {:?}", e);
                }
            }
        })
        .detach();

        Ok(())
    }

    async fn connect_forwarded_port(
        &self,
        addr: SocketAddr,
        socket: fasync::Socket,
    ) -> Result<(), std::io::Error> {
        let tcp_conn = fasync::net::TcpStream::connect(addr)?.await?;
        Self::spawn_tcp_forward_task(tcp_conn, socket);
        Ok(())
    }

    fn spawn_tcp_forward_task(tcp_side: fasync::net::TcpStream, socket: fasync::Socket) {
        let mut socket_closed = fasync::OnSignals::new(&socket, zx::Signals::SOCKET_PEER_CLOSED)
            .extend_lifetime()
            .fuse();

        let (mut conn_read, mut conn_write) = tcp_side.split();
        let (mut socket_read, mut socket_write) = socket.split();

        let write_read = async move {
            // TODO(84188): Use a buffer pool once we have them.
            let mut buf = [0; 4096];
            loop {
                let bytes = socket_read.read(&mut buf).await?;
                if bytes == 0 {
                    break Ok(());
                }
                conn_write.write_all(&mut buf[..bytes]).await?;
                conn_write.flush().await?;
            }
        };

        let read_write = async move {
            // TODO(84188): Use a buffer pool once we have them.
            let mut buf = [0; 4096];
            loop {
                futures::select! {
                    res = conn_read.read(&mut buf).fuse() => {
                        let bytes = res?;
                        if bytes == 0 {
                            break Ok(()) as Result<(), std::io::Error>;
                        }
                        socket_write.write_all(&mut buf[..bytes]).await?;
                        socket_write.flush().await?;
                    }
                    _ = socket_closed => {
                        break Ok(());
                    }
                }
            }
        };
        let forward = join(read_write, write_read);
        fasync::Task::local(async move {
            match forward.await {
                (Err(a), Err(b)) => {
                    log::warn!("Port forward closed with errors:\n  {:?}\n  {:?}", a, b)
                }
                (Err(e), _) | (_, Err(e)) => {
                    log::warn!("Port forward closed with error: {:?}", e)
                }
                (Ok(()), Ok(())) => (),
            }
        })
        .detach();
    }

    async fn connect_with_matcher(
        self: &Rc<Self>,
        selector: &Selector,
        service_chan: zx::Channel,
        matcher_fut: impl Future<Output = Result<Vec<service_discovery::PathEntry>>>,
    ) -> Result<rcs::ServiceMatch, rcs::ConnectError> {
        let paths = matcher_fut.await.map_err(|err| {
            warn!(?selector, %err, "error looking for matching services for selector");
            rcs::ConnectError::ServiceDiscoveryFailed
        })?;
        if paths.is_empty() {
            return Err(rcs::ConnectError::NoMatchingServices);
        } else if paths.len() > 1 {
            // TODO(jwing): we should be able to communicate this to the FE somehow.
            warn!(
                ?paths,
                "Selector must match exactly one service. Provided selector matched all of the following");
            return Err(rcs::ConnectError::MultipleMatchingServices);
        }
        let svc_match = paths.get(0).unwrap();
        let hub_path = svc_match.hub_path.to_str().unwrap();
        info!(hub_path, "attempting to connect");
        io_util::connect_in_namespace(
            hub_path,
            service_chan,
            io::OPEN_RIGHT_READABLE | io::OPEN_RIGHT_WRITABLE,
        )
        .map_err(|err| {
            error!(?selector, %err, "error connecting to selector");
            rcs::ConnectError::ServiceConnectFailed
        })?;

        Ok(svc_match.into())
    }

    pub async fn connect_to_service(
        self: &Rc<Self>,
        selector: Selector,
        service_chan: zx::Channel,
    ) -> Result<rcs::ServiceMatch, rcs::ConnectError> {
        self.connect_with_matcher(
            &selector,
            service_chan,
            service_discovery::get_matching_paths(HUB_ROOT, &selector),
        )
        .await
    }

    async fn select_with_matcher(
        self: &Rc<Self>,
        selector: &Selector,
        matcher_fut: impl Future<Output = Result<Vec<service_discovery::PathEntry>>>,
    ) -> Result<Vec<rcs::ServiceMatch>, rcs::SelectError> {
        let paths = matcher_fut.await.map_err(|err| {
            warn!(?selector, %err, "error looking for matching services for selector");
            rcs::SelectError::ServiceDiscoveryFailed
        })?;

        Ok(paths.iter().map(|p| p.into()).collect::<Vec<rcs::ServiceMatch>>())
    }

    pub async fn select(
        self: &Rc<Self>,
        selector: Selector,
    ) -> Result<Vec<rcs::ServiceMatch>, rcs::SelectError> {
        self.select_with_matcher(
            &selector,
            service_discovery::get_matching_paths(HUB_ROOT, &selector),
        )
        .await
    }

    pub async fn identify_host(
        self: &Rc<Self>,
        responder: rcs::RemoteControlIdentifyHostResponder,
    ) -> Result<()> {
        let identifier = match (self.id_allocator)() {
            Ok(i) => i,
            Err(e) => {
                error!(%e, "Allocating host identifier");
                return responder
                    .send(&mut Err(rcs::IdentifyHostError::ProxyConnectionFailed))
                    .context("responding to client");
            }
        };

        // TODO(raggi): limit size to stay under message size limit.
        let ids = self.ids.borrow().clone();
        let mut target_identity = identifier.identify().await.map(move |mut i| {
            i.ids = Some(ids);
            i
        });
        responder.send(&mut target_identity).context("responding to client")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*, fidl_fuchsia_buildinfo as buildinfo, fidl_fuchsia_developer_remotecontrol as rcs,
        fidl_fuchsia_device as fdevice, fidl_fuchsia_hwinfo as hwinfo, fidl_fuchsia_io::NodeMarker,
        fidl_fuchsia_net as fnet, fidl_fuchsia_net_interfaces as fnet_interfaces,
        fuchsia_zircon as zx, selectors::parse_selector, service_discovery::PathEntry,
        std::path::PathBuf,
    };

    const NODENAME: &'static str = "thumb-set-human-shred";
    const BOOT_TIME: u64 = 123456789000000000;
    const SERIAL: &'static str = "test_serial";
    const BOARD_CONFIG: &'static str = "test_board_name";
    const PRODUCT_CONFIG: &'static str = "core";

    const IPV4_ADDR: [u8; 4] = [127, 0, 0, 1];
    const IPV6_ADDR: [u8; 16] = [127, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5, 6];

    fn setup_fake_device_service() -> hwinfo::DeviceProxy {
        let (proxy, mut stream) =
            fidl::endpoints::create_proxy_and_stream::<hwinfo::DeviceMarker>().unwrap();
        fasync::Task::spawn(async move {
            while let Ok(Some(req)) = stream.try_next().await {
                match req {
                    hwinfo::DeviceRequest::GetInfo { responder } => {
                        let _ = responder.send(hwinfo::DeviceInfo {
                            serial_number: Some(String::from(SERIAL)),
                            ..hwinfo::DeviceInfo::EMPTY
                        });
                    }
                }
            }
        })
        .detach();

        proxy
    }

    fn setup_fake_build_info_service() -> buildinfo::ProviderProxy {
        let (proxy, mut stream) =
            fidl::endpoints::create_proxy_and_stream::<buildinfo::ProviderMarker>().unwrap();
        fasync::Task::spawn(async move {
            while let Ok(Some(req)) = stream.try_next().await {
                match req {
                    buildinfo::ProviderRequest::GetBuildInfo { responder } => {
                        let _ = responder.send(buildinfo::BuildInfo {
                            board_config: Some(String::from(BOARD_CONFIG)),
                            product_config: Some(String::from(PRODUCT_CONFIG)),
                            ..buildinfo::BuildInfo::EMPTY
                        });
                    }
                }
            }
        })
        .detach();

        proxy
    }

    fn setup_fake_name_provider_service() -> fdevice::NameProviderProxy {
        let (proxy, mut stream) =
            fidl::endpoints::create_proxy_and_stream::<fdevice::NameProviderMarker>().unwrap();

        fasync::Task::spawn(async move {
            while let Ok(Some(req)) = stream.try_next().await {
                match req {
                    fdevice::NameProviderRequest::GetDeviceName { responder } => {
                        let _ = responder.send(&mut Ok(String::from(NODENAME)));
                    }
                }
            }
        })
        .detach();

        proxy
    }

    fn setup_fake_interface_state_service() -> fnet_interfaces::StateProxy {
        let (proxy, mut stream) =
            fidl::endpoints::create_proxy_and_stream::<fnet_interfaces::StateMarker>().unwrap();

        fasync::Task::spawn(async move {
            while let Ok(Some(req)) = stream.try_next().await {
                match req {
                    fnet_interfaces::StateRequest::GetWatcher {
                        options: _,
                        watcher,
                        control_handle: _,
                    } => {
                        let mut stream = watcher.into_stream().unwrap();
                        let mut first = true;
                        while let Ok(Some(req)) = stream.try_next().await {
                            match req {
                                fnet_interfaces::WatcherRequest::Watch { responder } => {
                                    let mut event = if first {
                                        first = false;
                                        fnet_interfaces::Event::Existing(
                                            fnet_interfaces::Properties {
                                                id: Some(1),
                                                addresses: Some(
                                                    std::array::IntoIter::new([
                                                        fnet::Subnet {
                                                            addr: fnet::IpAddress::Ipv4(
                                                                fnet::Ipv4Address {
                                                                    addr: IPV4_ADDR,
                                                                },
                                                            ),
                                                            prefix_len: 4,
                                                        },
                                                        fnet::Subnet {
                                                            addr: fnet::IpAddress::Ipv6(
                                                                fnet::Ipv6Address {
                                                                    addr: IPV6_ADDR,
                                                                },
                                                            ),
                                                            prefix_len: 6,
                                                        },
                                                    ])
                                                    .map(Some)
                                                    .map(|addr| fnet_interfaces::Address {
                                                        addr,
                                                        valid_until: Some(1),
                                                        ..fnet_interfaces::Address::EMPTY
                                                    })
                                                    .collect(),
                                                ),
                                                online: Some(true),
                                                device_class: Some(
                                                    fnet_interfaces::DeviceClass::Loopback(
                                                        fnet_interfaces::Empty {},
                                                    ),
                                                ),
                                                has_default_ipv4_route: Some(false),
                                                has_default_ipv6_route: Some(false),
                                                name: Some(String::from("eth0")),
                                                ..fnet_interfaces::Properties::EMPTY
                                            },
                                        )
                                    } else {
                                        fnet_interfaces::Event::Idle(fnet_interfaces::Empty {})
                                    };
                                    let () = responder.send(&mut event).unwrap();
                                }
                            }
                        }
                    }
                }
            }
        })
        .detach();

        proxy
    }

    fn make_rcs() -> Rc<RemoteControlService> {
        Rc::new(RemoteControlService::new_with_allocator(|| {
            Ok(HostIdentifier {
                interface_state_proxy: setup_fake_interface_state_service(),
                name_provider_proxy: setup_fake_name_provider_service(),
                device_info_proxy: setup_fake_device_service(),
                build_info_proxy: setup_fake_build_info_service(),
                boot_timestamp_nanos: BOOT_TIME,
            })
        }))
    }

    fn setup_rcs_proxy() -> rcs::RemoteControlProxy {
        let service = make_rcs();

        let (rcs_proxy, stream) =
            fidl::endpoints::create_proxy_and_stream::<rcs::RemoteControlMarker>().unwrap();
        fasync::Task::local(async move {
            service.serve_stream(stream).await.unwrap();
        })
        .detach();

        return rcs_proxy;
    }

    #[fasync::run_singlethreaded(test)]
    async fn test_identify_host() -> Result<()> {
        let rcs_proxy = setup_rcs_proxy();

        let resp = rcs_proxy.identify_host().await.unwrap().unwrap();

        assert_eq!(resp.serial_number.unwrap(), SERIAL);
        assert_eq!(resp.board_config.unwrap(), BOARD_CONFIG);
        assert_eq!(resp.product_config.unwrap(), PRODUCT_CONFIG);
        assert_eq!(resp.nodename.unwrap(), NODENAME);

        let addrs = resp.addresses.unwrap();
        assert_eq!(addrs.len(), 2);

        let v4 = &addrs[0];
        assert_eq!(v4.prefix_len, 4);
        assert_eq!(v4.addr, fnet::IpAddress::Ipv4(fnet::Ipv4Address { addr: IPV4_ADDR }));

        let v6 = &addrs[1];
        assert_eq!(v6.prefix_len, 6);
        assert_eq!(v6.addr, fnet::IpAddress::Ipv6(fnet::Ipv6Address { addr: IPV6_ADDR }));

        assert_eq!(resp.boot_timestamp_nanos.unwrap(), BOOT_TIME);

        Ok(())
    }

    #[fasync::run_singlethreaded(test)]
    async fn test_ids_in_host_identify() -> Result<()> {
        let rcs_proxy = setup_rcs_proxy();

        let ident = rcs_proxy.identify_host().await.unwrap().unwrap();
        assert_eq!(ident.ids, Some(vec![]));

        rcs_proxy.add_id(1234).await.unwrap();
        rcs_proxy.add_id(4567).await.unwrap();

        let ident = rcs_proxy.identify_host().await.unwrap().unwrap();
        let ids = ident.ids.unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(1234u64, ids[0]);
        assert_eq!(4567u64, ids[1]);

        Ok(())
    }

    fn wildcard_selector() -> Selector {
        parse_selector("*:*:*").unwrap()
    }

    async fn no_paths_matcher() -> Result<Vec<PathEntry>> {
        Ok(vec![])
    }

    async fn two_paths_matcher() -> Result<Vec<PathEntry>> {
        Ok(vec![
            PathEntry {
                hub_path: PathBuf::from("/"),
                moniker: PathBuf::from("/a/b/c"),
                component_subdir: "out".to_string(),
                service: "myservice".to_string(),
                debug_hub_path: None,
            },
            PathEntry {
                hub_path: PathBuf::from("/"),
                moniker: PathBuf::from("/a/b/c"),
                component_subdir: "out".to_string(),
                service: "myservice2".to_string(),
                debug_hub_path: None,
            },
        ])
    }

    async fn single_path_matcher() -> Result<Vec<PathEntry>> {
        Ok(vec![PathEntry {
            hub_path: PathBuf::from("/tmp"),
            moniker: PathBuf::from("/tmp"),
            component_subdir: "out".to_string(),
            service: "myservice".to_string(),
            debug_hub_path: None,
        }])
    }

    #[fasync::run_singlethreaded(test)]
    async fn test_connect_no_matches() -> Result<()> {
        let service = make_rcs();
        let (_, server_end) = zx::Channel::create().unwrap();

        let result = service
            .connect_with_matcher(&wildcard_selector(), server_end, no_paths_matcher())
            .await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), rcs::ConnectError::NoMatchingServices);
        Ok(())
    }

    #[fasync::run_singlethreaded(test)]
    async fn test_connect_multiple_matches() -> Result<()> {
        let service = make_rcs();
        let (_, server_end) = zx::Channel::create().unwrap();

        let result = service
            .connect_with_matcher(&wildcard_selector(), server_end, two_paths_matcher())
            .await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), rcs::ConnectError::MultipleMatchingServices);
        Ok(())
    }

    #[fasync::run_singlethreaded(test)]
    async fn test_connect_single_match() -> Result<()> {
        let service = make_rcs();
        let (client_end, server_end) = fidl::endpoints::create_endpoints::<NodeMarker>().unwrap();

        service
            .connect_with_matcher(
                &wildcard_selector(),
                server_end.into_channel(),
                single_path_matcher(),
            )
            .await
            .unwrap();

        // Make a dummy call to verify that the channel did get hooked up.
        assert!(client_end.into_proxy().unwrap().describe().await.is_ok());
        Ok(())
    }

    #[fasync::run_singlethreaded(test)]
    async fn test_select_multiple_matches() -> Result<()> {
        let service = make_rcs();

        let result =
            service.select_with_matcher(&wildcard_selector(), two_paths_matcher()).await.unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.iter().any(|p| *p
            == rcs::ServiceMatch {
                moniker: vec!["a".to_string(), "b".to_string(), "c".to_string()],
                subdir: "out".to_string(),
                service: "myservice".to_string()
            }));
        assert!(result.iter().any(|p| *p
            == rcs::ServiceMatch {
                moniker: vec!["a".to_string(), "b".to_string(), "c".to_string()],
                subdir: "out".to_string(),
                service: "myservice2".to_string()
            }));
        Ok(())
    }
}
