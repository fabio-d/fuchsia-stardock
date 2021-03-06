// Copyright 2021 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(test)]

use anyhow::Context as _;
use fidl_fuchsia_net_stack as fnet_stack;
use fidl_fuchsia_net_stack_ext::FidlReturn as _;
use fuchsia_async::TimeoutExt as _;
use fuchsia_zircon as zx;
use futures::{FutureExt as _, StreamExt as _, TryStreamExt as _};
use itertools::Itertools as _;
use net_declare::{fidl_if_addr, fidl_ip, fidl_ip_v4_with_prefix, fidl_subnet, std_ip};
use netemul::RealmUdpSocket as _;
use netstack_testing_common::Result;
use netstack_testing_common::{
    interfaces,
    realms::{Netstack, Netstack2, NetstackVersion, TestSandboxExt as _},
};
use netstack_testing_macros::variants_test;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto as _;
use test_case::test_case;

#[variants_test]
async fn watcher_existing<N: Netstack>(name: &str) {
    // We're limiting this test to mostly IPv4 because Netstack3 doesn't support
    // updates yet. We wanted the best test we could write just for the Existing
    // case since IPv6 LL addresses are subject to DAD and hard to test with
    // Existing events only.

    let sandbox = netemul::TestSandbox::new().expect("create sandbox");
    let realm = sandbox.create_netstack_realm::<N, _>(name).expect("create realm");
    let stack =
        realm.connect_to_protocol::<fnet_stack::StackMarker>().expect("connect to protocol");

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Expectation {
        Loopback(u64),
        Ethernet {
            id: u64,
            addr: fidl_fuchsia_net::InterfaceAddress,
            has_default_ipv4_route: bool,
            has_default_ipv6_route: bool,
        },
    }

    impl PartialEq<fidl_fuchsia_net_interfaces_ext::Properties> for Expectation {
        fn eq(&self, other: &fidl_fuchsia_net_interfaces_ext::Properties) -> bool {
            match self {
                Expectation::Loopback(id) => {
                    other
                        == &fidl_fuchsia_net_interfaces_ext::Properties {
                            id: *id,
                            name: "lo".to_owned(),
                            device_class: fidl_fuchsia_net_interfaces::DeviceClass::Loopback(
                                fidl_fuchsia_net_interfaces::Empty,
                            ),
                            online: true,
                            addresses: vec![
                                fidl_fuchsia_net_interfaces_ext::Address {
                                    value: fidl_if_addr!("127.0.0.1/8"),
                                    valid_until: zx::sys::ZX_TIME_INFINITE,
                                },
                                fidl_fuchsia_net_interfaces_ext::Address {
                                    value: fidl_if_addr!("::1"),
                                    valid_until: zx::sys::ZX_TIME_INFINITE,
                                },
                            ],
                            has_default_ipv4_route: false,
                            has_default_ipv6_route: false,
                        }
                }
                Expectation::Ethernet {
                    id,
                    addr,
                    has_default_ipv4_route,
                    has_default_ipv6_route,
                } => {
                    let fidl_fuchsia_net_interfaces_ext::Properties {
                        id: rhs_id,
                        // TODO(https://fxbug.dev/84516): Not comparing name
                        // because ns3 doesn't generate names yet.
                        name: _,
                        device_class,
                        online,
                        addresses,
                        has_default_ipv4_route: rhs_ipv4_route,
                        has_default_ipv6_route: rhs_ipv6_route,
                    } = other;

                    // We use contains here because netstack can generate
                    // link-local addresses that can't be predicted.
                    addresses.contains(&fidl_fuchsia_net_interfaces_ext::Address {
                        value: *addr,
                        valid_until: zx::sys::ZX_TIME_INFINITE,
                    }) && *online
                        && id == rhs_id
                        && has_default_ipv4_route == rhs_ipv4_route
                        && has_default_ipv6_route == rhs_ipv6_route
                        && device_class
                            == &fidl_fuchsia_net_interfaces::DeviceClass::Device(
                                fidl_fuchsia_hardware_network::DeviceClass::Virtual,
                            )
                }
            }
        }
    }

    let interfaces_state = realm
        .connect_to_protocol::<fidl_fuchsia_net_interfaces::StateMarker>()
        .expect("connect to protocol");

    let mut eps = Vec::new();
    let mut expectations = HashMap::new();
    for (idx, (has_default_ipv4_route, has_default_ipv6_route)) in
        IntoIterator::into_iter([true, false]).cartesian_product([true, false]).enumerate()
    {
        // TODO(https://fxbug.dev/88796): Use TestRealm::join_network_with
        // https://fuchsia-docs.firebaseapp.com/rust/netemul/struct.TestRealm.html#method.join_network_with
        // when `fuchsia.net.interfaces.admin` is supported.
        let ep = sandbox
            .create_endpoint::<netemul::Ethernet, _>(format!("test-ep-{}", idx))
            .await
            .expect("create endpoint");

        let iface = ep.into_interface_in_realm(&realm).await.expect("add device to stack");
        let id = iface.id();

        // TODO(https://fxbug.dev/20989#c5): netstack3 doesn't allow addresses to be added while
        // link is down.
        let () =
            stack.enable_interface_deprecated(id).await.squash_result().expect("enable interface");
        let () = iface.set_link_up(true).await.expect("bring device up");

        fidl_fuchsia_net_interfaces_ext::wait_interface_with_id(
            fidl_fuchsia_net_interfaces_ext::event_stream_from_state(&interfaces_state)
                .expect("interface stream"),
            &mut fidl_fuchsia_net_interfaces_ext::InterfaceState::Unknown(id),
            |fidl_fuchsia_net_interfaces_ext::Properties {
                 id: _,
                 name: _,
                 device_class: _,
                 online,
                 addresses: _,
                 has_default_ipv4_route: _,
                 has_default_ipv6_route: _,
             }| (*online).then(|| ()),
        )
        .await
        .expect("wait device online");

        let addr = fidl_fuchsia_net::Ipv4Address { addr: [192, 168, idx.try_into().unwrap(), 1] };
        let prefix_len = 24;
        let if_addr =
            fidl_fuchsia_net::InterfaceAddress::Ipv4(fidl_fuchsia_net::Ipv4AddressWithPrefix {
                addr,
                prefix_len,
            });
        let expected = Expectation::Ethernet {
            id,
            addr: if_addr,
            has_default_ipv4_route,
            has_default_ipv6_route,
        };
        assert_eq!(expectations.insert(id, expected), None);
        match N::VERSION {
            NetstackVersion::Netstack2 => {
                let address_state_provider = interfaces::add_address_wait_assigned(
                    iface.control(),
                    if_addr,
                    fidl_fuchsia_net_interfaces_admin::AddressParameters::EMPTY,
                )
                .await
                .expect("add address");
                let () = address_state_provider.detach().expect("detach address lifetime");
            }
            NetstackVersion::ProdNetstack2 => panic!("unexpected netstack version"),
            NetstackVersion::Netstack2WithFastUdp => panic!("unexpected netstack version"),
            NetstackVersion::Netstack3 => {
                // TODO(https://fxbug.dev/92767): Remove this when N3 implements Control.
                let () = stack
                    .add_interface_address_deprecated(
                        id,
                        &mut fidl_fuchsia_net::Subnet {
                            addr: fidl_fuchsia_net::IpAddress::Ipv4(addr),
                            prefix_len,
                        },
                    )
                    .await
                    .squash_result()
                    .expect("add interface address");
            }
        }

        eps.push(iface);

        if has_default_ipv4_route {
            stack
                .add_forwarding_entry(&mut fnet_stack::ForwardingEntry {
                    subnet: fidl_subnet!("0.0.0.0/0"),
                    device_id: id,
                    next_hop: None,
                    metric: 0,
                })
                .await
                .squash_result()
                .expect("add default ipv4 route entry");
        }

        if has_default_ipv6_route {
            stack
                .add_forwarding_entry(&mut fnet_stack::ForwardingEntry {
                    subnet: fidl_subnet!("::/0"),
                    device_id: id,
                    next_hop: None,
                    metric: 0,
                })
                .await
                .squash_result()
                .expect("add default ipv6 route entry");
        }
    }

    // The netstacks report the loopback interface as NIC 1.
    assert_eq!(expectations.insert(1, Expectation::Loopback(1)), None);

    let mut interfaces = fidl_fuchsia_net_interfaces_ext::existing(
        fidl_fuchsia_net_interfaces_ext::event_stream_from_state(&interfaces_state)
            .expect("create event stream"),
        HashMap::new(),
    )
    .await
    .expect("fetch existing interfaces");

    for (id, expected) in expectations.iter() {
        assert_eq!(
            expected,
            interfaces.remove(id).as_ref().unwrap_or_else(|| panic!("get interface {}", id))
        );
    }

    assert_eq!(interfaces, HashMap::new());
}

#[variants_test]
async fn watcher_after_state_closed<N: Netstack>(name: &str) {
    let sandbox = netemul::TestSandbox::new().expect("create sandbox");
    let realm = sandbox.create_netstack_realm::<N, _>(name).expect("create realm");

    // New scope so when we get back the WatcherProxy, the StateProxy is closed.
    let watcher = {
        let interfaces_state = realm
            .connect_to_protocol::<fidl_fuchsia_net_interfaces::StateMarker>()
            .expect("connect to protocol");
        let (watcher, server) =
            fidl::endpoints::create_proxy::<fidl_fuchsia_net_interfaces::WatcherMarker>()
                .expect("create watcher proxy");
        let () = interfaces_state
            .get_watcher(fidl_fuchsia_net_interfaces::WatcherOptions::EMPTY, server)
            .expect("get watcher");
        watcher
    };

    let stream = fidl_fuchsia_net_interfaces_ext::event_stream(watcher);
    let interfaces = fidl_fuchsia_net_interfaces_ext::existing(stream, HashMap::new())
        .await
        .expect("collect interfaces");
    let expected = match N::VERSION {
        NetstackVersion::Netstack3 | NetstackVersion::Netstack2 => std::iter::once((
            1,
            fidl_fuchsia_net_interfaces_ext::Properties {
                id: 1,
                name: "lo".to_owned(),
                device_class: fidl_fuchsia_net_interfaces::DeviceClass::Loopback(
                    fidl_fuchsia_net_interfaces::Empty,
                ),
                online: true,
                addresses: vec![
                    fidl_fuchsia_net_interfaces_ext::Address {
                        value: fidl_if_addr!("127.0.0.1/8"),
                        valid_until: zx::sys::ZX_TIME_INFINITE,
                    },
                    fidl_fuchsia_net_interfaces_ext::Address {
                        value: fidl_if_addr!("::1"),
                        valid_until: zx::sys::ZX_TIME_INFINITE,
                    },
                ],
                has_default_ipv4_route: false,
                has_default_ipv6_route: false,
            },
        ))
        .collect(),
        NetstackVersion::ProdNetstack2 => panic!("unexpected netstack version"),
        NetstackVersion::Netstack2WithFastUdp => panic!("unexpected netstack version"),
    };
    assert_eq!(interfaces, expected);
}

/// Tests that adding an interface causes an interface changed event.
//
// TODO(https://fxbug.dev/88796): Run this against netstack3 when
// `fuchsia.net.interfaces.admin` is supported.
#[variants_test]
async fn test_add_remove_interface<E: netemul::Endpoint>(name: &str) {
    let sandbox = netemul::TestSandbox::new().expect("create sandbox");
    let realm = sandbox.create_netstack_realm::<Netstack2, _>(name).expect("create realm");
    let stack =
        realm.connect_to_protocol::<fnet_stack::StackMarker>().expect("connect to protocol");
    let device = sandbox.create_endpoint::<E, _>(name).await.expect("create endpoint");

    let iface = device.into_interface_in_realm(&realm).await.expect("add device");
    let id = iface.id();

    let interface_state = realm
        .connect_to_protocol::<fidl_fuchsia_net_interfaces::StateMarker>()
        .expect("connect to protocol");
    let (watcher, watcher_server) =
        ::fidl::endpoints::create_proxy::<fidl_fuchsia_net_interfaces::WatcherMarker>()
            .expect("create watcher");
    let () = interface_state
        .get_watcher(fidl_fuchsia_net_interfaces::WatcherOptions::EMPTY, watcher_server)
        .expect("initialize interface watcher");

    let mut if_map = HashMap::new();
    let () = fidl_fuchsia_net_interfaces_ext::wait_interface(
        fidl_fuchsia_net_interfaces_ext::event_stream(watcher.clone()),
        &mut if_map,
        // TODO(https://github.com/rust-lang/rust/issues/80967): use bool::then_some.
        |if_map| if_map.contains_key(&id).then(|| ()),
    )
    .await
    .expect("observe interface addition");

    let () = stack.del_ethernet_interface(id).await.squash_result().expect("delete device");

    let () = fidl_fuchsia_net_interfaces_ext::wait_interface(
        fidl_fuchsia_net_interfaces_ext::event_stream(watcher.clone()),
        &mut if_map,
        // TODO(https://github.com/rust-lang/rust/issues/80967): use bool::then_some.
        |if_map| (!if_map.contains_key(&id)).then(|| ()),
    )
    .await
    .expect("observe interface addition");
}

/// Tests that if a device closes (is removed from the system), the
/// corresponding Netstack interface is deleted.
/// if `enabled` is `true`, enables the interface before closing the device.
//
// TODO(https://fxbug.dev/88796): Run this against netstack3 when
// `fuchsia.net.interfaces.admin` is supported.
#[variants_test]
#[test_case("disabled", false; "disabled")]
#[test_case("enabled", true ; "enabled")]
async fn test_close_interface<E: netemul::Endpoint>(
    test_name: &str,
    sub_test_name: &str,
    enabled: bool,
) {
    let name = format!("{}_{}", test_name, sub_test_name);
    let name = name.as_str();

    let sandbox = netemul::TestSandbox::new().expect("create sandbox");
    let realm = sandbox.create_netstack_realm::<Netstack2, _>(name).expect("create realm");
    let device = sandbox.create_endpoint::<E, _>(name).await.expect("create endpoint");

    let iface = device.into_interface_in_realm(&realm).await.expect("add device");
    let id = iface.id();

    if enabled {
        let did_enable = iface.control().enable().await.expect("send enable").expect("enable");
        assert!(did_enable);
    }

    let interface_state = realm
        .connect_to_protocol::<fidl_fuchsia_net_interfaces::StateMarker>()
        .expect("connect to protocol");
    let (watcher, watcher_server) =
        ::fidl::endpoints::create_proxy::<fidl_fuchsia_net_interfaces::WatcherMarker>()
            .expect("create watcher");
    let () = interface_state
        .get_watcher(fidl_fuchsia_net_interfaces::WatcherOptions::EMPTY, watcher_server)
        .expect("initialize interface watcher");
    let mut if_map = HashMap::new();
    let () = fidl_fuchsia_net_interfaces_ext::wait_interface(
        fidl_fuchsia_net_interfaces_ext::event_stream(watcher.clone()),
        &mut if_map,
        // TODO(https://github.com/rust-lang/rust/issues/80967): use bool::then_some.
        |if_map| if_map.contains_key(&id).then(|| ()),
    )
    .await
    .expect("observe interface addition");

    // Drop the device, that should cause the interface to be deleted.
    let (ep, _control, _device_control) = iface.into_inner();
    std::mem::drop(ep);

    // Wait until we observe the removed interface is missing.
    let () = fidl_fuchsia_net_interfaces_ext::wait_interface(
        fidl_fuchsia_net_interfaces_ext::event_stream(watcher.clone()),
        &mut if_map,
        |if_map| {
            // TODO(https://github.com/rust-lang/rust/issues/80967): use bool::then_some.
            (!if_map.contains_key(&id)).then(|| ())
        },
    )
    .await
    .expect("observe interface removal");
}

/// Tests races between device link down and close.
//
// TODO(https://fxbug.dev/88796): Run this against netstack3 when
// `fuchsia.net.interfaces.admin` is supported.
#[variants_test]
async fn test_down_close_race<E: netemul::Endpoint>(name: &str) {
    let sandbox = netemul::TestSandbox::new().expect("create sandbox");
    let realm = sandbox.create_netstack_realm::<Netstack2, _>(name).expect("create netstack realm");
    let interface_state = realm
        .connect_to_protocol::<fidl_fuchsia_net_interfaces::StateMarker>()
        .expect("connect to protocol");
    let (watcher, watcher_server) =
        ::fidl::endpoints::create_proxy::<fidl_fuchsia_net_interfaces::WatcherMarker>()
            .expect("create watcher");
    let () = interface_state
        .get_watcher(fidl_fuchsia_net_interfaces::WatcherOptions::EMPTY, watcher_server)
        .expect("initialize interface watcher");
    let mut if_map = HashMap::new();

    for _ in 0..10u64 {
        let dev = sandbox
            .create_endpoint::<E, _>("ep")
            .await
            .expect("create endpoint")
            .into_interface_in_realm(&realm)
            .await
            .expect("add endpoint to Netstack");

        let did_enable = dev.control().enable().await.expect("send enable").expect("enable");
        assert!(did_enable);
        let () = dev.start_dhcp().await.expect("start DHCP");
        let () = dev.set_link_up(true).await.expect("bring device up");

        let id = dev.id();
        // Wait until the interface is installed and the link state is up.
        let () = fidl_fuchsia_net_interfaces_ext::wait_interface(
            fidl_fuchsia_net_interfaces_ext::event_stream(watcher.clone()),
            &mut if_map,
            |if_map| {
                let &fidl_fuchsia_net_interfaces_ext::Properties { online, .. } =
                    if_map.get(&id)?;
                // TODO(https://github.com/rust-lang/rust/issues/80967): use bool::then_some.
                online.then(|| ())
            },
        )
        .await
        .expect("observe interface online");

        // Here's where we cause the race. We bring the device's link down
        // and drop it right after; the two signals will race to reach
        // Netstack.
        let () = dev.set_link_up(false).await.expect("bring link down");
        std::mem::drop(dev);

        // Wait until the interface is removed from Netstack cleanly.
        let () = fidl_fuchsia_net_interfaces_ext::wait_interface(
            fidl_fuchsia_net_interfaces_ext::event_stream(watcher.clone()),
            &mut if_map,
            |if_map| {
                // TODO(https://github.com/rust-lang/rust/issues/80967): use bool::then_some.
                (!if_map.contains_key(&id)).then(|| ())
            },
        )
        .await
        .expect("observe interface removal");
    }
}

/// Tests races between data traffic and closing a device.
//
// TODO(https://fxbug.dev/88796): Run this against netstack3 when
// `fuchsia.net.interfaces.admin` is supported.
#[variants_test]
async fn test_close_data_race<E: netemul::Endpoint>(name: &str) {
    let sandbox = netemul::TestSandbox::new().expect("create sandbox");
    let net = sandbox.create_network("net").await.expect("create network");
    let fake_ep = net.create_fake_endpoint().expect("create fake endpoint");
    let realm = sandbox.create_netstack_realm::<Netstack2, _>(name).expect("create netstack realm");

    // NOTE: We only run this test with IPv4 sockets since we only care about
    // exciting the tx path, the domain is irrelevant.
    const DEVICE_ADDRESS_IN_SUBNET: fidl_fuchsia_net::Subnet = fidl_subnet!("192.168.0.2/24");
    // We're going to send data over a UDP socket to a multicast address so we
    // skip ARP resolution.
    const MCAST_ADDR: std::net::IpAddr = std_ip!("224.0.0.1");

    let interface_state = realm
        .connect_to_protocol::<fidl_fuchsia_net_interfaces::StateMarker>()
        .expect("connect to protocol");
    let (watcher, watcher_server) =
        ::fidl::endpoints::create_proxy::<fidl_fuchsia_net_interfaces::WatcherMarker>()
            .expect("create watcher");
    let () = interface_state
        .get_watcher(fidl_fuchsia_net_interfaces::WatcherOptions::EMPTY, watcher_server)
        .expect("initialize interface watcher");
    let mut if_map = HashMap::new();
    for _ in 0..10u64 {
        let dev = net
            .create_endpoint::<E, _>("ep")
            .await
            .expect("create endpoint")
            .into_interface_in_realm(&realm)
            .await
            .expect("add endpoint to Netstack");

        let did_enable = dev.control().enable().await.expect("send enable").expect("enable");
        assert!(did_enable);
        let () = dev.set_link_up(true).await.expect("bring device up");

        let address_state_provider = interfaces::add_subnet_address_and_route_wait_assigned(
            &dev,
            DEVICE_ADDRESS_IN_SUBNET,
            fidl_fuchsia_net_interfaces_admin::AddressParameters::EMPTY,
        )
        .await
        .expect("add subnet address and route");
        let () = address_state_provider.detach().expect("detach address lifetime");

        // Create a socket and start sending data on it nonstop.
        let fidl_fuchsia_net_ext::IpAddress(bind_addr) = DEVICE_ADDRESS_IN_SUBNET.addr.into();
        let sock = fuchsia_async::net::UdpSocket::bind_in_realm(
            &realm,
            std::net::SocketAddr::new(bind_addr, 0),
        )
        .await
        .expect("create socket");

        // Keep sending data until writing to the socket fails.
        let io_fut = async {
            loop {
                match sock
                    .send_to(&[1u8, 2, 3, 4], std::net::SocketAddr::new(MCAST_ADDR, 1234))
                    .await
                {
                    Ok(_sent) => {}
                    // We expect only "os errors" to happen, ideally we'd look
                    // only at specific errors (EPIPE, ENETUNREACH), but that
                    // made this test very flaky due to the branching error
                    // paths in gVisor when removing an interface.
                    Err(e) if e.raw_os_error().is_some() => break Result::Ok(()),
                    Err(e) => break Err(e).context("send_to error"),
                }

                // Enqueue some data on the rx path.
                let () = fake_ep
                    // We don't care that it's a valid frame, only that it excites
                    // the rx path.
                    .write(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
                    .await
                    .expect("send frame on fake_ep");

                // Wait on a short timer to avoid too much log noise when
                // running the test.
                let () = fuchsia_async::Timer::new(fuchsia_async::Time::after(
                    fuchsia_zircon::Duration::from_micros(10),
                ))
                .await;
            }
        };

        let id = dev.id();
        let drop_fut = async move {
            let () = fuchsia_async::Timer::new(fuchsia_async::Time::after(
                fuchsia_zircon::Duration::from_millis(3),
            ))
            .await;
            std::mem::drop(dev);
        };

        let iface_dropped = fidl_fuchsia_net_interfaces_ext::wait_interface(
            fidl_fuchsia_net_interfaces_ext::event_stream(watcher.clone()),
            &mut if_map,
            |if_map| {
                // TODO(https://github.com/rust-lang/rust/issues/80967): use bool::then_some.
                (!if_map.contains_key(&id)).then(|| ())
            },
        );

        let (io_result, iface_dropped, ()) =
            futures::future::join3(io_fut, iface_dropped, drop_fut).await;
        let () = io_result.expect("unexpected error on io future");
        let () = iface_dropped.expect("observe interface removal");
    }
}

/// Tests that toggling interface enabled repeatedly results in every change
/// in the boolean value being observable.
//
// TODO(https://fxbug.dev/88796): Run this against netstack3 when
// `fuchsia.net.interfaces.admin` is supported.
#[fuchsia_async::run_singlethreaded(test)]
async fn test_watcher_online_edges() {
    let name = "test_watcher_online_edges";
    let sandbox = netemul::TestSandbox::new().expect("create sandbox");
    let realm = sandbox.create_netstack_realm::<Netstack2, _>(name).expect("create netstack realm");

    let interface_state = realm
        .connect_to_protocol::<fidl_fuchsia_net_interfaces::StateMarker>()
        .expect("connect to protocol");
    let event_stream = fidl_fuchsia_net_interfaces_ext::event_stream_from_state(&interface_state)
        .expect("event stream from state")
        .map(|r| r.expect("watcher error"))
        .fuse();
    futures::pin_mut!(event_stream);

    // Consume the watcher until we see the idle event.
    let existing = fidl_fuchsia_net_interfaces_ext::existing(
        event_stream.by_ref().map(std::result::Result::<_, fidl::Error>::Ok),
        HashMap::new(),
    )
    .await
    .expect("existing");
    // Only loopback should exist.
    assert_eq!(existing.len(), 1, "unexpected interfaces in existing: {:?}", existing);

    let ep = sandbox
        // We don't need to run variants for this test, all we care about is
        // the Netstack race. Use NetworkDevice because it's lighter weight.
        .create_endpoint::<netemul::NetworkDevice, _>("ep")
        .await
        .expect("create fixed ep")
        .into_interface_in_realm(&realm)
        .await
        .expect("install in realm");
    let iface_id = ep.id();
    assert_matches::assert_matches!(
        event_stream.select_next_some().await,
        fidl_fuchsia_net_interfaces::Event::Added(fidl_fuchsia_net_interfaces::Properties {
            id: Some(id),
            online: Some(false),
            ..
        }) => id == iface_id
    );
    // NB: Need to set link up and ensure that Netstack has observed link-up
    // (by also enabling the interface and observing that online changes
    // to true); otherwise enabling/disabling the interface may not change
    // interface online as we'd expect.
    ep.set_link_up(true).await.expect("bring link up");
    assert!(ep.control().enable().await.expect("send enable").expect("enable"));
    assert_matches::assert_matches!(
        event_stream.select_next_some().await,
        fidl_fuchsia_net_interfaces::Event::Changed(fidl_fuchsia_net_interfaces::Properties {
            id: Some(id),
            online: Some(true),
            ..
        }) => id == iface_id
    );

    // Future which concurrently enables and disables the interface a set
    // number of iterations.  Note that the raciness is intentional: the
    // interface may be enabled/disabled less than the number of iterations.
    let toggle_online_fut = {
        const ITERATIONS: usize = 100;
        let enable_fut = futures::stream::iter(std::iter::repeat(()).take(ITERATIONS)).fold(
            (ep, 0),
            |(ep, change_count), ()| async move {
                if ep.control().enable().await.expect("send enable").expect("enable") {
                    (ep, change_count + 1)
                } else {
                    (ep, change_count)
                }
            },
        );
        let disable_fut = {
            let debug_interfaces = realm
                .connect_to_protocol::<fidl_fuchsia_net_debug::InterfacesMarker>()
                .expect("connect to protocol");
            let (control, server) =
                fidl::endpoints::create_proxy::<fidl_fuchsia_net_interfaces_admin::ControlMarker>()
                    .expect("create Control");
            debug_interfaces.get_admin(iface_id, server).expect("send get_admin");
            futures::stream::iter(std::iter::repeat(()).take(ITERATIONS)).fold(
                0,
                move |change_count, ()| {
                    control.disable().map(move |r| {
                        change_count
                            + if r.expect("send disable").expect("disable") { 1 } else { 0 }
                    })
                },
            )
        };
        futures::future::join(enable_fut, disable_fut).map(|((ep, enable_count), disable_count)| {
            // Removes the interface.
            std::mem::drop(ep);
            (enable_count, disable_count)
        })
    };

    // Future which consumes interface watcher events and tallies number of
    // offline->online edges (and vice versa).
    let watcher_fut = event_stream
        .take_while(|e| {
            futures::future::ready(match e {
                fidl_fuchsia_net_interfaces::Event::Removed(removed_id) => *removed_id != iface_id,
                fidl_fuchsia_net_interfaces::Event::Added(_)
                | fidl_fuchsia_net_interfaces::Event::Existing(_)
                | fidl_fuchsia_net_interfaces::Event::Changed(_)
                | fidl_fuchsia_net_interfaces::Event::Idle(fidl_fuchsia_net_interfaces::Empty) => {
                    true
                }
            })
        })
        .fold((0, 0, true), |(enable_count, disable_count, online_prev), event| {
            let online_next = assert_matches::assert_matches!(
                event,
                fidl_fuchsia_net_interfaces::Event::Changed(
                    fidl_fuchsia_net_interfaces::Properties {
                        id: Some(id),
                        online,
                        ..
                    },
                ) if id == iface_id => online
            );
            futures::future::ready(match online_next {
                None => (enable_count, disable_count, online_prev),
                Some(online_next) => match (online_prev, online_next) {
                    (false, true) => (enable_count + 1, disable_count, online_next),
                    (true, false) => (enable_count, disable_count + 1, online_next),
                    (prev, next) => {
                        panic!(
                            "online changed event with no change: prev = {}, next = {}",
                            prev, next
                        )
                    }
                },
            })
        });

    let ((want_enable_count, want_disable_count), (got_enable_count, got_disable_count, online)) =
        futures::future::join(toggle_online_fut, watcher_fut).await;
    assert_eq!((got_enable_count, got_disable_count), (want_enable_count, want_disable_count));
    // Since we started with the interface being online, if we end on offline
    // then there must have been one more disable than enable.
    assert_eq!(got_disable_count, if !online { got_enable_count + 1 } else { got_enable_count });
}

/// Tests that competing interface change events are reported by
/// fuchsia.net.interfaces/Watcher in the correct order.
//
// TODO(https://fxbug.dev/88796): Run this against netstack3 when
// `fuchsia.net.interfaces.admin` is supported.
#[fuchsia_async::run_singlethreaded(test)]
async fn test_watcher_race() {
    let name = "test_watcher_race";
    let sandbox = netemul::TestSandbox::new().expect("create sandbox");
    let realm = sandbox.create_netstack_realm::<Netstack2, _>(name).expect("create netstack realm");
    let interface_state = realm
        .connect_to_protocol::<fidl_fuchsia_net_interfaces::StateMarker>()
        .expect("connect to protocol");
    let debug_interfaces = realm
        .connect_to_protocol::<fidl_fuchsia_net_debug::InterfacesMarker>()
        .expect("connect to protocol");
    for _ in 0..100 {
        let (watcher, server) =
            fidl::endpoints::create_proxy::<fidl_fuchsia_net_interfaces::WatcherMarker>()
                .expect("create watcher");
        let () = interface_state
            .get_watcher(fidl_fuchsia_net_interfaces::WatcherOptions::EMPTY, server)
            .expect("initialize interface watcher");

        let ep = sandbox
            // We don't need to run variants for this test, all we care about is
            // the Netstack race. Use NetworkDevice because it's lighter weight.
            .create_endpoint::<netemul::NetworkDevice, _>("ep")
            .await
            .expect("create fixed ep")
            .into_interface_in_realm(&realm)
            .await
            .expect("install in realm");

        const IF_ADDR: fidl_fuchsia_net::InterfaceAddress = fidl_if_addr!("192.168.0.1/24");
        let control_add_address = {
            let (control, server_end) =
                fidl_fuchsia_net_interfaces_ext::admin::Control::create_endpoints()
                    .expect("create endpoints");
            debug_interfaces.get_admin(ep.id(), server_end).expect("send get_admin");
            control
        };

        // Bring the link up, enable the interface, add an IP address,
        // and a default route for the address "non-sequentially" (as much
        // as possible) to cause races in Netstack when reporting events.
        let ((), (), (), ()) = futures::future::join4(
            ep.set_link_up(true).map(|r| r.expect("bring link up")),
            async {
                let did_enable = ep.control().enable().await.expect("send enable").expect("enable");
                assert!(did_enable);
            },
            async {
                let address_state_provider = interfaces::add_address_wait_assigned(
                    &control_add_address,
                    IF_ADDR,
                    fidl_fuchsia_net_interfaces_admin::AddressParameters::EMPTY,
                )
                .await
                .expect("add address");
                let () = address_state_provider.detach().expect("detach address lifetime");
            },
            ep.add_subnet_route(fidl_subnet!("0.0.0.0/0")).map(|r| r.expect("add default route")),
        )
        .await;

        let id = ep.id();
        let () =
            futures::stream::unfold(
                (watcher, false, false, false, false),
                |(watcher, present, up, has_addr, has_default_ipv4_route)| async move {
                    let event = watcher.watch().await.expect("watch");

                    let (
                        mut new_present,
                        mut new_up,
                        mut new_has_addr,
                        mut new_has_default_ipv4_route,
                    ) = (present, up, has_addr, has_default_ipv4_route);
                    match event {
                        fidl_fuchsia_net_interfaces::Event::Added(properties)
                        | fidl_fuchsia_net_interfaces::Event::Existing(properties) => {
                            if properties.id == Some(id) {
                                assert!(!present, "duplicate added/existing event");
                                new_present = true;
                                new_up = properties
                                    .online
                                    .expect("added/existing event missing online property");
                                new_has_addr = properties
                                    .addresses
                                    .expect("added/existing event missing addresses property")
                                    .iter()
                                    .any(
                                        |fidl_fuchsia_net_interfaces::Address {
                                             value,
                                             valid_until: _,
                                             ..
                                         }| {
                                            value == &Some(IF_ADDR)
                                        },
                                    );
                                new_has_default_ipv4_route = properties
                                    .has_default_ipv4_route
                                    .expect(
                                    "added/existing event missing has_default_ipv4_route property",
                                );
                            }
                        }
                        fidl_fuchsia_net_interfaces::Event::Changed(
                            fidl_fuchsia_net_interfaces::Properties {
                                id: changed_id,
                                online,
                                addresses,
                                has_default_ipv4_route,
                                name: _,
                                device_class: _,
                                has_default_ipv6_route: _,
                                ..
                            },
                        ) => {
                            if changed_id == Some(id) {
                                assert!(
                                    present,
                                    "property change event before added or existing event"
                                );
                                if let Some(online) = online {
                                    new_up = online;
                                }
                                if let Some(addresses) = addresses {
                                    new_has_addr = addresses.iter().any(
                                        |fidl_fuchsia_net_interfaces::Address {
                                             value,
                                             valid_until: _,
                                             ..
                                         }| {
                                            value == &Some(IF_ADDR)
                                        },
                                    );
                                }
                                if let Some(has_default_ipv4_route) = has_default_ipv4_route {
                                    new_has_default_ipv4_route = has_default_ipv4_route;
                                }
                            }
                        }
                        fidl_fuchsia_net_interfaces::Event::Removed(removed_id) => {
                            if removed_id == id {
                                assert!(present, "removed event before added or existing");
                                new_present = false;
                            }
                        }
                        _ => {}
                    }
                    println!(
                        "Observed interfaces, previous = ({}, {}, {}, {}), new = ({}, {}, {}, {})",
                        present,
                        up,
                        has_addr,
                        has_default_ipv4_route,
                        new_present,
                        new_up,
                        new_has_addr,
                        new_has_default_ipv4_route
                    );

                    // Verify that none of the observed states can be seen as
                    // "undone" by bad event ordering in Netstack. We don't care
                    // about the order in which we see the events since we're
                    // intentionally racing some things, only that nothing tracks
                    // back.

                    // Device should not disappear.
                    assert!(!present || new_present, "out of order events, device disappeared");
                    // Device should not go offline.
                    assert!(!up || new_up, "out of order events, device went offline");
                    // Address should not disappear.
                    assert!(!has_addr || new_has_addr, "out of order events, address disappeared");
                    // Default route should not disappear.
                    assert!(
                        !has_default_ipv4_route || new_has_default_ipv4_route,
                        "out of order events, default IPv4 route disappeared"
                    );
                    if new_present && new_up && new_has_addr && new_has_default_ipv4_route {
                        // We got everything we wanted, end the stream.
                        None
                    } else {
                        // Continue folding with the new state.
                        Some((
                            (),
                            (
                                watcher,
                                new_present,
                                new_up,
                                new_has_addr,
                                new_has_default_ipv4_route,
                            ),
                        ))
                    }
                },
            )
            .collect()
            .await;
    }
}

/// Test interface changes are reported through the interface watcher.
//
// TODO(https://fxbug.dev/88796): Run this against netstack3 when
// `fuchsia.net.interfaces.admin` is supported.
#[fuchsia_async::run_singlethreaded(test)]
async fn test_watcher() {
    let name = "test_watcher";
    let sandbox = netemul::TestSandbox::new().expect("create sandbox");
    let realm = sandbox.create_netstack_realm::<Netstack2, _>(name).expect("create realm");
    let stack =
        realm.connect_to_protocol::<fnet_stack::StackMarker>().expect("connect to protocol");

    let interface_state = realm
        .connect_to_protocol::<fidl_fuchsia_net_interfaces::StateMarker>()
        .expect("connect to protocol");

    let initialize_watcher = || async {
        let (watcher, server) =
            fidl::endpoints::create_proxy::<fidl_fuchsia_net_interfaces::WatcherMarker>()
                .expect("create watcher");
        let () = interface_state
            .get_watcher(fidl_fuchsia_net_interfaces::WatcherOptions::EMPTY, server)
            .expect("initialize interface watcher");

        let event = watcher.watch().await.expect("watch");
        if let fidl_fuchsia_net_interfaces::Event::Existing(properties) = event {
            assert_eq!(
                properties.device_class,
                Some(fidl_fuchsia_net_interfaces::DeviceClass::Loopback(
                    fidl_fuchsia_net_interfaces::Empty {}
                ))
            );
        } else {
            panic!("got {:?}, want loopback interface existing event", event);
        }

        assert_eq!(
            watcher.watch().await.expect("watch"),
            fidl_fuchsia_net_interfaces::Event::Idle(fidl_fuchsia_net_interfaces::Empty {})
        );
        Result::Ok(watcher)
    };

    let blocking_watcher = initialize_watcher().await.expect("initialize blocking watcher");
    let blocking_stream = fidl_fuchsia_net_interfaces_ext::event_stream(blocking_watcher.clone());
    futures::pin_mut!(blocking_stream);
    let watcher = initialize_watcher().await.expect("initialize watcher");
    let stream = fidl_fuchsia_net_interfaces_ext::event_stream(watcher.clone());
    futures::pin_mut!(stream);

    async fn assert_blocked<S>(stream: &mut S)
    where
        S: futures::stream::TryStream<Error = fidl::Error> + std::marker::Unpin,
        <S as futures::TryStream>::Ok: std::fmt::Debug,
    {
        stream
            .try_next()
            .map(|event| {
                let event = event.expect("event stream error");
                let event = event.expect("watcher event stream ended");
                Some(event)
            })
            .on_timeout(
                fuchsia_async::Time::after(fuchsia_zircon::Duration::from_millis(50)),
                || None,
            )
            .map(|e| match e {
                Some(e) => panic!("did not block but yielded {:?}", e),
                None => (),
            })
            .await
    }
    // Add an interface.
    let () = assert_blocked(&mut blocking_stream).await;
    let dev = sandbox
        .create_endpoint::<netemul::NetworkDevice, _>("ep")
        .await
        .expect("create endpoint")
        .into_interface_in_realm(&realm)
        .await
        .expect("add endpoint to Netstack");
    let () = dev.set_link_up(true).await.expect("bring device up");
    let id = dev.id();
    let want = fidl_fuchsia_net_interfaces::Event::Added(fidl_fuchsia_net_interfaces::Properties {
        id: Some(id),
        // We're not explicitly setting the name when adding the interface, so
        // this may break if Netstack changes how it names interfaces.
        name: Some(format!("eth{}", id)),
        online: Some(false),
        device_class: Some(fidl_fuchsia_net_interfaces::DeviceClass::Device(
            fidl_fuchsia_hardware_network::DeviceClass::Virtual,
        )),
        addresses: Some(vec![]),
        has_default_ipv4_route: Some(false),
        has_default_ipv6_route: Some(false),
        ..fidl_fuchsia_net_interfaces::Properties::EMPTY
    });
    async fn next<S>(stream: &mut S) -> fidl_fuchsia_net_interfaces::Event
    where
        S: futures::stream::TryStream<Ok = fidl_fuchsia_net_interfaces::Event, Error = fidl::Error>
            + Unpin,
    {
        stream.try_next().await.expect("stream error").expect("watcher event stream ended")
    }
    assert_eq!(next(&mut blocking_stream).await, want);
    assert_eq!(next(&mut stream).await, want);

    // Set the link to up.
    let () = assert_blocked(&mut blocking_stream).await;
    let did_enable = dev.control().enable().await.expect("send enable").expect("enable");
    assert!(did_enable);
    // NB The following fold function is necessary because IPv6 link-local addresses are configured
    // when the interface is brought up (and removed when the interface is brought down) such
    // that the ordering or the number of events that reports the changes in the online and
    // addresses properties cannot be guaranteed. As such, we assert that:
    //
    // 1. the online property MUST change to the expected value in the first event and never change
    //    again,
    // 2. the addresses property changes over some number of events (including possibly the first
    //    event) and eventually reaches the desired count, and
    // 3. no other properties change in any of the events.
    //
    // It would be ideal to disable IPv6 LL address configuration for this test, which would
    // simplify this significantly.
    let fold_fn = |want_online, want_addr_count| {
        move |(mut online_changed, mut addresses), event| match event {
            fidl_fuchsia_net_interfaces::Event::Changed(
                fidl_fuchsia_net_interfaces::Properties {
                    id: Some(event_id),
                    online,
                    addresses: got_addrs,
                    name: None,
                    device_class: None,
                    has_default_ipv4_route: None,
                    has_default_ipv6_route: None,
                    ..
                },
            ) if event_id == id => {
                if let Some(got_online) = online {
                    if online_changed {
                        panic!("duplicate online property change to new value of {}", got_online,);
                    }
                    if got_online != want_online {
                        panic!("got online: {}, want {}", got_online, want_online);
                    }
                    online_changed = true;
                }
                if let Some(got_addrs) = got_addrs {
                    if !online_changed {
                        panic!(
                            "addresses changed before online property change, addresses: {:?}",
                            got_addrs
                        );
                    }
                    let got_addrs = got_addrs
                        .iter()
                        .filter_map(
                            |&fidl_fuchsia_net_interfaces::Address {
                                 value, valid_until, ..
                             }| {
                                assert_eq!(
                                    valid_until,
                                    Some(fuchsia_zircon::sys::ZX_TIME_INFINITE)
                                );
                                match value? {
                                    fidl_fuchsia_net::InterfaceAddress::Ipv4(
                                        fidl_fuchsia_net::Ipv4AddressWithPrefix {
                                            addr: _,
                                            prefix_len: _,
                                        },
                                    ) => None,
                                    addr @ fidl_fuchsia_net::InterfaceAddress::Ipv6(_) => {
                                        Some(addr)
                                    }
                                }
                            },
                        )
                        .collect::<HashSet<_>>();
                    if got_addrs.len() == want_addr_count {
                        return futures::future::ready(async_utils::fold::FoldWhile::Done(
                            got_addrs,
                        ));
                    }
                    addresses = Some(got_addrs);
                }
                futures::future::ready(async_utils::fold::FoldWhile::Continue((
                    online_changed,
                    addresses,
                )))
            }
            event => {
                panic!("got: {:?}, want online and/or IPv6 link-local address change event", event)
            }
        }
    };
    const LL_ADDR_COUNT: usize = 1;
    let want_online = true;
    let ll_addrs = async_utils::fold::fold_while(
        blocking_stream.map(|r| r.expect("blocking event stream error")),
        (false, None),
        fold_fn(want_online, LL_ADDR_COUNT),
    )
        .await.short_circuited().unwrap_or_else(|(online_changed, addresses)| {
        panic!(
            "event stream ended unexpectedly while waiting for interface online = {} and LL addr count = {}, final state online_changed = {} addresses = {:?}",
            want_online, LL_ADDR_COUNT,
            online_changed,
            addresses
        )
    });

    let addrs = async_utils::fold::fold_while(
        stream.map(|r| r.expect("non-blocking event stream error")),
        (false, None),
        fold_fn(true, LL_ADDR_COUNT),
    )
        .await.short_circuited().unwrap_or_else(|(online_changed, addresses)| {
        panic!(
            "event stream ended unexpectedly while waiting for interface online = {} and LL addr count = {}, final state online_changed = {} addresses = {:?}",
            want_online, LL_ADDR_COUNT,
            online_changed,
            addresses
        )});
    assert_eq!(ll_addrs, addrs);
    let blocking_stream = fidl_fuchsia_net_interfaces_ext::event_stream(blocking_watcher.clone());
    futures::pin_mut!(blocking_stream);
    let stream = fidl_fuchsia_net_interfaces_ext::event_stream(watcher.clone());
    futures::pin_mut!(stream);

    // Add an address and subnet route.
    let () = assert_blocked(&mut blocking_stream).await;
    let addr_with_prefix = fidl_ip_v4_with_prefix!("192.168.0.1/16");
    let subnet = {
        let fidl_fuchsia_net::Ipv4AddressWithPrefix { addr, prefix_len } = addr_with_prefix;
        fidl_fuchsia_net::Subnet { addr: fidl_fuchsia_net::IpAddress::Ipv4(addr), prefix_len }
    };
    let _address_state_provider = interfaces::add_subnet_address_and_route_wait_assigned(
        &dev,
        subnet,
        fidl_fuchsia_net_interfaces_admin::AddressParameters::EMPTY,
    )
    .await
    .expect("add subnet address and route");
    let addresses_changed = |event| match event {
        fidl_fuchsia_net_interfaces::Event::Changed(fidl_fuchsia_net_interfaces::Properties {
            id: Some(event_id),
            addresses: Some(addresses),
            name: None,
            device_class: None,
            online: None,
            has_default_ipv4_route: None,
            has_default_ipv6_route: None,
            ..
        }) if event_id == id => addresses
            .iter()
            .filter_map(|&fidl_fuchsia_net_interfaces::Address { value, valid_until, .. }| {
                assert_eq!(valid_until, Some(fuchsia_zircon::sys::ZX_TIME_INFINITE));
                value
            })
            .collect::<HashSet<_>>(),
        event => panic!("got: {:?}, want changed event with added IPv4 address", event),
    };
    let want = ll_addrs
        .iter()
        .cloned()
        .chain(std::iter::once(fidl_fuchsia_net::InterfaceAddress::Ipv4(addr_with_prefix)))
        .collect();
    assert_eq!(addresses_changed(next(&mut blocking_stream).await), want);
    assert_eq!(addresses_changed(next(&mut stream).await), want);

    // Add a default route.
    let () = assert_blocked(&mut blocking_stream).await;
    let mut default_v4_entry = fnet_stack::ForwardingEntry {
        subnet: fidl_subnet!("0.0.0.0/0"),
        device_id: 0,
        next_hop: Some(Box::new(fidl_ip!("192.168.255.254"))),
        metric: 0,
    };
    let () = stack
        .add_forwarding_entry(&mut default_v4_entry)
        .await
        .squash_result()
        .expect("add default route");
    let want =
        fidl_fuchsia_net_interfaces::Event::Changed(fidl_fuchsia_net_interfaces::Properties {
            id: Some(id),
            has_default_ipv4_route: Some(true),
            ..fidl_fuchsia_net_interfaces::Properties::EMPTY
        });
    assert_eq!(next(&mut blocking_stream).await, want);
    assert_eq!(next(&mut stream).await, want);

    // Remove the default route.
    let () = assert_blocked(&mut blocking_stream).await;
    let () = stack
        .del_forwarding_entry(&mut default_v4_entry)
        .await
        .squash_result()
        .expect("delete default route");
    let want =
        fidl_fuchsia_net_interfaces::Event::Changed(fidl_fuchsia_net_interfaces::Properties {
            id: Some(id),
            has_default_ipv4_route: Some(false),
            ..fidl_fuchsia_net_interfaces::Properties::EMPTY
        });
    assert_eq!(next(&mut blocking_stream).await, want);
    assert_eq!(next(&mut stream).await, want);

    // Remove the added address.
    let () = assert_blocked(&mut blocking_stream).await;
    let was_removed = interfaces::remove_subnet_address_and_route(&dev, subnet)
        .await
        .expect("remove subnet address and route");
    assert!(was_removed);
    assert_eq!(addresses_changed(next(&mut blocking_stream).await), ll_addrs);
    assert_eq!(addresses_changed(next(&mut stream).await), ll_addrs);

    // Set the link to down.
    let () = assert_blocked(&mut blocking_stream).await;
    let () = dev.set_link_up(false).await.expect("bring device up");
    const LL_ADDR_COUNT_AFTER_LINK_DOWN: usize = 0;
    let want_online = false;
    let addresses = async_utils::fold::fold_while(
        blocking_stream.map(|r| r.expect("blocking event stream error")),
        (false, None),
        fold_fn(want_online, LL_ADDR_COUNT_AFTER_LINK_DOWN),
    )
        .await.short_circuited().unwrap_or_else(|(online_changed, addresses)| {
        panic!(
            "event stream ended unexpectedly while waiting for interface online = {} and LL addr count = {}, final state online_changed = {} addresses = {:?}",
            want_online, LL_ADDR_COUNT_AFTER_LINK_DOWN,
            online_changed,
            addresses
        )
    });
    assert!(addresses.is_subset(&ll_addrs), "got {:?}, want a subset of {:?}", addresses, ll_addrs);
    assert_eq!(
        async_utils::fold::fold_while(
            stream.map(|r| r.expect("non-blocking event stream error")),
            (false, None),
            fold_fn(false, LL_ADDR_COUNT_AFTER_LINK_DOWN),
        )
        .await,
        async_utils::fold::FoldResult::ShortCircuited(addresses),
    );
    let blocking_stream = fidl_fuchsia_net_interfaces_ext::event_stream(blocking_watcher);
    futures::pin_mut!(blocking_stream);
    let stream = fidl_fuchsia_net_interfaces_ext::event_stream(watcher);
    futures::pin_mut!(stream);

    // Remove the ethernet interface.
    let () = assert_blocked(&mut blocking_stream).await;
    std::mem::drop(dev);
    let want = fidl_fuchsia_net_interfaces::Event::Removed(id);
    assert_eq!(next(&mut blocking_stream).await, want);
    assert_eq!(next(&mut stream).await, want);
}
