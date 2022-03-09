// Copyright 2022 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Duplicate Address Detection.

use core::{num::NonZeroU8, time::Duration};

use net_types::{
    ip::{Ipv6, Ipv6Addr},
    MulticastAddr, UnicastAddr, Witness as _,
};
use packet::{EmptyBuf, InnerPacketBuilder as _, Serializer};
use packet_formats::icmp::ndp::{
    options::NdpOptionBuilder, NeighborSolicitation, OptionSequenceBuilder,
};

use crate::{
    context::TimerContext,
    ip::{device::state::AddressState, IpDeviceIdContext},
};

/// The number of NS messages to be sent to perform DAD [RFC 4862 section 5.1].
///
/// [RFC 4862 section 5.1]: https://tools.ietf.org/html/rfc4862#section-5.1
pub(crate) const DUP_ADDR_DETECT_TRANSMITS: u8 = 1;

/// A timer ID for duplicate address detection.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub(crate) struct DadTimerId<DeviceId> {
    pub(crate) device_id: DeviceId,
    pub(crate) addr: UnicastAddr<Ipv6Addr>,
}

/// The IP device context provided to DAD.
pub(super) trait Ipv6DeviceDadContext: IpDeviceIdContext<Ipv6> {
    /// Returns the address's state mutably, if it exists on the interface.
    fn get_address_state_mut(
        &mut self,
        device_id: Self::DeviceId,
        addr: UnicastAddr<Ipv6Addr>,
    ) -> Option<&mut AddressState>;

    /// Returns the NDP retransmission timer configured on the device.
    fn retrans_timer(&self, device_id: Self::DeviceId) -> Duration;

    /// Returns the device's link-layer address bytes, if the device supports
    /// link-layer addressing.
    fn get_link_layer_addr_bytes(&self, device_id: Self::DeviceId) -> Option<&[u8]>;
}

/// The IP layer context provided to DAD.
pub(super) trait Ipv6LayerDadContext: IpDeviceIdContext<Ipv6> {
    /// Sends an NDP Neighbor Solicitation message for DAD to the local-link.
    ///
    /// The message will be sent with the unspecified (all-zeroes) source
    /// address.
    fn send_dad_packet<S: Serializer<Buffer = EmptyBuf>>(
        &mut self,
        device_id: Self::DeviceId,
        dst_ip: MulticastAddr<Ipv6Addr>,
        message: NeighborSolicitation,
        body: S,
    ) -> Result<(), S>;
}

/// The execution context for DAD
pub(super) trait DadContext:
    Ipv6DeviceDadContext + Ipv6LayerDadContext + TimerContext<DadTimerId<Self::DeviceId>>
{
}

impl<C: Ipv6DeviceDadContext + Ipv6LayerDadContext + TimerContext<DadTimerId<C::DeviceId>>>
    DadContext for C
{
}

/// An implementation for Duplicate Address Detection.
pub(crate) trait DadHandler: IpDeviceIdContext<Ipv6> {
    /// Do duplicate address detection.
    ///
    /// # Panics
    ///
    /// Panics if tentative state for the address is not found.
    fn do_duplicate_address_detection(
        &mut self,
        device_id: Self::DeviceId,
        addr: UnicastAddr<Ipv6Addr>,
    );

    /// Stops duplicate address detection.
    ///
    /// Does nothing if DAD is not being performed on the address.
    fn stop_duplicate_address_detection(
        &mut self,
        device_id: Self::DeviceId,
        addr: UnicastAddr<Ipv6Addr>,
    );

    /// Handles a timer.
    fn handle_timer(&mut self, DadTimerId { device_id, addr }: DadTimerId<Self::DeviceId>) {
        self.do_duplicate_address_detection(device_id, addr)
    }
}

impl<C: DadContext> DadHandler for C {
    fn do_duplicate_address_detection(
        &mut self,
        device_id: Self::DeviceId,
        addr: UnicastAddr<Ipv6Addr>,
    ) {
        let state = self
            .get_address_state_mut(device_id, addr)
            .unwrap_or_else(|| panic!("expected address to exist; addr={}", addr));

        let remaining = match state {
            AddressState::Tentative { dad_transmits_remaining } => dad_transmits_remaining,
            AddressState::Assigned | AddressState::Deprecated => {
                panic!("expected address to be tentative; addr={}", addr)
            }
        };

        match remaining {
            None => {
                *state = AddressState::Assigned;
            }
            Some(non_zero_remaining) => {
                *remaining = NonZeroU8::new(non_zero_remaining.get() - 1);

                // Per RFC 4862 section 5.1,
                //
                //   DupAddrDetectTransmits ...
                //      Autoconfiguration also assumes the presence of the variable
                //      RetransTimer as defined in [RFC4861]. For autoconfiguration
                //      purposes, RetransTimer specifies the delay between
                //      consecutive Neighbor Solicitation transmissions performed
                //      during Duplicate Address Detection (if
                //      DupAddrDetectTransmits is greater than 1), as well as the
                //      time a node waits after sending the last Neighbor
                //      Solicitation before ending the Duplicate Address Detection
                //      process.
                let retrans_timer = self.retrans_timer(device_id);

                let src_ll = self.get_link_layer_addr_bytes(device_id).map(|a| a.to_vec());
                let dst_ip = addr.to_solicited_node_address();

                // TODO(https://fxbug.dev/85055): Either panic or guarantee that this error
                // can't happen statically.
                let _: Result<(), _> = self.send_dad_packet(
                    device_id,
                    dst_ip,
                    NeighborSolicitation::new(addr.get()),
                    OptionSequenceBuilder::<_>::new(
                        src_ll
                            .as_ref()
                            .map(AsRef::as_ref)
                            .map(NdpOptionBuilder::SourceLinkLayerAddress)
                            .iter(),
                    )
                    .into_serializer(),
                );

                assert_eq!(
                self.schedule_timer(retrans_timer, DadTimerId { device_id, addr }),
                None,
                "Should not have a DAD timer set when performing DAD work; addr={}, device_id={}",
                addr,
                device_id
            );
            }
        }
    }

    fn stop_duplicate_address_detection(
        &mut self,
        device_id: Self::DeviceId,
        addr: UnicastAddr<Ipv6Addr>,
    ) {
        let _: Option<C::Instant> = self.cancel_timer(DadTimerId { device_id, addr });
    }
}

#[cfg(test)]
mod tests {
    use packet_formats::icmp::ndp::{options::NdpOption, Options};

    use super::*;
    use crate::{
        context::{
            testutil::{DummyCtx, DummyTimerCtxExt as _},
            FrameContext as _, InstantContext as _,
        },
        ip::DummyDeviceId,
    };

    struct MockDadContext<'a> {
        addr: UnicastAddr<Ipv6Addr>,
        state: AddressState,
        retrans_timer: Duration,
        link_layer_bytes: Option<&'a [u8]>,
    }

    #[derive(Debug)]
    struct DadMessageMeta {
        dst_ip: MulticastAddr<Ipv6Addr>,
        message: NeighborSolicitation,
    }

    type MockCtx<'a> = DummyCtx<MockDadContext<'a>, DadTimerId<DummyDeviceId>, DadMessageMeta>;

    impl<'a> Ipv6DeviceDadContext for MockCtx<'a> {
        fn get_address_state_mut(
            &mut self,
            DummyDeviceId: DummyDeviceId,
            request_addr: UnicastAddr<Ipv6Addr>,
        ) -> Option<&mut AddressState> {
            let MockDadContext { addr, state, retrans_timer: _, link_layer_bytes: _ } =
                self.get_mut();
            (*addr == request_addr).then(|| state)
        }

        fn retrans_timer(&self, DummyDeviceId: DummyDeviceId) -> Duration {
            let MockDadContext { addr: _, state: _, retrans_timer, link_layer_bytes: _ } =
                self.get_ref();
            *retrans_timer
        }

        fn get_link_layer_addr_bytes(&self, DummyDeviceId: DummyDeviceId) -> Option<&[u8]> {
            let MockDadContext { addr: _, state: _, retrans_timer: _, link_layer_bytes } =
                self.get_ref();
            *link_layer_bytes
        }
    }

    impl<'a> Ipv6LayerDadContext for MockCtx<'a> {
        fn send_dad_packet<S: Serializer<Buffer = EmptyBuf>>(
            &mut self,
            DummyDeviceId: DummyDeviceId,
            dst_ip: MulticastAddr<Ipv6Addr>,
            message: NeighborSolicitation,
            body: S,
        ) -> Result<(), S> {
            self.send_frame(DadMessageMeta { dst_ip, message }, body)
        }
    }

    const DAD_ADDRESS: UnicastAddr<Ipv6Addr> =
        unsafe { UnicastAddr::new_unchecked(Ipv6Addr::new([0xa, 0, 0, 0, 0, 0, 0, 1])) };
    const OTHER_ADDRESS: UnicastAddr<Ipv6Addr> =
        unsafe { UnicastAddr::new_unchecked(Ipv6Addr::new([0xa, 0, 0, 0, 0, 0, 0, 2])) };

    #[test]
    #[should_panic(expected = "expected address to exist")]
    fn panic_unknown_address() {
        let mut ctx = MockCtx::with_state(MockDadContext {
            addr: DAD_ADDRESS,
            state: AddressState::Tentative { dad_transmits_remaining: None },
            retrans_timer: Duration::default(),
            link_layer_bytes: None,
        });
        DadHandler::do_duplicate_address_detection(&mut ctx, DummyDeviceId, OTHER_ADDRESS);
    }

    #[test]
    #[should_panic(expected = "expected address to be tentative")]
    fn panic_non_tentative_address() {
        let mut ctx = MockCtx::with_state(MockDadContext {
            addr: DAD_ADDRESS,
            state: AddressState::Assigned,
            retrans_timer: Duration::default(),
            link_layer_bytes: None,
        });
        DadHandler::do_duplicate_address_detection(&mut ctx, DummyDeviceId, DAD_ADDRESS);
    }

    #[test]
    fn dad_disabled() {
        let mut ctx = MockCtx::with_state(MockDadContext {
            addr: DAD_ADDRESS,
            state: AddressState::Tentative { dad_transmits_remaining: None },
            retrans_timer: Duration::default(),
            link_layer_bytes: None,
        });
        DadHandler::do_duplicate_address_detection(&mut ctx, DummyDeviceId, DAD_ADDRESS);
        let MockDadContext { addr: _, state, retrans_timer: _, link_layer_bytes: _ } =
            ctx.get_ref();
        assert_eq!(*state, AddressState::Assigned);
    }

    const DAD_TIMER_ID: DadTimerId<DummyDeviceId> =
        DadTimerId { addr: DAD_ADDRESS, device_id: DummyDeviceId };

    fn check_dad(
        ctx: &MockCtx<'_>,
        frames_len: usize,
        dad_transmits_remaining: Option<NonZeroU8>,
        retrans_timer: Duration,
        expected_sll_bytes: Option<&[u8]>,
    ) {
        let MockDadContext { addr: _, state, retrans_timer: _, link_layer_bytes: _ } =
            ctx.get_ref();
        assert_eq!(*state, AddressState::Tentative { dad_transmits_remaining });
        let frames = ctx.frames();
        assert_eq!(frames.len(), frames_len, "frames = {:?}", frames);
        let (DadMessageMeta { dst_ip, message }, frame) =
            frames.last().expect("should have transmitted a frame");

        assert_eq!(*dst_ip, DAD_ADDRESS.to_solicited_node_address());
        assert_eq!(*message, NeighborSolicitation::new(DAD_ADDRESS.get()));

        let options = Options::parse(&frame[..]).expect("parse NDP options");
        assert_eq!(
            options.iter().find_map(|o| match o {
                NdpOption::SourceLinkLayerAddress(a) => Some(a),
                _ => None,
            }),
            expected_sll_bytes
        );
        ctx.timer_ctx().assert_timers_installed([(DAD_TIMER_ID, ctx.now() + retrans_timer)]);
    }

    fn perform_dad(link_layer_bytes: Option<(&[u8], &[u8])>) {
        const DAD_TRANSMITS_REQUIRED: u8 = 2;
        const RETRANS_TIMER: Duration = Duration::from_secs(1);

        let (link_layer_bytes, expected_sll_bytes) =
            link_layer_bytes.map_or((None, None), |(a, b)| (Some(a), Some(b)));

        let mut ctx = MockCtx::with_state(MockDadContext {
            addr: DAD_ADDRESS,
            state: AddressState::Tentative {
                dad_transmits_remaining: NonZeroU8::new(DAD_TRANSMITS_REQUIRED),
            },
            retrans_timer: RETRANS_TIMER,
            link_layer_bytes,
        });
        DadHandler::do_duplicate_address_detection(&mut ctx, DummyDeviceId, DAD_ADDRESS);

        for count in 0..=1u8 {
            check_dad(
                &ctx,
                usize::from(count + 1),
                NonZeroU8::new(DAD_TRANSMITS_REQUIRED - count - 1),
                RETRANS_TIMER,
                expected_sll_bytes,
            );
            assert_eq!(ctx.trigger_next_timer(DadHandler::handle_timer), Some(DAD_TIMER_ID));
        }
        let MockDadContext { addr: _, state, retrans_timer: _, link_layer_bytes: _ } =
            ctx.get_ref();
        assert_eq!(*state, AddressState::Assigned);
    }

    #[test]
    fn stop_dad() {
        const DAD_TRANSMITS_REQUIRED: u8 = 2;
        const RETRANS_TIMER: Duration = Duration::from_secs(2);

        let mut ctx = MockCtx::with_state(MockDadContext {
            addr: DAD_ADDRESS,
            state: AddressState::Tentative {
                dad_transmits_remaining: NonZeroU8::new(DAD_TRANSMITS_REQUIRED),
            },
            retrans_timer: RETRANS_TIMER,
            link_layer_bytes: None,
        });
        DadHandler::do_duplicate_address_detection(&mut ctx, DummyDeviceId, DAD_ADDRESS);
        check_dad(&ctx, 1, NonZeroU8::new(DAD_TRANSMITS_REQUIRED - 1), RETRANS_TIMER, None);

        DadHandler::stop_duplicate_address_detection(&mut ctx, DummyDeviceId, DAD_ADDRESS);
        ctx.timer_ctx().assert_no_timers_installed();
    }

    #[test]
    fn perform_dad_no_source_link_layer_option() {
        perform_dad(None)
    }

    #[test]
    fn perform_dad_with_source_link_layer_option_short_address() {
        perform_dad(Some((
            &[1, 2, 3, 4],
            &[
                1, 2, 3, 4,
                // Padding bytes as NDP options have lengths in 8 byte
                // increments.
                0, 0,
            ],
        )))
    }

    #[test]
    fn perform_dad_with_source_link_layer_option_mac_addresss() {
        perform_dad(Some((
            &[1, 2, 3, 4, 5, 6],
            &[
                1, 2, 3, 4, 5,
                6,
                // No padding bytes as ethernet Mac address fit perfectly in an
                // NDP source link-layer address option.
            ],
        )))
    }

    #[test]
    fn perform_dad_with_source_link_layer_option_long_address() {
        perform_dad(Some((
            &[1, 2, 3, 4, 5, 6, 7, 8],
            &[
                1, 2, 3, 4, 5, 6, 7, 8,
                // Padding bytes as NDP options have lengths in 8 byte
                // increments.
                0, 0, 0, 0, 0, 0,
            ],
        )))
    }
}
