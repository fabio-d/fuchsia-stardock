// Copyright 2020 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use {
    component_events::{
        events::{Event, EventMode, EventSource, EventSubscription, Purged, Stopped},
        matcher::{EventMatcher, ExitStatusMatcher},
        sequence::{EventSequence, Ordering},
    },
    fuchsia_async::{self as fasync, futures::join},
    fuchsia_component_test::ScopedInstance,
    fuchsia_zircon::{self as zx, HandleBased},
};

/// This test invokes components which don't stop when they're told to. We
/// still expect them to be stopped when the system kills them.
#[fuchsia::test]
async fn test_stop_timeouts() {
    let event_source = EventSource::new().unwrap();
    let event_stream = event_source
        .subscribe(vec![EventSubscription::new(
            vec![Stopped::NAME, Purged::NAME],
            EventMode::Async,
        )])
        .await
        .unwrap();
    event_source.start_component_tree().await;
    let collection_name = String::from("test-collection");
    // What is going on here? A scoped dynamic instance is created and then
    // dropped. When a the instance is dropped it stops the instance.
    let target_monikers = {
        let instance = ScopedInstance::new(
            collection_name.clone(),
            String::from(concat!(
                "fuchsia-pkg://fuchsia.com/elf_runner_lifecycle_test",
                "#meta/lifecycle_timeout_unresponsive_root.cm"
            )),
        )
        .await
        .unwrap();

        // Make sure we start the root component, since it has no runtime, this
        // is sufficient.
        let _ = instance.connect_to_binder().unwrap();

        let moniker_stem = format!("./{}:{}", collection_name, instance.child_name().to_string());
        let custom_timeout_child = format!("{}/custom-timeout-child$", moniker_stem);
        let inherited_timeout_child = format!("{}/inherited-timeout-child$", moniker_stem);
        let target_monikers = [moniker_stem, custom_timeout_child, inherited_timeout_child];

        // Attempt to connect to protocols exposed from the components whose
        // stop we want to observe. Those components don't actually provide
        // these protocols, but trying to access them will force them to start
        // and once component manager fails to open the protocols from the
        // components' outgoing directories our channels will be closed.
        let (server_end, client_end) = zx::Channel::create().unwrap();
        instance
            .connect_request_to_named_protocol_at_exposed_dir("inherited-timeout-echo", server_end)
            .expect("failed to request connection");
        let client1_startup = async move {
            fasync::OnSignals::new(&client_end.into_handle(), zx::Signals::CHANNEL_PEER_CLOSED)
                .await
                .expect("failed to wait for channel close");
        };
        let (server_end, client_end) = zx::Channel::create().unwrap();
        instance
            .connect_request_to_named_protocol_at_exposed_dir("custom-timeout-echo", server_end)
            .expect("failed to request connection");
        let client2_startup = async move {
            fasync::OnSignals::new(&client_end.into_handle(), zx::Signals::CHANNEL_PEER_CLOSED)
                .await
                .expect("failed to wait for channel close");
        };

        join!(client1_startup, client2_startup);
        target_monikers
    };

    // We expect three things to stop, the root component and its two children.
    EventSequence::new()
        .all_of(
            vec![
                EventMatcher::ok()
                    .r#type(Stopped::TYPE)
                    .monikers_regex(&target_monikers)
                    .stop(Some(ExitStatusMatcher::AnyCrash)),
                EventMatcher::ok()
                    .monikers_regex(&target_monikers)
                    .stop(Some(ExitStatusMatcher::AnyCrash)),
                EventMatcher::ok()
                    .monikers_regex(&target_monikers)
                    .stop(Some(ExitStatusMatcher::AnyCrash)),
                EventMatcher::ok().r#type(Purged::TYPE).monikers_regex(&target_monikers),
                EventMatcher::ok().r#type(Purged::TYPE).monikers_regex(&target_monikers),
                EventMatcher::ok().r#type(Purged::TYPE).monikers_regex(&target_monikers),
            ],
            Ordering::Unordered,
        )
        .expect(event_stream)
        .await
        .unwrap();
}
