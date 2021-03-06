// Copyright 2022 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use {
    crate::diagnostics::{Diagnostics, IncomingMethod},
    fidl_fuchsia_identity_credential::CredentialError,
    parking_lot::Mutex,
};

/// The different events that can be recorded through interactions with a `FakeDiagnostics`.
#[derive(Debug, PartialEq)]
pub enum Event {
    IncomingOutcome(IncomingMethod, Result<(), CredentialError>),
}

/// A fake `Diagnostics` implementation useful for verifying unittest.
pub struct FakeDiagnostics {
    /// An ordered list of the events received.
    events: Mutex<Vec<Event>>,
}

impl FakeDiagnostics {
    /// Constructs a new `FakeDiagnostics`.
    pub fn new() -> Self {
        FakeDiagnostics { events: Mutex::new(Vec::new()) }
    }

    /// Panics if the supplied slice does not match the received events.
    pub fn assert_events(&self, expected: &[Event]) {
        let actual: &[Event] = &*self.events.lock();
        assert_eq!(actual, expected);
    }
}

impl Diagnostics for FakeDiagnostics {
    fn incoming_outcome(&self, method: IncomingMethod, result: Result<(), CredentialError>) {
        self.events.lock().push(Event::IncomingOutcome(method, result));
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[fuchsia::test]
    fn log_and_assert_incoming_outcomes() {
        let diagnostics = FakeDiagnostics::new();

        diagnostics.incoming_outcome(IncomingMethod::AddCredential, Ok(()));
        diagnostics
            .incoming_outcome(IncomingMethod::RemoveCredential, Err(CredentialError::InvalidLabel));
        diagnostics.incoming_outcome(IncomingMethod::CheckCredential, Ok(()));
        diagnostics
            .incoming_outcome(IncomingMethod::AddCredential, Err(CredentialError::NoFreeLabel));

        diagnostics.assert_events(&[
            Event::IncomingOutcome(IncomingMethod::AddCredential, Ok(())),
            Event::IncomingOutcome(
                IncomingMethod::RemoveCredential,
                Err(CredentialError::InvalidLabel),
            ),
            Event::IncomingOutcome(IncomingMethod::CheckCredential, Ok(())),
            Event::IncomingOutcome(
                IncomingMethod::AddCredential,
                Err(CredentialError::NoFreeLabel),
            ),
        ]);
    }
}
