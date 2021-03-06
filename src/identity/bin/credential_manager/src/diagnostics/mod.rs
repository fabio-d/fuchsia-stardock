// Copyright 2022 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(test)]
mod fake;
mod inspect;

#[cfg(test)]
pub use self::fake::{Event, FakeDiagnostics};
pub use self::inspect::{InspectDiagnostics, INSPECTOR};

use {fidl_fuchsia_identity_credential::CredentialError, paste::paste, std::collections::HashMap};

// Create an enum with a `name_map` method that returns a map of every value to its snake_case name.
macro_rules! mapped_enum {
    ($name:ident { $($field:ident),* }) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub enum $name {
            $(
                $field,
            )*
        }

        impl $name {
            pub fn name_map() -> HashMap<Self, &'static str> {
                paste! {
                    HashMap::from([
                        $(
                            ($name::$field, stringify!([< $field:snake >])),
                        )*
                    ])
                }
            }
        }
    }
}

mapped_enum!(IncomingMethod { AddCredential, RemoveCredential, CheckCredential });

/// A standard interface for systems that record CredentialManger events for diagnostics purposes.
pub trait Diagnostics {
    /// Records the result of an incoming CredentialManager RPC.
    fn incoming_outcome(&self, method: IncomingMethod, result: Result<(), CredentialError>);
}
