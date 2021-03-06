// Copyright 2020 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Error;
use fidl::endpoints::ClientEnd;
use fidl_fuchsia_testing_proxy::{TcpProxyControlMarker, TcpProxyControlProxy, TcpProxy_Marker};
use fuchsia_component::client::{connect_to_protocol, launch, launcher, App};
use fuchsia_syslog::macros::fx_log_info;
use futures::lock::Mutex;
use std::collections::HashMap;
use std::fmt::{self, Debug};

// TODO(77056) Clean up the v1 code paths once SL4F has migrated to v2 for all products.
const PROXY_V1_URL: &str = "fuchsia-pkg://fuchsia.com/sl4f#meta/data_proxy.cmx";

#[derive(Debug)]
pub struct ProxyFacade {
    internal: Mutex<Option<ProxyFacadeInternal>>,
    v1: bool,
}

impl ProxyFacade {
    pub fn new(v1: bool) -> Self {
        Self { v1, internal: Mutex::new(None) }
    }

    /// Opens an externally accessible proxy to target_port. Returns the
    /// port with which to access the proxy. In case a proxy to |target_port|
    /// is already open, the proxy is reused.
    pub async fn open_proxy(&self, target_port: u16, proxy_port: u16) -> Result<u16, Error> {
        let mut internal_lock = self.internal.lock().await;
        match *internal_lock {
            None => {
                let mut internal = ProxyFacadeInternal::new(self.v1)?;
                let result = internal.open_proxy(target_port, proxy_port).await;
                *internal_lock = Some(internal);
                result
            }
            Some(ref mut internal) => internal.open_proxy(target_port, proxy_port).await,
        }
    }

    /// Indicate that the proxy to |target_port| is no longer needed. The proxy is
    /// stopped once all clients that requested the proxy call `drop_proxy`. Note
    /// that this means the proxy may still be running after a call to `drop_proxy`.
    pub async fn drop_proxy(&self, target_port: u16) {
        if let Some(ref mut internal) = *self.internal.lock().await {
            internal.drop_proxy(target_port);
        }
    }

    /// Forcibly stop all proxies, regardless of whether or not any clients are still
    /// using them. This method is intended for cleanup after a test.
    pub async fn stop_all_proxies(&self) {
        if let Some(ref mut internal) = *self.internal.lock().await {
            internal.stop_all_proxies();
        }
    }
}

struct ProxyFacadeInternal {
    /// The launched proxy component. Kept in scope to keep the app alive.
    _app: Option<App>,
    /// Proxy used to control the data proxy.
    proxy_control: TcpProxyControlProxy,
    /// Mapping of targeted ports to open proxies.
    open_proxies: HashMap<u16, OpenProxy>,
}

struct OpenProxy {
    /// The port through which the proxy may be accessed.
    open_port: u16,
    /// Handle to the open proxy, kept in memory to keep the proxy alive.
    _proxy_handle: ClientEnd<TcpProxy_Marker>,
    /// Number of clients actively using the proxy.
    num_users: u32,
}

// Manual impl given as App does not implement Debug.
impl Debug for ProxyFacadeInternal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("ProxyFacadeInternal {:?}", self.proxy_control))
    }
}

impl ProxyFacadeInternal {
    fn new(v1: bool) -> Result<Self, Error> {
        if v1 {
            fx_log_info!("Launching proxy component as V1");
            let launcher_proxy = launcher()?;
            let app = launch(&launcher_proxy, PROXY_V1_URL.to_string(), None)?;
            let proxy_control = app.connect_to_protocol::<TcpProxyControlMarker>()?;
            Ok(Self { _app: Some(app), proxy_control, open_proxies: HashMap::new() })
        } else {
            fx_log_info!("Launching proxy component as V2");
            let proxy_control = connect_to_protocol::<TcpProxyControlMarker>()?;
            Ok(Self { _app: None, proxy_control, open_proxies: HashMap::new() })
        }
    }

    async fn open_proxy(&mut self, target_port: u16, proxy_port: u16) -> Result<u16, Error> {
        match self.open_proxies.get_mut(&target_port) {
            Some(mut proxy) => {
                proxy.num_users += 1;
                Ok(proxy.open_port)
            }
            None => {
                let (client, server) = fidl::endpoints::create_endpoints::<TcpProxy_Marker>()?;
                let open_port =
                    self.proxy_control.open_proxy_(target_port, proxy_port, server).await?;
                self.open_proxies.insert(
                    target_port,
                    OpenProxy { open_port, _proxy_handle: client, num_users: 1 },
                );
                Ok(open_port)
            }
        }
    }

    fn drop_proxy(&mut self, target_port: u16) {
        if let Some(mut proxy) = self.open_proxies.remove(&target_port) {
            proxy.num_users -= 1;
            if proxy.num_users > 0 {
                self.open_proxies.insert(target_port, proxy);
            }
        }
    }

    fn stop_all_proxies(&mut self) {
        self.open_proxies.clear();
    }
}
