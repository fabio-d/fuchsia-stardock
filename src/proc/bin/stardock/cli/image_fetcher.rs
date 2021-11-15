// Copyright 2021 Fabio D'Urso. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::{Context, Error};
use fidl_fuchsia_net_http as fnethttp;
use fidl_fuchsia_stardock as fstardock;
use fuchsia_async as fasync;
use futures::io::AsyncReadExt;
use futures::TryStreamExt;
use lazy_static::lazy_static;
use regex::Regex;
use serde_json::Value;
use stardock_common::digest;
use std::collections::HashMap;

const MANIFEST_ACCEPT_HEADER: &str = "application/vnd.docker.distribution.manifest.v2+json";

/// FIDL server that fetches parts of an image from a public registry.
///
/// Note: Even if the registry is public, it might be necessary to obtain a token (e.g.
/// https://docs.docker.com/registry/spec/auth/token/) to download data. This is the
/// reason why methods in this struct have to deal with autorization too.
pub struct ImageFetcher {
    base_url: String,
    image_reference: String,
    http_loader: fnethttp::LoaderProxy,
    authorization_header: Option<String>,
}

impl ImageFetcher {
    pub fn new(
        http_loader: fnethttp::LoaderProxy,
        base_url: &str,
        image_reference: &str,
    ) -> ImageFetcher {
        ImageFetcher {
            base_url: base_url.to_string(),
            image_reference: image_reference.to_string(),
            http_loader,
            authorization_header: None,
        }
    }

    async fn http_authorize(
        &mut self,
        www_authenticate_header: &str,
    ) -> Result<(), Error> {
        let mut params = parse_challenge(www_authenticate_header)?;
        let realm = params.remove("realm").ok_or(anyhow::anyhow!("Missing \"realm\" parameter"))?;
        let service = params.remove("service").ok_or(anyhow::anyhow!("Missing \"service\" parameter"))?;
        let scope = params.remove("scope").ok_or(anyhow::anyhow!("Missing \"scope\" parameter"))?;

        // Build the request
        // TODO: proper escaping
        let url = format!("{}?service={}&scope={}", realm, service, scope);
        let request = fnethttp::Request { url: Some(url), ..fnethttp::Request::EMPTY };

        // Execute it
        let response = self.http_loader.fetch(request).await?;
        if let Some(error) = response.error {
            anyhow::bail!("HTTP error: {:?}", error);
        }

        // Read and parse response as JSON
        let body =
            if let (Some(status_code), Some(body)) = (response.status_code, response.body) {
                if status_code == 200 {
                    let mut data = Vec::new();
                    // FIXME: this reads the socket into an unbounded buffer, potentially exhausting
                    // this process' memory
                    fasync::Socket::from_socket(body)?.read_to_end(&mut data).await?;
                    serde_json::from_slice::<Value>(&data)?
                } else {
                    anyhow::bail!("HTTP error: code {}", status_code);
                }
            } else {
                anyhow::bail!("HTTP error: response lacks status_code and/or body");
            };

        // Extract "token" or "access_token" value (at least one of them must be present)
        let token =
            if let Value::String(ref text) = body["token"] {
                text
            } else if let Value::String(ref text) = body["access_token"] {
                text
            } else {
                anyhow::bail!("Missing token/access_token in JSON response")
            };

        // Success!
        self.authorization_header = Some(format!("Bearer {}", token));
        Ok(())
    }

    async fn http_open_url(
        &mut self,
        url: &str,
        accept_header: Option<&str>,
    ) -> Result<fidl::Socket, Error> {
        // Try to get the requested resource. If a "401 Unauthorized" HTTP status code
        // is received, call the authorization service and try again.
        for authorization_already_attempted in vec![false, true] {
            // Build the request
            let mut request =
                fnethttp::Request { url: Some(url.to_string()), ..fnethttp::Request::EMPTY };
            if let Some(value) = accept_header {
                add_header(&mut request.headers, "accept", value);
            }
            if let Some(ref value) = self.authorization_header {
                add_header(&mut request.headers, "authorization", value.as_str());
            }

            // Execute it
            let response = self.http_loader.fetch(request).await?;
            if let Some(error) = response.error {
                anyhow::bail!("HTTP error: {:?}", error);
            }

            // Process response headers
            if let (Some(status_code), Some(body)) = (response.status_code, response.body) {
                // Did we get "401 Unauthorized" for the first attempt?
                if status_code == 401 && !authorization_already_attempted {
                    // Return error if the WWW-Authenticate header is not present or if the
                    // authorization call fails
                    self.http_authorize(
                        get_header(&response.headers, "www-authenticate")
                            .context("Failed to process 401 response")?
                            .as_str(),
                    ).await.context("Authorization failed")?;

                    // Proceed to the second iteration, knowing that now we have a token
                    assert!(self.authorization_header.is_some());
                } else if status_code == 200 {
                    return Ok(body);
                } else {
                    anyhow::bail!("HTTP error: code {}", status_code);
                }
            } else {
                anyhow::bail!("HTTP error: response lacks status_code and/or body");
            }
        }

        unreachable!();
    }

    async fn fetch_manifest(
        &mut self,
    ) -> Result<fidl::Socket, Error> {
        let manifest_url = format!("{}/manifests/{}", self.base_url, self.image_reference);
        self.http_open_url(&manifest_url, Some(MANIFEST_ACCEPT_HEADER)).await
    }

    async fn fetch_blob(
        &mut self,
        digest: &digest::Sha256Digest,
    ) -> Result<fidl::Socket, Error> {
        let blob_url = format!("{}/blobs/sha256:{}", self.base_url, digest.as_str());
        self.http_open_url(&blob_url, None).await
    }

    pub async fn handle_client(
        &mut self,
        mut stream: fstardock::ImageFetcherRequestStream,
    ) -> Result<(), Error> {
        while let Some(request) = stream.try_next().await? {
            match request {
                fstardock::ImageFetcherRequest::FetchManifest { responder } => {
                    eprintln!("Fetching manifest...");

                    match self.fetch_manifest().await {
                        Ok(socket) => {
                            responder.send(Some(socket))?;
                        }
                        Err(e) => {
                            eprintln!("Failed to fetch manifest: {}", e);
                            responder.send(None)?;
                        }
                    };
                }
                fstardock::ImageFetcherRequest::FetchBlob { digest, responder } => {
                    let digest = digest.parse::<digest::Sha256Digest>()?;
                    eprintln!("Fetching blob {}...", digest.as_str());

                    match self.fetch_blob(&digest).await {
                        Ok(socket) => {
                            responder.send(Some(socket))?;
                        }
                        Err(e) => {
                            eprintln!("Failed to fetch blob {}: {}", digest.as_str(), e);
                            responder.send(None)?;
                        }
                    };
                }
            }
        }

        Ok(())
    }
}

/// Append new header to a FIDL vector of headers
fn add_header(headers: &mut Option<Vec<fnethttp::Header>>, name: &str, value: &str) {
    let new_header = fnethttp::Header {
        name: name.as_bytes().to_vec(),
        value: value.as_bytes().to_vec(),
    };

    if let Some(ref mut vec_ref) = headers {
        vec_ref.push(new_header);
    } else {
        *headers = Some(vec![new_header]);
    }
}

/// Find by name in a FIDL vector of headers
fn get_header(headers: &Option<Vec<fnethttp::Header>>, name: &str) -> Result<String, Error> {
    let name_encoded = name.as_bytes();

    if let Some(headers) = headers {
        for fnethttp::Header { name: name_bytes, value: value_bytes } in headers {
            if name_bytes == name_encoded {
                let value = String::from_utf8(value_bytes.clone())
                    .context(format!("Failed to parse {} header", name))?;
                return Ok(value);
            }
        }
    }

    anyhow::bail!("Failed to find {} header", name);
}

/// Decode www-authenticate challenge parameters
fn parse_challenge(header_value: &str) -> Result<HashMap<String, String>, Error> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r#"([_a-z]+)="([^"]*)"(,?)"#).unwrap();
    }

    if !header_value.starts_with("Bearer ") {
        anyhow::bail!("Unexpected challenge type");
    }

    let params = &header_value[7..];
    let mut result = HashMap::new();

    let parse_err = anyhow::anyhow!("Parse error");
    let mut previous_end = 0;
    let mut ready_for_another = true;
    for param in RE.captures_iter(params) {
        if let (Some(all_group), Some(name_group), Some(value_group), Some(comma_group)) =
            (param.get(0), param.get(1), param.get(2), param.get(3)) {

            if all_group.start() != previous_end || !ready_for_another {
                return Err(parse_err);
            }

            previous_end = all_group.end();
            ready_for_another = comma_group.as_str() == ",";

            result.insert(name_group.as_str().to_string(), value_group.as_str().to_string());
        } else {
            return Err(parse_err);
        }
    }

    if params.len() != previous_end || ready_for_another {
        return Err(parse_err);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::{add_header, parse_challenge, ImageFetcher, MANIFEST_ACCEPT_HEADER};
    use anyhow::Error;
    use fidl::endpoints::create_proxy_and_stream;
    use fidl_fuchsia_net_http as fnethttp;
    use fuchsia_async as fasync;
    use futures::io::AsyncWriteExt;
    use futures::TryStreamExt;
    use matches::assert_matches;
    use std::collections::HashMap;
    use test_case::test_case;

    // Valid input
    #[test_case(
        r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/hello-world:pull""#,
        vec![
            ("realm", "https://auth.docker.io/token"),
            ("service", "registry.docker.io"),
            ("scope", "repository:library/hello-world:pull")
        ];
        "valid, pull only"
    )]
    #[test_case(
        r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/hello-world:pull,push""#,
        vec![
            ("realm", "https://auth.docker.io/token"),
            ("service", "registry.docker.io"),
            ("scope", "repository:library/hello-world:pull,push")
        ];
        "valid, pull and push"
    )]
    #[test_case(
        r#"Bearer realm="example",error="invalid_token",error_description="The access token expired""#,
        vec![
            ("realm", "example"),
            ("error", "invalid_token"),
            ("error_description", "The access token expired")
        ];
        "valid, from IETF RFC 6750"
    )]
    fn parse_challenge_ok(text: &str, expect: Vec<(&str, &str)>) {
        let mut expect_owned = HashMap::new();
        for (k, v) in expect {
            expect_owned.insert(k.to_string(), v.to_string());
        }

        assert_eq!(
            parse_challenge(text).unwrap(),
            expect_owned
        );
    }

    // Bad input
    #[test_case(r#""#; "empty string")]
    #[test_case(r#"Bearer "#; "Bearer only")]
    #[test_case(r#"Bearer ,realm="https://auth.docker.io/token""#; "Extra comma at start")]
    #[test_case(r#"Bearer realm="https://auth.docker.io/token","#; "Extra comma at end")]
    #[test_case(r#"Bearer -realm="https://auth.docker.io/token""#; "Invalid char at start")]
    #[test_case(r#"Bearer realm="https://auth.docker.io/token"-"#; "Invalid char at end")]
    #[test_case(r#"Bearer realm="https://auth.docker.io/token",,service="registry.docker.io""#; "Extra comma between")]
    #[test_case(r#"Bearer realm="https://auth.docker.io/token"-,service="registry.docker.io""#; "Bad char between")]
    #[test_case(r#"Bearer realm=https://auth.docker.io/token""#; "Missing start quote")]
    #[test_case(r#"Bearer realm="https://auth.docker.io/token"#; "Missing end quote")]
    #[test_case(r#"Bearer realm"https://auth.docker.io/token"#; "Missing equal sign")]
    #[test_case(r#"Bearer ="https://auth.docker.io/token"#; "Missing key")]
    fn parse_challenge_err(text: &str) {
        assert_matches!(
            parse_challenge(text),
            Err(_)
        );
    }

    /// Helper function to generate a mock HTTP Loader
    ///
    /// Return value: a proxy to interact with it and a future to serve it
    fn mock_http_loader(
        expected_requests_with_responses: Vec<(fnethttp::Request, fnethttp::Response)>,
    ) -> (fnethttp::LoaderProxy, impl futures::Future) {
        let (http_loader, mut stream) =
            create_proxy_and_stream::<fnethttp::LoaderMarker>().unwrap();

        let serve_fut = async move {
            // Expect each request and respond to it
            for (expected_request, canned_response) in expected_requests_with_responses {
                match stream.try_next().await {
                    Ok(Some(fnethttp::LoaderRequest::Fetch { request, responder })) => {
                        assert_eq!(expected_request, request);

                        let send_result = responder.send(canned_response);
                        assert_matches!(send_result, Ok(_));
                    }

                    other => {
                        panic!("Got {:?}, expected fetch request {:?}", other, expected_request)
                    }
                }
            }

            // There should be no more requests
            assert_matches!(stream.try_next().await, Ok(None));
        };

        (http_loader, serve_fut)
    }

    /// Helper function to generate a readable socket with canned data
    fn mock_body_socket(body_text: &str) -> fidl::Socket {
        let (r, w) = fidl::Socket::create(fidl::SocketOpts::empty()).unwrap();

        let body_vec = body_text.as_bytes().to_vec();
        let mut async_w = fasync::Socket::from_socket(w).unwrap();

        fasync::Task::local(async move {
            async_w.write_all(&body_vec).await.expect("Failed to write to socket");
        })
        .detach();

        r
    }

    // Test fetching a manifest and a blob from a registry requiring no authorization
    #[fasync::run_singlethreaded(test)]
    async fn test_fetcher_no_auth() -> Result<(), Error> {
        let (http_loader, mock_fut) = mock_http_loader(vec![
            // Fetch manifest -> Success
            (
                fnethttp::Request {
                    url: Some("https://registry.example.com/v2/library/example/manifests/latest".to_string()),
                    headers: {
                        let mut headers = None;
                        add_header(&mut headers, "accept", MANIFEST_ACCEPT_HEADER);
                        headers
                    },
                    ..fnethttp::Request::EMPTY
                },
                fnethttp::Response {
                    status_code: Some(200),
                    body: Some(mock_body_socket("baz")),
                    ..fnethttp::Response::EMPTY
                },
            ),
            // Fetch blob -> Success
            (
                fnethttp::Request {
                    url: Some("https://registry.example.com/v2/library/example/blobs/sha256:4f5543c9f7580bd5bdb2fb111c1c6941f81599b865c9bcd396c5f39125189a26".to_string()),
                    ..fnethttp::Request::EMPTY
                },
                fnethttp::Response {
                    status_code: Some(200),
                    body: Some(mock_body_socket("baz")),
                    ..fnethttp::Response::EMPTY
                },
            ),
        ]);

        let mut sut = ImageFetcher::new(
            http_loader,
            "https://registry.example.com/v2/library/example",
            "latest",
        );

        let test_fut = async move {
            assert_matches!(sut.fetch_manifest().await, Ok(_));

            let blob_digest =
                "4f5543c9f7580bd5bdb2fb111c1c6941f81599b865c9bcd396c5f39125189a26"
                .parse().unwrap();

            assert_matches!(sut.fetch_blob(&blob_digest).await, Ok(_));
        };

        futures::join!(test_fut, mock_fut);
        Ok(())
    }

    // Test fetching a manifest from a registry requiring authorization
    #[fasync::run_singlethreaded(test)]
    async fn test_fetcher_with_auth() -> Result<(), Error> {
        let (http_loader, mock_fut) = mock_http_loader(vec![
            // Fetch manifest -> Unauthorized
            (
                fnethttp::Request {
                    url: Some("https://registry.example.com/v2/library/example/manifests/latest".to_string()),
                    headers: {
                        let mut headers = None;
                        add_header(&mut headers, "accept", MANIFEST_ACCEPT_HEADER);
                        headers
                    },
                    ..fnethttp::Request::EMPTY
                },
                fnethttp::Response {
                    status_code: Some(401),
                    headers: {
                        let mut headers = None;
                        add_header(&mut headers, "www-authenticate", r#"Bearer realm="https://auth.example.com/gen",service="foo",scope="bar""#);
                        headers
                    },
                    body: Some(mock_body_socket("baz")),
                    ..fnethttp::Response::EMPTY
                },
            ),
            // Authorization request -> Success
            (
                fnethttp::Request {
                    url: Some("https://auth.example.com/gen?service=foo&scope=bar".to_string()),
                    ..fnethttp::Request::EMPTY
                },
                fnethttp::Response {
                    status_code: Some(200),
                    headers: {
                        let mut headers = None;
                        add_header(&mut headers, "content-type", "application/json");
                        headers
                    },
                    body: Some(mock_body_socket(r#"{"token":"dG9rZW4=", "access_token":"dG9rZW4="}"#)),
                    ..fnethttp::Response::EMPTY
                },
            ),
            // Fetch manifest -> Success
            (
                fnethttp::Request {
                    url: Some("https://registry.example.com/v2/library/example/manifests/latest".to_string()),
                    headers: {
                        let mut headers = None;
                        add_header(&mut headers, "accept", MANIFEST_ACCEPT_HEADER);
                        add_header(&mut headers, "authorization", "Bearer dG9rZW4=");
                        headers
                    },
                    ..fnethttp::Request::EMPTY
                },
                fnethttp::Response {
                    status_code: Some(200),
                    body: Some(mock_body_socket("baz")),
                    ..fnethttp::Response::EMPTY
                },
            ),
        ]);

        let mut sut = ImageFetcher::new(
            http_loader,
            "https://registry.example.com/v2/library/example",
            "latest",
        );

        let test_fut = async move {
            assert_matches!(sut.fetch_manifest().await, Ok(_));
        };

        futures::join!(test_fut, mock_fut);
        Ok(())
    }
}
