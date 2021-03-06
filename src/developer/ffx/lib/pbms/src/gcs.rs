// Copyright 2022 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Access utilities for gcs metadata.

use {
    anyhow::{anyhow, bail, Context, Result},
    errors::ffx_bail,
    gcs::{
        client::ClientFactory,
        gs_url::split_gs_url,
        token_store::{
            auth_code_to_refresh, get_auth_code, read_boto_refresh_token, write_boto_refresh_token,
            GcsError, TokenStore,
        },
    },
    std::{
        io::Write,
        path::{Path, PathBuf},
    },
};

/// Download from a given `gcs_url`.
///
/// `gcs_url` is the full GCS url, e.g. "gs://bucket/path/to/file".
/// The resulting data will be written to a directory at `local_dir`.
pub(crate) async fn fetch_from_gcs<W>(
    gcs_url: &str,
    local_dir: &Path,
    verbose: bool,
    writer: &mut W,
) -> Result<()>
where
    W: Write + Sync,
{
    let no_auth = TokenStore::new_without_auth();
    let client_factory = ClientFactory::new(no_auth);
    let client = client_factory.create_client();
    let (bucket, gcs_path) = split_gs_url(gcs_url).context("Splitting gs URL.")?;
    if !client.fetch_all(bucket, gcs_path, &local_dir, verbose, writer).await.is_ok() {
        fetch_from_gcs_with_auth(bucket, gcs_path, local_dir, verbose, writer)
            .await
            .context("fetch with auth")?;
    }
    Ok(())
}

/// Download from a given `gcs_url` using auth.
///
/// Fallback from using `fetch_from_gcs()` without auth.
async fn fetch_from_gcs_with_auth<W>(
    gcs_bucket: &str,
    gcs_path: &str,
    local_dir: &Path,
    verbose: bool,
    writer: &mut W,
) -> Result<()>
where
    W: Write + Sync,
{
    // TODO(fxb/89584): Change to using ffx client Id and consent screen.
    let boto: Option<PathBuf> =
        ffx_config::get("flash.gcs.token").await.context("getting flash.gcs.token config value")?;
    let boto_path = match boto {
        Some(boto_path) => boto_path,
        None => ffx_bail!(
            "GCS authentication configuration value \"flash.gcs.token\" not \
            found. Set this value by running `ffx config set flash.gcs.token <path>` \
            to the path of the .boto file."
        ),
    };
    if !boto_path.is_file() {
        update_refresh_token(&boto_path).await.context("Set up refresh token")?
    }
    loop {
        let auth = TokenStore::new_with_auth(
            read_boto_refresh_token(&boto_path)
                .context("read boto refresh")?
                .ok_or(anyhow!("Could not read boto token store"))?,
            /*access_token=*/ None,
        )?;

        let client_factory = ClientFactory::new(auth);
        let client = client_factory.create_client();
        match client
            .fetch_all(gcs_bucket, gcs_path, &local_dir, verbose, writer)
            .await
            .context("fetch all")
        {
            Ok(()) => break,
            Err(e) => match e.downcast_ref::<GcsError>() {
                Some(GcsError::NeedNewRefreshToken) => {
                    update_refresh_token(&boto_path).await.context("Updating refresh token")?
                }
                Some(GcsError::NotFound(b, p)) => {
                    writeln!(writer, "[gs://{}/{} not found]", b, p)?;
                    break;
                }
                Some(_) | None => bail!(
                    "Cannot get product bundle container while \
                     downloading from gs://{}/{}, saving to {:?}, error {:?}",
                    gcs_bucket,
                    gcs_path,
                    local_dir,
                    e,
                ),
            },
        }
    }
    Ok(())
}

/// Prompt the user to visit the OAUTH2 permissions web page and enter a new
/// authorization code, then convert that to a refresh token and write that
/// refresh token to the ~/.boto file.
async fn update_refresh_token(boto_path: &Path) -> Result<()> {
    println!("\nThe refresh token in the {:?} file needs to be updated.", boto_path);
    let auth_code = get_auth_code()?;
    let refresh_token = auth_code_to_refresh(&auth_code).await.context("get refresh token")?;
    write_boto_refresh_token(boto_path, &refresh_token)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use {super::*, tempfile::NamedTempFile};

    // TODO(fxbug.dev/92773): This test requires mocks for interactivity and
    // https. The test is currently disabled.
    #[ignore]
    #[fuchsia_async::run_singlethreaded(test)]
    async fn test_update_refresh_token() {
        let temp_file = NamedTempFile::new().expect("temp file");
        update_refresh_token(&temp_file.path()).await.expect("set refresh token");
    }
}
