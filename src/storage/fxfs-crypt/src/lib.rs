// Copyright 2022 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use {
    anyhow::{Context, Error},
    byteorder::{ByteOrder, LittleEndian},
    fidl_fuchsia_fxfs::{
        CryptCreateKeyResult, CryptManagementAddWrappingKeyResult,
        CryptManagementForgetWrappingKeyResult, CryptManagementRequest,
        CryptManagementRequestStream, CryptManagementSetActiveKeyResult, CryptRequest,
        CryptRequestStream, CryptUnwrapKeysResult, KeyPurpose,
    },
    fuchsia_zircon as zx,
    futures::stream::TryStreamExt,
    std::{
        collections::hash_map::{Entry, HashMap},
        sync::Mutex,
    },
};

pub enum Services {
    Crypt(CryptRequestStream),
    CryptManagement(CryptManagementRequestStream),
}

const WRAP_XOR: u64 = 0x012345678abcdef;

#[derive(Default)]
struct CryptServiceInner {
    keys: HashMap<u64, Vec<u8>>,
    active_data_key: Option<u64>,
    active_metadata_key: Option<u64>,
}

pub struct CryptService {
    // When set, a fake (and insecure) crypto algorithm is used, which ignores the keys provided by
    // CryptManagement and instead uses a hard-coded "key".
    use_legacy_stubbed_crypto: bool,
    inner: Mutex<CryptServiceInner>,
}

impl CryptService {
    pub fn new(use_legacy_stubbed_crypto: bool) -> Self {
        Self { use_legacy_stubbed_crypto, inner: Mutex::new(CryptServiceInner::default()) }
    }

    fn create_key(&self, owner: u64, _purpose: KeyPurpose) -> CryptCreateKeyResult {
        if self.use_legacy_stubbed_crypto {
            self.create_key_legacy(owner)
        } else {
            // TODO(fxbug.dev/94587): Implement real crypto.
            unimplemented!()
        }
    }

    fn create_key_legacy(&self, owner: u64) -> CryptCreateKeyResult {
        let mut key = [0; 32];
        zx::cprng_draw(&mut key);
        let mut wrapped = [0; 32];
        for (i, chunk) in key.chunks_exact(8).enumerate() {
            LittleEndian::write_u64(
                &mut wrapped[i * 8..i * 8 + 8],
                LittleEndian::read_u64(chunk) ^ WRAP_XOR ^ owner,
            );
        }
        Ok((0, wrapped.into(), key.into()))
    }

    fn unwrap_keys(
        &self,
        wrapping_key_id: u64,
        owner: u64,
        keys: Vec<Vec<u8>>,
    ) -> CryptUnwrapKeysResult {
        if self.use_legacy_stubbed_crypto {
            self.unwrap_keys_legacy(wrapping_key_id, owner, keys)
        } else {
            unimplemented!()
        }
    }

    fn unwrap_keys_legacy(
        &self,
        wrapping_key_id: u64,
        owner: u64,
        keys: Vec<Vec<u8>>,
    ) -> CryptUnwrapKeysResult {
        assert_eq!(wrapping_key_id, 0, "Key ID must be 0 for legacy keys.");
        let mut unwrapped_keys = Vec::new();
        for key in keys {
            let mut unwrapped = [0; 32];
            for (chunk, mut unwrapped) in key.chunks_exact(8).zip(unwrapped.chunks_exact_mut(8)) {
                LittleEndian::write_u64(
                    &mut unwrapped,
                    LittleEndian::read_u64(chunk) ^ WRAP_XOR ^ owner,
                );
            }
            unwrapped_keys.push(unwrapped.into());
        }
        Ok(unwrapped_keys)
    }

    fn add_wrapping_key(
        &self,
        wrapping_key_id: u64,
        key: Vec<u8>,
    ) -> CryptManagementAddWrappingKeyResult {
        let mut inner = self.inner.lock().unwrap();
        match inner.keys.entry(wrapping_key_id) {
            Entry::Occupied(_) => Err(zx::Status::ALREADY_EXISTS.into_raw()),
            Entry::Vacant(vacant) => {
                log::info!("Adding wrapping key {}", wrapping_key_id);
                vacant.insert(key);
                Ok(())
            }
        }
    }

    fn set_active_key(
        &self,
        purpose: KeyPurpose,
        wrapping_key_id: u64,
    ) -> CryptManagementSetActiveKeyResult {
        let mut inner = self.inner.lock().unwrap();
        if !inner.keys.contains_key(&wrapping_key_id) {
            return Err(zx::Status::NOT_FOUND.into_raw());
        }
        match purpose {
            KeyPurpose::Data => inner.active_data_key = Some(wrapping_key_id),
            KeyPurpose::Metadata => inner.active_metadata_key = Some(wrapping_key_id),
            _ => return Err(zx::Status::INVALID_ARGS.into_raw()),
        }
        Ok(())
    }

    fn forget_wrapping_key(&self, wrapping_key_id: u64) -> CryptManagementForgetWrappingKeyResult {
        log::info!("Removing wrapping key {}", wrapping_key_id);
        let mut inner = self.inner.lock().unwrap();
        if let Some(id) = &inner.active_data_key {
            if *id == wrapping_key_id {
                return Err(zx::Status::INVALID_ARGS.into_raw());
            }
        }
        if let Some(id) = &inner.active_metadata_key {
            if *id == wrapping_key_id {
                return Err(zx::Status::INVALID_ARGS.into_raw());
            }
        }
        inner.keys.remove(&wrapping_key_id);
        Ok(())
    }

    pub async fn handle_request(&self, stream: Services) -> Result<(), Error> {
        match stream {
            Services::Crypt(mut stream) => {
                while let Some(request) = stream.try_next().await.context("Reading request")? {
                    match request {
                        CryptRequest::CreateKey { owner, purpose, responder } => {
                            let mut response = self.create_key(owner, purpose);
                            responder.send(&mut response).unwrap_or_else(|e| {
                                log::error!("Failed to send CreateKey response: {:?}", e)
                            });
                        }
                        CryptRequest::UnwrapKeys { wrapping_key_id, owner, keys, responder } => {
                            let mut response = self.unwrap_keys(wrapping_key_id, owner, keys);
                            responder.send(&mut response).unwrap_or_else(|e| {
                                log::error!("Failed to send UnwrapKeys response: {:?}", e)
                            });
                        }
                    }
                }
            }
            Services::CryptManagement(mut stream) => {
                while let Some(request) = stream.try_next().await.context("Reading request")? {
                    match request {
                        CryptManagementRequest::AddWrappingKey {
                            wrapping_key_id,
                            key,
                            responder,
                        } => {
                            let mut response = self.add_wrapping_key(wrapping_key_id, key);
                            responder.send(&mut response).unwrap_or_else(|e| {
                                log::error!("Failed to send AddWrappingKey response: {:?}", e)
                            });
                        }
                        CryptManagementRequest::SetActiveKey {
                            purpose,
                            wrapping_key_id,
                            responder,
                        } => {
                            let mut response = self.set_active_key(purpose, wrapping_key_id);
                            responder.send(&mut response).unwrap_or_else(|e| {
                                log::error!("Failed to send SetActiveKey response: {:?}", e)
                            });
                        }
                        CryptManagementRequest::ForgetWrappingKey {
                            wrapping_key_id,
                            responder,
                        } => {
                            let mut response = self.forget_wrapping_key(wrapping_key_id);
                            responder.send(&mut response).unwrap_or_else(|e| {
                                log::error!("Failed to send ForgetWrappingKey response: {:?}", e)
                            });
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use {super::CryptService, fidl_fuchsia_fxfs::KeyPurpose};

    #[test]
    fn wrap_unwrap_legacy_key() {
        let service = CryptService::new(true);
        let (wrapping_key_id, wrapped, unwrapped) =
            service.create_key(0, KeyPurpose::Data).expect("create_key failed");
        let unwrap_result =
            service.unwrap_keys(wrapping_key_id, 0, vec![wrapped]).expect("unwrap_key failed");
        assert_eq!(unwrap_result, vec![unwrapped]);
    }

    #[test]
    fn unwrap_legacy_key_wrong_key() {
        let service = CryptService::new(true);
        let (wrapping_key_id, mut wrapped, unwrapped) =
            service.create_key(0, KeyPurpose::Data).expect("create_key failed");
        for byte in &mut wrapped {
            *byte ^= 0xff;
        }
        let unwrap_result =
            service.unwrap_keys(wrapping_key_id, 0, vec![wrapped]).expect("unwrap_key failed");
        assert_ne!(unwrap_result, vec![unwrapped]);
    }

    #[test]
    fn add_forget_key() {
        let service = CryptService::new(true);
        let key = vec![0xABu8; 32];
        service.add_wrapping_key(0, key.clone()).expect("add_key failed");
        service.add_wrapping_key(0, key.clone()).expect_err("add_key should fail on a used slot");
        service.add_wrapping_key(1, key.clone()).expect("add_key failed");

        service.forget_wrapping_key(0).expect("forget_key failed");

        service.add_wrapping_key(0, key.clone()).expect("add_key failed");
    }

    #[test]
    fn set_active_key() {
        let service = CryptService::new(true);
        let key = vec![0xABu8; 32];

        service
            .set_active_key(KeyPurpose::Data, 0)
            .expect_err("set_active_key should fail when targeting nonexistent keys");

        service.add_wrapping_key(0, key.clone()).expect("add_key failed");
        service.add_wrapping_key(1, key.clone()).expect("add_key failed");

        service.set_active_key(KeyPurpose::Data, 0).expect("set_active_key failed");
        service.set_active_key(KeyPurpose::Metadata, 1).expect("set_active_key failed");

        service.forget_wrapping_key(0).expect_err("forget_key should fail on an active key");
        service.forget_wrapping_key(1).expect_err("forget_key should fail on an active key");
    }
}
