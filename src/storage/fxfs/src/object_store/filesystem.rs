// Copyright 2021 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use {
    crate::object_store::{
        allocator::Allocator,
        constants::INVALID_OBJECT_ID,
        journal::JournalCheckpoint,
        transaction::{Mutation, Transaction},
        Device, ObjectStore,
    },
    async_trait::async_trait,
    std::{
        collections::HashMap,
        sync::{Arc, RwLock},
    },
};

#[async_trait]
pub trait Filesystem: Send + Sync {
    /// Implementations should perform any required journaling and then apply the mutations via
    /// ObjectManager's apply_mutation method.
    async fn commit_transaction(&self, transaction: Transaction);

    /// Informs the journaling system that a new store has been created so that when a transaction
    /// is committed or replayed, mutations can be routed to the correct store.
    fn register_store(&self, store: &Arc<ObjectStore>);

    /// Informs the journaling system that the given object ID is about to flush in-memory data.  If
    /// successful, all mutations pertinent to this object can be discarded, but any mutations that
    /// follow will still be kept.
    fn begin_object_sync(&self, object_id: u64) -> ObjectSync;

    /// Returns access to the undeyling device.
    fn device(&self) -> Arc<dyn Device>;

    /// Returns the root store or panics if it is not available.
    fn root_store(&self) -> Arc<ObjectStore>;

    /// Returns the allocator or panics if it is not available.
    fn allocator(&self) -> Arc<dyn Allocator>;
}

pub struct ObjectManager {
    objects: RwLock<Objects>,
}

// We currently maintain strong references to all stores that have been opened, but there's no
// currently no mechanism for releasing stores that aren't being used.
struct Objects {
    stores: HashMap<u64, Arc<ObjectStore>>,
    root_parent_store_object_id: u64,
    root_store_object_id: u64,
    allocator_object_id: u64,
    allocator: Option<Arc<dyn Allocator>>,

    // Records dependencies on the journal for objects i.e. an entry for object ID 1, would mean it
    // has a dependency on journal records from that offset.
    journal_file_checkpoints: HashMap<u64, JournalCheckpoint>,
}

impl ObjectManager {
    pub fn new() -> ObjectManager {
        ObjectManager {
            objects: RwLock::new(Objects {
                stores: HashMap::new(),
                root_parent_store_object_id: INVALID_OBJECT_ID,
                root_store_object_id: INVALID_OBJECT_ID,
                allocator_object_id: INVALID_OBJECT_ID,
                allocator: None,
                journal_file_checkpoints: HashMap::new(),
            }),
        }
    }

    pub fn root_parent_store(&self) -> Arc<ObjectStore> {
        let objects = self.objects.read().unwrap();
        objects.stores.get(&objects.root_parent_store_object_id).unwrap().clone()
    }

    pub fn set_root_parent_store_object_id(&self, object_id: u64) {
        let mut objects = self.objects.write().unwrap();
        assert!(objects.stores.contains_key(&object_id));
        objects.root_parent_store_object_id = object_id;
    }

    pub fn register_store(&self, store: &Arc<ObjectStore>) {
        let mut objects = self.objects.write().unwrap();
        assert!(store.store_object_id() != objects.allocator_object_id);
        assert!(objects.stores.insert(store.store_object_id(), store.clone()).is_none());
    }

    pub fn store(&self, store_object_id: u64) -> Option<Arc<ObjectStore>> {
        self.objects.read().unwrap().stores.get(&store_object_id).cloned()
    }

    pub fn set_root_store_object_id(&self, object_id: u64) {
        let mut objects = self.objects.write().unwrap();
        assert!(objects.stores.contains_key(&object_id));
        objects.root_store_object_id = object_id;
    }

    pub fn root_store(&self) -> Arc<ObjectStore> {
        let objects = self.objects.read().unwrap();
        objects.stores.get(&objects.root_store_object_id).unwrap().clone()
    }

    pub fn set_allocator(&self, allocator: Arc<dyn Allocator>) {
        let mut objects = self.objects.write().unwrap();
        assert!(!objects.stores.contains_key(&allocator.object_id()));
        objects.allocator_object_id = allocator.object_id();
        objects.allocator = Some(allocator.clone());
    }

    pub fn allocator(&self) -> Arc<dyn Allocator> {
        self.objects.read().unwrap().allocator.clone().unwrap()
    }

    /// The journaling system should call this when a mutation needs to be applied. |replay|
    /// indicates whether this is for replay.  |checkpoint| indicates the location in the journal
    /// file for this mutation and is used to keep track of each object's dependencies on the
    /// journal.
    pub async fn apply_mutation(
        &self,
        object_id: u64,
        mutation: Mutation,
        replay: bool,
        checkpoint: &JournalCheckpoint,
    ) {
        {
            let mut objects = self.objects.write().unwrap();
            objects.journal_file_checkpoints.entry(object_id).or_insert_with(|| checkpoint.clone());
            if object_id == objects.allocator_object_id {
                Some(objects.allocator.clone().unwrap().as_apply_mutations())
            } else {
                objects.stores.get(&object_id).map(|x| x.clone() as Arc<dyn ApplyMutations>)
            }
        }
        .unwrap_or_else(|| self.root_store().lazy_open_store(object_id))
        .apply_mutation(mutation, replay)
        .await;
    }

    /// Returns the journal file offsets that each object depends on and the checkpoint for the
    /// minimum offset.
    pub fn journal_file_offsets(&self) -> (HashMap<u64, u64>, Option<JournalCheckpoint>) {
        let objects = self.objects.read().unwrap();
        let mut min_checkpoint = None;
        let mut offsets = HashMap::new();
        for (&object_id, checkpoint) in &objects.journal_file_checkpoints {
            match &mut min_checkpoint {
                None => min_checkpoint = Some(checkpoint),
                Some(ref mut min_checkpoint) => {
                    if checkpoint.file_offset < min_checkpoint.file_offset {
                        *min_checkpoint = checkpoint;
                    }
                }
            }
            offsets.insert(object_id, checkpoint.file_offset);
        }
        (offsets, min_checkpoint.cloned())
    }

    pub fn begin_object_sync(self: &Arc<Self>, object_id: u64) -> ObjectSync {
        let old_journal_file_checkpoint =
            self.objects.write().unwrap().journal_file_checkpoints.remove(&object_id);
        ObjectSync { object_manager: self.clone(), object_id, old_journal_file_checkpoint }
    }
}

/// ObjectSync is used by objects to indicate some kind of event such that if successful, existing
/// mutation records are no longer required from the journal.  For example, for object stores, it is
/// used when the in-memory layer is persisted since once that is done the records in the journal
/// are no longer required.  Clients must make sure to call the commit function upon success; the
/// default is to roll back.
#[must_use]
pub struct ObjectSync {
    object_manager: Arc<ObjectManager>,
    object_id: u64,
    old_journal_file_checkpoint: Option<JournalCheckpoint>,
}

impl ObjectSync {
    pub fn needs_sync(&self) -> bool {
        self.old_journal_file_checkpoint.is_some()
    }

    pub fn commit(mut self) {
        self.old_journal_file_checkpoint = None;
    }
}

impl Drop for ObjectSync {
    fn drop(&mut self) {
        if let Some(checkpoint) = self.old_journal_file_checkpoint.take() {
            self.object_manager
                .objects
                .write()
                .unwrap()
                .journal_file_checkpoints
                .insert(self.object_id, checkpoint);
        }
    }
}

#[async_trait]
pub trait ApplyMutations: Send + Sync {
    /// Objects that use the journaling system to track mutations should implement this trait.  This
    /// method will get called when the transaction commits, which can either be during live
    /// operation or during journal replay, in which case |replay| will be true.  Also see
    /// ObjectManager's apply_mutation method.
    async fn apply_mutation(&self, mutation: Mutation, replay: bool);
}
