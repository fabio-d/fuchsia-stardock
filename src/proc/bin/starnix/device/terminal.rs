// Copyright 2022 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use derivative::Derivative;
use parking_lot::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Weak};

use crate::fs::devpts::*;
use crate::fs::*;
use crate::task::*;
use crate::types::*;

/// Global state of the devpts filesystem.
pub struct TTYState {
    /// The terminal objects indexed by their identifier.
    pub terminals: RwLock<HashMap<u32, Weak<Terminal>>>,

    /// The devpts filesystem.
    fs: FileSystemHandle,

    /// The set of available terminal identifier.
    pts_ids_set: Mutex<PtsIdsSet>,
}

impl TTYState {
    pub fn new(fs: FileSystemHandle) -> Self {
        Self {
            terminals: RwLock::new(HashMap::new()),
            fs,
            pts_ids_set: Mutex::new(PtsIdsSet::new(DEVPTS_COUNT)),
        }
    }

    /// Returns the next available terminal.
    pub fn get_next_terminal(self: &Arc<Self>, task: &CurrentTask) -> Result<Arc<Terminal>, Errno> {
        let id = self.pts_ids_set.lock().get()?;
        let terminal = Arc::new(Terminal::new(self.clone(), id));
        create_pts_node(&self.fs, task, id)?;
        self.terminals.write().insert(id, Arc::downgrade(&terminal));
        Ok(terminal)
    }

    /// Release the terminal identifier into the set of available identifier.
    pub fn release_terminal(&self, id: u32) -> Result<(), Errno> {
        self.pts_ids_set.lock().release(id);
        self.terminals.write().remove(&id);
        Ok(())
    }
}

/// State of a given terminal. This object handles both the main and the replica terminal.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Terminal {
    /// The global devpts state.
    #[derivative(Debug = "ignore")]
    state: Arc<TTYState>,

    /// The identifier of the terminal.
    pub id: u32,

    /// |true| is the terminal is locked.
    pub locked: RwLock<bool>,

    /// The controlling sessions for the main and replica side of the terminal.
    main_controlling_session: RwLock<Option<ControllingSession>>,
    replica_controlling_session: RwLock<Option<ControllingSession>>,
}

impl Terminal {
    pub fn new(state: Arc<TTYState>, id: u32) -> Self {
        Self {
            state,
            id,
            locked: RwLock::new(true),
            main_controlling_session: RwLock::new(None),
            replica_controlling_session: RwLock::new(None),
        }
    }

    /// Returns the controlling session of the terminal. |is_main| is used to choose whether the
    /// caller needs the controlling session of the main part of the terminal or the replica.
    pub fn get_controlling_session<'a>(
        &'a self,
        is_main: bool,
    ) -> RwLockReadGuard<'a, Option<ControllingSession>> {
        return if is_main {
            self.main_controlling_session.read()
        } else {
            self.replica_controlling_session.read()
        };
    }

    /// Returns a mutable reference to the session of the terminal. |is_main| is used to choose
    /// whether the caller needs the controlling session of the main part of the terminal or the
    /// replica.

    pub fn get_controlling_session_mut<'a>(
        &'a self,
        is_main: bool,
    ) -> RwLockWriteGuard<'a, Option<ControllingSession>> {
        return if is_main {
            self.main_controlling_session.write()
        } else {
            self.replica_controlling_session.write()
        };
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        self.state.release_terminal(self.id).unwrap()
    }
}

/// The controlling session of a terminal. Is is associated to a single side of the terminal,
/// either main or replica.
#[derive(Debug)]
pub struct ControllingSession {
    /// The controlling session.
    pub session: Weak<Session>,
    /// The foreground process group.
    pub foregound_process_group: pid_t,
}

impl ControllingSession {
    pub fn new(session: &Arc<Session>) -> Option<Self> {
        Some(Self { session: Arc::downgrade(session), foregound_process_group: session.leader })
    }

    pub fn set_foregound_process_group(&self, foregound_process_group: pid_t) -> Option<Self> {
        Some(Self { session: self.session.clone(), foregound_process_group })
    }
}

#[derive(Debug)]
struct PtsIdsSet {
    pts_count: u32,
    next_id: u32,
    reclaimed_ids: BTreeSet<u32>,
}

impl PtsIdsSet {
    pub fn new(pts_count: u32) -> Self {
        Self { pts_count, next_id: 0, reclaimed_ids: BTreeSet::new() }
    }

    pub fn release(&mut self, id: u32) {
        assert!(self.reclaimed_ids.insert(id))
    }

    pub fn get(&mut self) -> Result<u32, Errno> {
        match self.reclaimed_ids.iter().next() {
            Some(e) => {
                let value = e.clone();
                self.reclaimed_ids.remove(&value);
                Ok(value)
            }
            None => {
                if self.next_id < self.pts_count {
                    let id = self.next_id;
                    self.next_id += 1;
                    Ok(id)
                } else {
                    error!(ENOSPC)
                }
            }
        }
    }
}
