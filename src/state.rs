use parking_lot::RwLock;
use std::sync::Arc;

use crate::auth::SessionStore;
use crate::db::{normalize_base_path, Database};
use crate::monitor::RuntimeMonitor;
use crate::process::ShoesProcessManager;

pub struct AppState {
    pub db: Arc<Database>,
    pub proc_mgr: Arc<ShoesProcessManager>,
    pub monitor: Arc<RuntimeMonitor>,
    pub sessions: SessionStore,
    pub base_path: RwLock<String>,
}

impl AppState {
    pub fn new(
        db: Arc<Database>,
        proc_mgr: Arc<ShoesProcessManager>,
        monitor: Arc<RuntimeMonitor>,
    ) -> Arc<Self> {
        let bp = db
            .get_settings()
            .map(|s| normalize_base_path(&s.panel_base_path))
            .unwrap_or_else(|_| "/".to_string());
        Arc::new(Self {
            db,
            proc_mgr,
            monitor,
            sessions: SessionStore::default(),
            base_path: RwLock::new(bp),
        })
    }

    pub fn get_base_path(&self) -> String {
        self.base_path.read().clone()
    }

    pub fn set_base_path(&self, p: &str) {
        *self.base_path.write() = normalize_base_path(p);
    }
}
