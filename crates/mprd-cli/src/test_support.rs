use std::sync::{Mutex, MutexGuard};

static ENV_LOCK: Mutex<()> = Mutex::new(());

pub(crate) struct EnvGuard {
    prev: Vec<(&'static str, Option<String>)>,
    _lock: MutexGuard<'static, ()>,
}

impl EnvGuard {
    pub(crate) fn set_many(vars: &[(&'static str, &str)]) -> Self {
        let lock = ENV_LOCK.lock().expect("env lock");
        let mut prev = Vec::with_capacity(vars.len());
        for (key, value) in vars {
            prev.push((*key, std::env::var(key).ok()));
            std::env::set_var(key, value);
        }
        Self { prev, _lock: lock }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, prev) in self.prev.drain(..) {
            if let Some(prev) = prev {
                std::env::set_var(key, prev);
            } else {
                std::env::remove_var(key);
            }
        }
    }
}
