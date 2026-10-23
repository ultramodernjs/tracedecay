//! The clock behind every exact SQL deadline: statement execution and the
//! transaction idle and absolute leases.
//!
//! Production reads the monotonic wall clock. Under `cfg(test)` every thread
//! reads a [`FakeClock`] that stands still until a test moves it: expiry tests
//! drive the production limits deterministically, and no other test can
//! expire because the machine running it was loaded.

#[cfg(not(any(test, feature = "test-runtime")))]
pub(super) fn now() -> std::time::Instant {
    std::time::Instant::now()
}

#[cfg(any(test, feature = "test-runtime"))]
pub(super) use fake::now;

#[cfg(any(test, feature = "test-runtime"))]
pub(super) mod fake {
    use std::{
        cell::RefCell,
        sync::{Arc, Mutex, PoisonError},
        time::{Duration, Instant},
    };

    thread_local! {
        static INSTALLED: RefCell<Option<Arc<FakeClock>>> = const { RefCell::new(None) };
    }

    /// This thread's installed clock. A thread with none gets a frozen one,
    /// so no test's exact SQL deadline passes because the machine was slow.
    pub(in crate::exact_sql) fn now() -> Instant {
        INSTALLED.with(|installed| {
            #[cfg(test)]
            return installed
                .borrow_mut()
                .get_or_insert_with(FakeClock::frozen)
                .read();
            #[cfg(not(test))]
            installed
                .borrow()
                .as_ref()
                .map_or_else(Instant::now, |clock| clock.read())
        })
    }

    /// A shared clock that moves only when a test moves it, or by a fixed
    /// tick on every read.
    pub(in crate::exact_sql) struct FakeClock {
        #[cfg(test)]
        started: Instant,
        now: Mutex<Instant>,
        tick: Duration,
    }

    impl FakeClock {
        #[cfg(test)]
        pub(in crate::exact_sql) fn frozen() -> Arc<Self> {
            Self::ticking(Duration::ZERO)
        }

        /// Advances by `tick` after every read, so a statement's progress
        /// callbacks move it with no other thread involved.
        pub(in crate::exact_sql) fn ticking(tick: Duration) -> Arc<Self> {
            let started = Instant::now();
            Arc::new(Self {
                #[cfg(test)]
                started,
                now: Mutex::new(started),
                tick,
            })
        }

        /// Makes every exact SQL deadline computed or checked on the calling
        /// thread from here on read this clock.
        pub(in crate::exact_sql) fn install(self: &Arc<Self>) {
            INSTALLED.with(|installed| *installed.borrow_mut() = Some(Arc::clone(self)));
        }

        #[cfg(test)]
        pub(in crate::exact_sql) fn advance(&self, by: Duration) {
            *self.now.lock().unwrap_or_else(PoisonError::into_inner) += by;
        }

        #[cfg(test)]
        pub(in crate::exact_sql) fn elapsed(&self) -> Duration {
            self.now
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .duration_since(self.started)
        }

        fn read(&self) -> Instant {
            let mut now = self.now.lock().unwrap_or_else(PoisonError::into_inner);
            let read = *now;
            *now += self.tick;
            read
        }
    }

    #[cfg(feature = "test-runtime")]
    static STATEMENT_CLOCKS: std::sync::LazyLock<
        Mutex<std::collections::HashMap<std::path::PathBuf, Arc<FakeClock>>>,
    > = std::sync::LazyLock::new(Mutex::default);

    /// Accelerates statement deadlines on one temporary database, including its
    /// reader and writer workers. Dropping it unregisters the clock.
    #[cfg(feature = "test-runtime")]
    pub struct StatementClock(std::path::PathBuf);

    #[cfg(feature = "test-runtime")]
    impl StatementClock {
        pub fn ticking(path: &std::path::Path, tick: Duration) -> Self {
            let path = path.canonicalize().expect("test database must exist");
            let previous = STATEMENT_CLOCKS
                .lock()
                .unwrap()
                .insert(path.clone(), FakeClock::ticking(tick));
            assert!(
                previous.is_none(),
                "test database already has a statement clock"
            );
            Self(path)
        }
    }

    #[cfg(feature = "test-runtime")]
    impl Drop for StatementClock {
        fn drop(&mut self) {
            STATEMENT_CLOCKS.lock().unwrap().remove(&self.0);
        }
    }

    #[cfg(feature = "test-runtime")]
    pub(in crate::exact_sql) struct InstalledClock(Option<Arc<FakeClock>>);

    #[cfg(feature = "test-runtime")]
    impl Drop for InstalledClock {
        fn drop(&mut self) {
            INSTALLED.with(|installed| *installed.borrow_mut() = self.0.take());
        }
    }

    #[cfg(feature = "test-runtime")]
    fn clock_for_path(path: &std::path::Path) -> Option<Arc<FakeClock>> {
        // Registration uses canonical filesystem identity. SQLite may report
        // another spelling (notably a non-verbatim Windows path), so a raw
        // string lookup silently leaves the statement on the wall clock.
        let path = path.canonicalize().ok()?;
        STATEMENT_CLOCKS.lock().unwrap().get(&path).cloned()
    }

    #[cfg(feature = "test-runtime")]
    pub(in crate::exact_sql) fn for_statement(connection: &rusqlite::Connection) -> InstalledClock {
        let clock = connection
            .path()
            .and_then(|path| clock_for_path(std::path::Path::new(path)));
        let previous = INSTALLED.with(|installed| installed.borrow().clone());
        if let Some(clock) = clock {
            clock.install();
        }
        InstalledClock(previous)
    }

    #[cfg(all(test, feature = "test-runtime"))]
    mod tests {
        use super::*;

        #[test]
        fn statement_clock_uses_canonical_database_identity() {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("clock.sqlite3");
            let connection = rusqlite::Connection::open(&path).unwrap();
            std::fs::create_dir(directory.path().join("nested")).unwrap();
            let alias = directory.path().join("nested/../clock.sqlite3");
            let tick = Duration::from_secs(10);
            {
                let _registration = StatementClock::ticking(&path, tick);
                let canonical = clock_for_path(&path).unwrap();
                let aliased = clock_for_path(&alias).unwrap();
                assert!(Arc::ptr_eq(&canonical, &aliased));
                let _installed = for_statement(&connection);
                let first = now();
                assert_eq!(now().duration_since(first), tick);
            }
            assert!(clock_for_path(&path).is_none());
            assert!(clock_for_path(&alias).is_none());
        }
    }

    #[cfg(test)]
    #[derive(Default)]
    pub(crate) struct TaskClock(Option<Arc<FakeClock>>);

    #[cfg(test)]
    impl TaskClock {
        pub(crate) fn swap(&mut self) {
            INSTALLED.with(|installed| std::mem::swap(&mut *installed.borrow_mut(), &mut self.0));
        }
    }
}
