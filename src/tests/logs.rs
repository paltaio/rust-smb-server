//! Collects the tracing events of a test.

use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

/// Collects the tracing events of the thread that made it, while it lives.
/// A test on a runtime of one thread sees the events of its tasks.
pub(crate) struct Logs {
    text: Arc<Mutex<Vec<u8>>>,
    _guard: tracing::subscriber::DefaultGuard,
}

impl Logs {
    /// Collects the events at info level and above.
    pub(crate) fn new() -> Self {
        Self::at(tracing::Level::INFO)
    }

    /// Collects the events at `level` and above.
    pub(crate) fn at(level: tracing::Level) -> Self {
        // With one dispatcher registered, tracing decides whether a callsite
        // is enabled by asking the dispatcher of the thread that reaches it
        // first. A test thread without a subscriber then disables the
        // callsite for the thread that has one. A second dispatcher that
        // lives for the whole process turns that shortcut off.
        static ANCHOR: OnceLock<tracing::Dispatch> = OnceLock::new();
        ANCHOR.get_or_init(|| {
            tracing::Dispatch::new(
                tracing_subscriber::fmt()
                    .with_writer(std::io::sink)
                    .finish(),
            )
        });

        #[derive(Clone)]
        struct Sink(Arc<Mutex<Vec<u8>>>);
        impl Write for Sink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .write(buf)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let text = Arc::new(Mutex::new(Vec::new()));
        let sink = Sink(Arc::clone(&text));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(level)
            .with_writer(move || sink.clone())
            .with_ansi(false)
            .finish();
        Self {
            text,
            _guard: tracing::subscriber::set_default(subscriber),
        }
    }

    /// Everything written so far.
    pub(crate) fn text(&self) -> String {
        let text = self.text.lock().unwrap_or_else(PoisonError::into_inner);
        String::from_utf8_lossy(&text).into_owned()
    }

    /// The lines at warn level so far.
    #[cfg(feature = "encryption")]
    pub(crate) fn warnings(&self) -> Vec<String> {
        self.lines_of_level("WARN")
    }

    /// The lines at debug level so far.
    #[cfg(feature = "encryption")]
    pub(crate) fn debugs(&self) -> Vec<String> {
        self.lines_of_level("DEBUG")
    }

    #[cfg(feature = "encryption")]
    fn lines_of_level(&self, level: &str) -> Vec<String> {
        let marker = format!(" {level} ");
        self.text()
            .lines()
            .filter(|line| line.contains(&marker))
            .map(str::to_string)
            .collect()
    }
}
