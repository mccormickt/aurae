/* -------------------------------------------------------------------------- *\
 *                |   █████╗ ██╗   ██╗██████╗  █████╗ ███████╗ |              *
 *                |  ██╔══██╗██║   ██║██╔══██╗██╔══██╗██╔════╝ |              *
 *                |  ███████║██║   ██║██████╔╝███████║█████╗   |              *
 *                |  ██╔══██║██║   ██║██╔══██╗██╔══██║██╔══╝   |              *
 *                |  ██║  ██║╚██████╔╝██║  ██║██║  ██║███████╗ |              *
 *                |  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ |              *
 *                +--------------------------------------------+              *
 *                                                                            *
 *                         Distributed Systems Runtime                        *
 * -------------------------------------------------------------------------- *
 * Copyright 2022 - 2024, the aurae contributors                              *
 * SPDX-License-Identifier: Apache-2.0                                        *
\* -------------------------------------------------------------------------- */
use crate::logging::log_channel::LogChannel;
use tracing::{Level, info};
use tracing_subscriber::{
    EnvFilter, Layer, filter::FilterExt, layer::SubscriberExt,
    util::SubscriberInitExt,
};

#[derive(thiserror::Error, Debug)]
pub(crate) enum LoggingError {
    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error(transparent)]
    TryInit(#[from] tracing_subscriber::util::TryInitError),

    #[error("Failed to setup syslog logging")]
    Syslog,
}

impl LogChannel {
    /// Build the broadcast layer that pipes events into `GetAuraeDaemonLogStream`.
    ///
    /// `auraed::observe=off` in the EnvFilter is an optimization that keeps the
    /// consumer task's own events out of the broadcast cheaply. The real
    /// backstop against a feedback loop is the thread-local reentrancy guard in
    /// `broadcast_writer::BroadcastWriter::drop`, which suppresses recursion for
    /// events on any target — including the proxy/bridge paths outside
    /// `auraed::observe`.
    fn broadcast_layer<S>(self, tracing_level: Level) -> impl Layer<S>
    where
        S: tracing::Subscriber
            + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    {
        // Gate the layer on there being a live `GetAuraeDaemonLogStream`
        // subscriber. JSON-serializing every event is the bulk of the
        // per-event cost, and it is pure waste in the steady state where no
        // client is streaming logs; this filter skips `on_event` entirely
        // (and so the serialization) when `receiver_count()` is zero. The
        // `BroadcastWriter::drop` short-circuit remains as a backstop.
        let tx = self.sender().clone();
        let filter = EnvFilter::new(format!(
            "auraed={tracing_level},auraed::observe=off"
        ))
        .and(tracing_subscriber::filter::filter_fn(move |_| {
            tx.receiver_count() > 0
        }));
        tracing_subscriber::fmt::layer()
            .json()
            .with_writer(self)
            .with_filter(filter)
    }

    pub(crate) fn container(self, verbose: bool) -> Result<(), LoggingError> {
        info!("initializing container logging");
        let tracing_level = if verbose { Level::TRACE } else { Level::INFO };

        // Stdout
        let stdout_layer = Layer::with_filter(
            tracing_subscriber::fmt::layer().compact(),
            EnvFilter::new(format!("auraed={tracing_level}")),
        );

        tracing_subscriber::registry()
            .with(stdout_layer)
            .with(self.broadcast_layer(tracing_level))
            .try_init()
            .map_err(|e| e.into())
    }

    /// when we run as a daemon we want to log to stdout and syslog.
    pub(crate) fn daemon(self, verbose: bool) -> Result<(), LoggingError> {
        info!("initializing syslog logging");
        let tracing_level = if verbose { Level::TRACE } else { Level::INFO };

        // Syslog
        let syslog_identity = c"auraed";
        let syslog_facility = Default::default();
        let syslog_options = syslog_tracing::Options::LOG_PID;
        let Some(syslog) = syslog_tracing::Syslog::new(
            syslog_identity,
            syslog_options,
            syslog_facility,
        ) else {
            return Err(LoggingError::Syslog);
        };

        let syslog_layer = tracing_subscriber::fmt::layer().with_writer(syslog);

        // Stdout
        let stdout_layer = Layer::with_filter(
            tracing_subscriber::fmt::layer().compact(),
            EnvFilter::new(format!("auraed={tracing_level}")),
        );

        tracing_subscriber::registry()
            .with(syslog_layer)
            .with(stdout_layer)
            .with(self.broadcast_layer(tracing_level))
            .try_init()
            .map_err(|e| e.into())
    }

    pub(crate) fn pid1(self, verbose: bool) -> Result<(), LoggingError> {
        info!("initializing pid1 logging");
        let tracing_level = if verbose { Level::TRACE } else { Level::INFO };

        let stdout_layer = Layer::with_filter(
            tracing_subscriber::fmt::layer().compact(),
            EnvFilter::new(format!("auraed={tracing_level}")),
        );

        tracing_subscriber::registry()
            .with(stdout_layer)
            .with(self.broadcast_layer(tracing_level))
            .try_init()
            .map_err(|e| e.into())
    }
}
