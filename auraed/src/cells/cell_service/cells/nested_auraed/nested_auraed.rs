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

use super::isolation_controls::{Isolation, IsolationControls};
use crate::AURAED_RUNTIME;
use client::AuraeSocket;
use clone3::Flags;
use nix::{
    errno::Errno,
    libc::SIGCHLD,
    sys::{
        signal::{Signal, Signal::SIGKILL, Signal::SIGTERM},
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::Pid,
};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use std::{
    io,
    os::unix::process::{CommandExt, ExitStatusExt},
    process::{Command, ExitStatus},
};
use tracing::{error, info, trace, warn};

/// How long to wait for a signalled nested auraed to actually exit before
/// escalating (SIGTERM → SIGKILL) or giving up. A bounded reap keeps a
/// child that ignores or is slow on SIGTERM from wedging teardown — and,
/// because `free`/`kill` run under the `CellService` cells lock, from
/// stalling every other cell RPC behind it.
const REAP_TIMEOUT: Duration = Duration::from_secs(5);
/// Poll interval for the bounded reap loop.
const REAP_POLL_INTERVAL: Duration = Duration::from_millis(20);

#[derive(Debug)]
pub struct NestedAuraed {
    process: procfs::process::Process,
    #[allow(unused)]
    pidfd: i32,
    #[allow(unused)]
    iso_ctl: IsolationControls,
    pub client_socket: AuraeSocket,
    /// Exit status memoized by the first successful wait. Subsequent
    /// `shutdown()`/`kill()` calls return it instead of re-signaling:
    /// the pid was reaped by that first wait, so a second signal would
    /// either fail with ESRCH — wedging retried teardown before it ever
    /// reaches the cgroup cleanup — or, after pid reuse, hit an
    /// unrelated process. This is what keeps `Cell::free` retryable
    /// after a partial failure and makes `Drop`'s kill safe.
    exit_status: Option<ExitStatus>,
}

impl NestedAuraed {
    pub fn new(
        name: String,
        iso_ctl: IsolationControls,
    ) -> io::Result<Self> {
        // Here we launch a nested auraed with the --nested flag
        // which is used our way of "hooking" into the newly created
        // aurae isolation zone.

        let auraed_runtime = AURAED_RUNTIME.get().expect("runtime");

        let socket_path = format!(
            "{}/aurae-{}.sock",
            auraed_runtime.runtime_dir.to_string_lossy(),
            uuid::Uuid::new_v4(),
        );

        let client_socket = AuraeSocket::Path(socket_path.clone().into());

        let auraed_path: PathBuf =
            auraed_runtime.auraed.clone().try_into().expect("path to auraed");
        let mut command = Command::new(auraed_path);

        let _ = command.args([
            "--socket",
            &socket_path,
            "--nested", // NOTE: for now, the nested flag only signals for the code in the init module to not trigger (i.e., don't run the pid 1 code, run the non pid 1 code)
            "--server-crt",
            &auraed_runtime.server_crt.to_string_lossy(),
            "--server-key",
            &auraed_runtime.server_key.to_string_lossy(),
            "--ca-crt",
            &auraed_runtime.ca_crt.to_string_lossy(),
            "--runtime-dir",
            &auraed_runtime.runtime_dir.to_string_lossy(),
            "--library-dir",
            &auraed_runtime.library_dir.to_string_lossy(),
        ]);

        // We have a concern that the "command" API make change/break in the future and this
        // test is intended to help safeguard against that!
        // We check that the command we kept has the expected number of args following the call
        // to command.args, whose return value we ignored above.
        assert_eq!(command.get_args().len(), 13);

        // *****************************************************************
        // ██████╗██╗      ██████╗ ███╗   ██╗███████╗██████╗
        // ██╔════╝██║     ██╔═══██╗████╗  ██║██╔════╝╚════██╗
        // ██║     ██║     ██║   ██║██╔██╗ ██║█████╗   █████╔╝
        // ██║     ██║     ██║   ██║██║╚██╗██║██╔══╝   ╚═══██╗
        // ╚██████╗███████╗╚██████╔╝██║ ╚████║███████╗██████╔╝
        // ╚═════╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═════╝
        // Clone docs: https://man7.org/linux/man-pages/man2/clone.2.html
        // *****************************************************************

        // Prepare clone3 command to "execute" the nested auraed
        let mut clone = clone3::Clone3::default();

        // [ Options ]

        // If the child fails to start, indicate an error
        // Set the pid file descriptor to -1
        let mut pidfd = -1;
        let _ = clone.flag_pidfd(&mut pidfd);

        // We have a concern that the "clone" API changes/breaks in the future and this
        // test is intended to help safeguard against that!
        // We check that the clone we kept has set the first flag we set above.
        assert_eq!(clone.as_clone_args().flags, Flags::PIDFD.bits());

        // Freeze the parent until the child calls execvp
        let _ = clone.flag_vfork();

        // Manage SIGCHLD for the nested process
        // Define SIGCHLD for signal handler
        let _ = clone.exit_signal(SIGCHLD as u64);

        // [ Namespaces and Isolation ]

        let mut isolation = Isolation::new(name);
        isolation.setup(&iso_ctl)?;

        // Always unshare the Cgroup namespace
        let _ = clone.flag_newcgroup();

        // Isolate Network
        if iso_ctl.isolate_network {
            let _ = clone.flag_newnet();
        }

        // Isolate Process
        if iso_ctl.isolate_process {
            let _ = clone.flag_newpid();
            let _ = clone.flag_newns();
            let _ = clone.flag_newipc();
            let _ = clone.flag_newuts();
        }

        // Execute the clone system call and create the new process with the relevant namespaces.
        match unsafe { clone.call() }? {
            0 => {
                // child
                let command = {
                    unsafe {
                        command.pre_exec(move || {
                            isolation.isolate_process(&iso_ctl)?;
                            isolation.isolate_network(&iso_ctl)?;
                            Ok(())
                        })
                    }
                };

                let e = command.exec();
                error!("Unexpected exit from child command: {e:#?}");
                Err(e)
            }
            pid => {
                // parent
                info!("Nested auraed running with host pid {}", pid.clone());
                let process = procfs::process::Process::new(pid)
                    .map_err(io::Error::other)?;

                Ok(Self {
                    process,
                    pidfd,
                    iso_ctl,
                    client_socket,
                    exit_status: None,
                })
            }
        }
    }

    /// Sends a graceful shutdown signal to the nested process. Idempotent:
    /// once the process has been waited on, returns the memoized exit
    /// status without signaling again.
    pub fn shutdown(&mut self) -> io::Result<ExitStatus> {
        // TODO: Here, SIGTERM works when using auraescript, but hangs(?) during unit tests.
        //       SIGKILL, however, works. The hang is avoided if the process is not isolated.
        //       Tests have not been done to figure out which namespace is the cause of the hang.
        self.signal_and_wait(SIGTERM)
    }

    /// Sends a [SIGKILL] signal to the nested process. Idempotent: once
    /// the process has been waited on, returns the memoized exit status
    /// without signaling again.
    pub fn kill(&mut self) -> io::Result<ExitStatus> {
        self.signal_and_wait(SIGKILL)
    }

    /// Signal the nested process and reap it, memoizing the exit status.
    ///
    /// The reap is bounded: if a graceful signal doesn't take within
    /// [`REAP_TIMEOUT`] it escalates to SIGKILL, and if even that doesn't
    /// land it returns a timeout error rather than blocking forever. This
    /// matters because `free`/`kill` run under the `CellService` cells
    /// lock, so an unbounded wait here stalls every other cell RPC.
    ///
    /// Already-reaped is success, not an error: a previous teardown
    /// attempt (or an external reaper) may have reaped the process and
    /// then failed at a later step (e.g. cgroup delete) — the retry must
    /// fall through to that later step instead of failing here forever.
    /// ESRCH on the signal and ECHILD on the wait are both treated as a
    /// synthesized clean exit.
    fn signal_and_wait(&mut self, signal: Signal) -> io::Result<ExitStatus> {
        if let Some(exit_status) = self.exit_status {
            trace!(
                "Pid {} already reaped (status {exit_status}); skipping \
                 {signal}",
                self.process.pid
            );
            return Ok(exit_status);
        }

        self.send_signal_tolerating_esrch(signal)?;

        let exit_status = match self.wait_bounded(REAP_TIMEOUT)? {
            Some(status) => status,
            // The graceful signal didn't take in time; escalate to SIGKILL
            // and reap again. (If we were already sending SIGKILL there is
            // nothing stronger to try.)
            None if signal != SIGKILL => {
                warn!(
                    "Pid {} did not exit within {}s of {signal}; escalating \
                     to SIGKILL",
                    self.process.pid,
                    REAP_TIMEOUT.as_secs()
                );
                self.send_signal_tolerating_esrch(SIGKILL)?;
                self.wait_bounded(REAP_TIMEOUT)?.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "process {} did not exit within {}s of SIGKILL",
                            self.process.pid,
                            REAP_TIMEOUT.as_secs()
                        ),
                    )
                })?
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "process {} did not exit within {}s of SIGKILL",
                        self.process.pid,
                        REAP_TIMEOUT.as_secs()
                    ),
                ));
            }
        };

        self.exit_status = Some(exit_status);
        Ok(exit_status)
    }

    /// Send `signal`, treating ESRCH (no such process — already gone) as
    /// success so the caller falls through to the wait, which observes
    /// ECHILD and synthesizes a clean exit.
    fn send_signal_tolerating_esrch(
        &mut self,
        signal: Signal,
    ) -> io::Result<()> {
        match self.do_kill(Some(signal)) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(Errno::ESRCH as i32) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn do_kill<T: Into<Option<Signal>>>(
        &mut self,
        signal: T,
    ) -> io::Result<()> {
        let signal = signal.into();
        let pid = Pid::from_raw(self.process.pid);
        nix::sys::signal::kill(pid, signal)?;
        Ok(())
    }

    /// Reap the process without blocking indefinitely, polling up to
    /// `timeout`. Returns `Ok(Some(status))` once it has exited (or was
    /// already reaped elsewhere — ECHILD — synthesized as a clean exit),
    /// or `Ok(None)` if it is still alive after `timeout`.
    fn wait_bounded(
        &mut self,
        timeout: Duration,
    ) -> io::Result<Option<ExitStatus>> {
        let pid = Pid::from_raw(self.process.pid);
        let start = Instant::now();

        loop {
            match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) => {
                    if start.elapsed() >= timeout {
                        return Ok(None);
                    }
                    std::thread::sleep(REAP_POLL_INTERVAL);
                }
                Ok(status) => {
                    return Ok(Some(Self::exit_status_from(pid, status)?));
                }
                Err(Errno::EINTR) => continue,
                // Already reaped (racing teardown or an external reaper):
                // nothing left to wait on. Treat as a clean exit so a
                // retried teardown proceeds to the cgroup cleanup instead
                // of wedging here.
                Err(Errno::ECHILD) => {
                    trace!("Pid {pid} already reaped; synthesizing clean exit");
                    return Ok(Some(ExitStatus::from_raw(0)));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Map a terminal [`WaitStatus`] to an [`ExitStatus`]. Non-terminal
    /// states (stopped/continued/ptrace) are unexpected for a nested
    /// auraed and surface as an error.
    fn exit_status_from(
        pid: Pid,
        status: WaitStatus,
    ) -> io::Result<ExitStatus> {
        let exit_status = match status {
            WaitStatus::Exited(_, code) => {
                trace!("Pid {pid} exited with code {code}");
                ExitStatus::from_raw(code << 8)
            }
            WaitStatus::Signaled(_, sig, core_dumped) => {
                if core_dumped {
                    error!("Pid {pid} killed by signal {sig} (core dumped)");
                } else {
                    trace!("Pid {pid} killed by signal {sig}");
                }
                ExitStatus::from_raw(sig as i32)
            }
            WaitStatus::Stopped(_, sig) => {
                error!("Pid {pid} unexpectedly stopped by signal {sig}");
                return Err(io::Error::other(format!(
                    "process {pid} stopped by signal {sig}"
                )));
            }
            WaitStatus::Continued(_) => {
                error!("Pid {pid} unexpectedly continued");
                return Err(io::Error::other(format!(
                    "process {pid} continued unexpectedly"
                )));
            }
            WaitStatus::PtraceEvent(_, sig, event) => {
                error!(
                    "Pid {pid} unexpected ptrace event {event} (signal {sig})"
                );
                return Err(io::Error::other(format!(
                    "unexpected ptrace event for process {pid}"
                )));
            }
            WaitStatus::PtraceSyscall(_) => {
                error!("Pid {pid} unexpected ptrace syscall-stop");
                return Err(io::Error::other(format!(
                    "unexpected ptrace syscall-stop for process {pid}"
                )));
            }
            WaitStatus::StillAlive => {
                // Handled by the WNOHANG poll loop; never reached here.
                error!("Pid {pid} still alive after waitpid");
                return Err(io::Error::other(format!(
                    "process {pid} still alive after waitpid"
                )));
            }
        };

        Ok(exit_status)
    }

    pub fn pid(&self) -> Pid {
        Pid::from_raw(self.process.pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `NestedAuraed` around an arbitrary child process so the
    /// teardown paths can be exercised without spawning a real nested
    /// auraed (no certs, no namespaces, no root).
    fn nested_for(child: &std::process::Child) -> NestedAuraed {
        NestedAuraed {
            process: procfs::process::Process::new(child.id() as i32)
                .expect("child process exists in /proc"),
            pidfd: -1,
            iso_ctl: IsolationControls {
                isolate_process: false,
                isolate_network: false,
            },
            client_socket: AuraeSocket::Path("/dev/null".into()),
            exit_status: None,
        }
    }

    /// A second (and third) teardown call must not re-signal the reaped
    /// — and possibly recycled — pid: it returns the memoized status.
    /// This is what lets a retried `Cell::free` proceed past the process
    /// step to the cgroup cleanup after a partial failure.
    #[test]
    // The child IS reaped — by `nested.kill()`'s internal waitpid, which
    // is the very behavior under test — just not via `Child::wait`.
    #[allow(clippy::zombie_processes)]
    fn teardown_is_idempotent_after_reap() {
        let child =
            Command::new("sleep").arg("30").spawn().expect("spawn sleep child");
        let mut nested = nested_for(&child);

        let first = nested.kill().expect("first kill reaps the child");
        let second = nested.kill().expect("second kill is a no-op");
        let third = nested.shutdown().expect("shutdown after kill is a no-op");
        assert_eq!(first, second);
        assert_eq!(first, third);
    }

    /// A child that was already reaped elsewhere (ESRCH on signal,
    /// ECHILD on wait) is treated as exited — synthesized clean status —
    /// instead of wedging teardown forever.
    #[test]
    fn teardown_of_externally_reaped_child_synthesizes_clean_exit() {
        let mut child = Command::new("true").spawn().expect("spawn true child");
        // Build while the /proc entry still exists (running or zombie).
        let mut nested = nested_for(&child);
        let _ = child.wait().expect("reap the child out from under us");

        let status =
            nested.kill().expect("teardown of a reaped child must succeed");
        assert!(status.success(), "synthesized status is a clean exit");

        // And it memoizes like any other teardown.
        let again = nested.shutdown().expect("subsequent teardown is a no-op");
        assert_eq!(status, again);
    }
}
