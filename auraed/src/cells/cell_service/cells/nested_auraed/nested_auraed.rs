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
use crate::init::network::endpoint::NetworkConfig;
use client::AuraeSocket;
use clone3::Flags;
use nix::{
    errno::Errno,
    libc::SIGCHLD,
    sys::{
        signal::{Signal, Signal::SIGKILL, Signal::SIGTERM},
        wait::{WaitStatus, waitpid},
    },
    unistd::Pid,
};
use std::path::PathBuf;
use std::{
    io,
    os::unix::process::{CommandExt, ExitStatusExt},
    process::{Command, ExitStatus},
};
use tracing::{error, info, trace};

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
        net_config: Option<NetworkConfig>,
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

        // Pass per-cell network config to the child auraed via CLI flags.
        // The child parses these on startup (in `CellSystemRuntime`) and
        // uses them to configure its eth0 from inside the cell's netns.
        if let Some(net_config) = net_config.as_ref() {
            for (flag, value) in net_config.as_cli_args() {
                let _ = command.args([flag, value.as_str()]);
            }
        }

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
    /// Already-reaped is success, not an error: a previous teardown
    /// attempt may have reaped the process and then failed at a later
    /// step (e.g. cgroup delete) — the retry must fall through to that
    /// later step instead of failing here forever. ESRCH on the signal
    /// (with no memoized status — somebody else reaped, or a previous
    /// wait was interrupted at the wrong moment) is treated the same
    /// way, with a synthesized clean exit.
    fn signal_and_wait(&mut self, signal: Signal) -> io::Result<ExitStatus> {
        if let Some(exit_status) = self.exit_status {
            trace!(
                "Pid {} already reaped (status {exit_status}); skipping \
                 {signal}",
                self.process.pid
            );
            return Ok(exit_status);
        }

        let already_gone = match self.do_kill(Some(signal)) {
            Ok(()) => false,
            Err(e) if e.raw_os_error() == Some(Errno::ESRCH as i32) => true,
            Err(e) => return Err(e),
        };

        let exit_status = match self.wait() {
            Ok(exit_status) => exit_status,
            // Nothing left to reap, consistent with the ESRCH above.
            Err(e)
                if already_gone
                    && e.raw_os_error() == Some(Errno::ECHILD as i32) =>
            {
                trace!(
                    "Pid {} was already reaped; synthesizing clean exit",
                    self.process.pid
                );
                ExitStatus::from_raw(0)
            }
            Err(e) => return Err(e),
        };

        self.exit_status = Some(exit_status);
        Ok(exit_status)
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

    fn wait(&mut self) -> io::Result<ExitStatus> {
        let pid = Pid::from_raw(self.process.pid);

        let status = loop {
            match waitpid(pid, None) {
                Ok(status) => break status,
                Err(Errno::EINTR) => continue,
                Err(e) => return Err(e.into()),
            }
        };

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
