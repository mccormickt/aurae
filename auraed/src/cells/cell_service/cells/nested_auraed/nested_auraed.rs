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
    libc::{self, SIGCHLD},
    sys::{
        signal::{Signal, Signal::SIGKILL, Signal::SIGTERM},
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::Pid,
};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use std::{
    io,
    os::unix::process::{CommandExt, ExitStatusExt},
    process::{Command, ExitStatus},
};
use tracing::{error, info, trace, warn};

/// Async per-signal timeout and total synchronous Drop budget.
pub(crate) const REAP_TIMEOUT: Duration = Duration::from_secs(5);
/// Poll interval for the bounded reap loop.
const REAP_POLL_INTERVAL: Duration = Duration::from_millis(20);

fn reap_timed_out(pid: i32) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!("process {pid} did not exit before the teardown deadline"),
    )
}

#[derive(Debug)]
pub struct NestedAuraed {
    process: procfs::process::Process,
    pidfd: OwnedFd,
    #[allow(unused)]
    iso_ctl: IsolationControls,
    pub client_socket: AuraeSocket,
    /// Cached after reaping so cgroup-cleanup retries do not signal again.
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

        // Send the network configuration of the cell to the child auraed
        // in CLI flags. `CellSystemRuntime` in the child parses them at
        // its start and configures `eth0` in the network namespace of the cell.
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
                if pidfd < 0 {
                    return Err(io::Error::other(
                        "clone3 did not return a pidfd",
                    ));
                }
                // clone3 created this descriptor for the parent.
                let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
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

    /// Gracefully stops and reaps the process, or returns its cached status.
    pub async fn shutdown(&mut self) -> io::Result<ExitStatus> {
        // TODO: Here, SIGTERM works when using auraescript, but hangs(?) during unit tests.
        //       SIGKILL, however, works. The hang is avoided if the process is not isolated.
        //       Tests have not been done to figure out which namespace is the cause of the hang.
        self.signal_and_wait(SIGTERM).await
    }

    /// Kills and reaps the process, or returns its cached status.
    pub async fn kill(&mut self) -> io::Result<ExitStatus> {
        self.signal_and_wait(SIGKILL).await
    }

    pub(crate) fn signal_kill_for_drop(&mut self) -> io::Result<()> {
        if let Some(exit_status) = self.exit_status {
            trace!(
                "Pid {} already reaped (status {exit_status}); skipping SIGKILL",
                self.process.pid
            );
            return Ok(());
        }

        self.send_signal_tolerating_esrch(SIGKILL)
    }

    pub(crate) fn reap_for_drop(
        &mut self,
        deadline: Instant,
    ) -> io::Result<ExitStatus> {
        if let Some(exit_status) = self.exit_status {
            return Ok(exit_status);
        }

        let exit_status = self
            .wait_bounded_blocking(deadline)?
            .ok_or_else(|| reap_timed_out(self.process.pid))?;

        self.exit_status = Some(exit_status);
        Ok(exit_status)
    }

    /// Sends a signal, escalates SIGTERM after timeout, and caches the reap
    /// result.
    async fn signal_and_wait(
        &mut self,
        signal: Signal,
    ) -> io::Result<ExitStatus> {
        if let Some(exit_status) = self.exit_status {
            trace!(
                "Pid {} already reaped (status {exit_status}); skipping \
                 {signal}",
                self.process.pid
            );
            return Ok(exit_status);
        }

        self.send_signal_tolerating_esrch(signal)?;

        let exit_status = match self.wait_bounded(REAP_TIMEOUT).await? {
            Some(status) => status,
            // Escalate a timed-out graceful shutdown.
            None if signal != SIGKILL => {
                warn!(
                    "Pid {} did not exit within {}s of {signal}; escalating \
                     to SIGKILL",
                    self.process.pid,
                    REAP_TIMEOUT.as_secs()
                );
                self.send_signal_tolerating_esrch(SIGKILL)?;
                self.wait_bounded(REAP_TIMEOUT)
                    .await?
                    .ok_or_else(|| reap_timed_out(self.process.pid))?
            }
            None => {
                return Err(reap_timed_out(self.process.pid));
            }
        };

        self.exit_status = Some(exit_status);
        Ok(exit_status)
    }

    /// Treats ESRCH as process exit and lets waitpid determine the reap state.
    fn send_signal_tolerating_esrch(
        &mut self,
        signal: Signal,
    ) -> io::Result<()> {
        match self.do_kill(signal) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(Errno::ESRCH as i32) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn do_kill(&self, signal: Signal) -> io::Result<()> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                signal as libc::c_int,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if result == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Attempts one non-blocking reap. `None` means the process is alive.
    fn try_reap(&mut self) -> io::Result<Option<ExitStatus>> {
        let pid = Pid::from_raw(self.process.pid);
        loop {
            return match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) => Ok(None),
                Ok(status) => Ok(Some(Self::exit_status_from(pid, status)?)),
                Err(Errno::EINTR) => continue,
                // Allow cleanup to continue after another waiter reaps it.
                Err(Errno::ECHILD) => {
                    trace!("Pid {pid} already reaped; synthesizing clean exit");
                    Ok(Some(ExitStatus::from_raw(0)))
                }
                Err(e) => Err(e.into()),
            };
        }
    }

    /// Polls for process exit without blocking the executor.
    async fn wait_bounded(
        &mut self,
        timeout: Duration,
    ) -> io::Result<Option<ExitStatus>> {
        let start = Instant::now();
        loop {
            if let Some(status) = self.try_reap()? {
                return Ok(Some(status));
            }
            if start.elapsed() >= timeout {
                return Ok(None);
            }
            tokio::time::sleep(REAP_POLL_INTERVAL).await;
        }
    }

    fn wait_bounded_blocking(
        &mut self,
        deadline: Instant,
    ) -> io::Result<Option<ExitStatus>> {
        loop {
            if let Some(status) = self.try_reap()? {
                return Ok(Some(status));
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            std::thread::sleep(REAP_POLL_INTERVAL.min(deadline - now));
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
                ExitStatus::from_raw(
                    sig as i32 | if core_dumped { 0x80 } else { 0 },
                )
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
    use std::fs::File;

    fn open_pidfd(pid: u32) -> OwnedFd {
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(fd >= 0, "open pidfd: {}", io::Error::last_os_error());
        unsafe { OwnedFd::from_raw_fd(fd as i32) }
    }

    fn clean_up_child(child: &mut std::process::Child) {
        match child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                child.kill().expect("kill child");
                let _ = child.wait().expect("reap child");
            }
            Err(ref error)
                if error.raw_os_error() == Some(Errno::ECHILD as i32) => {}
            Err(error) => panic!("query child state: {error}"),
        }
    }

    /// Wraps a child without namespaces, certificates, or root access.
    fn nested_for(child: &std::process::Child) -> NestedAuraed {
        NestedAuraed {
            process: procfs::process::Process::new(child.id() as i32)
                .expect("child process exists in /proc"),
            pidfd: open_pidfd(child.id()),
            iso_ctl: IsolationControls {
                isolate_process: false,
                isolate_network: false,
            },
            client_socket: AuraeSocket::Path("/dev/null".into()),
            exit_status: None,
        }
    }

    /// Repeated teardown returns the cached status without signaling again.
    #[tokio::test]
    // nested.kill reaps the child directly.
    #[allow(clippy::zombie_processes)]
    async fn teardown_is_idempotent_after_reap() {
        let child =
            Command::new("sleep").arg("30").spawn().expect("spawn sleep child");
        let mut nested = nested_for(&child);

        let first = nested.kill().await.expect("first kill reaps the child");
        let second = nested.kill().await.expect("second kill is a no-op");
        let third =
            nested.shutdown().await.expect("shutdown after kill is a no-op");
        assert_eq!(first, second);
        assert_eq!(first, third);
    }

    /// An external reap is treated as a clean exit.
    #[tokio::test]
    async fn teardown_of_externally_reaped_child_synthesizes_clean_exit() {
        let mut child = Command::new("true").spawn().expect("spawn true child");
        // Build while the /proc entry still exists (running or zombie).
        let mut nested = nested_for(&child);
        let _ = child.wait().expect("reap the child out from under us");

        let status = nested
            .kill()
            .await
            .expect("teardown of a reaped child must succeed");
        assert!(status.success(), "synthesized status is a clean exit");

        let again =
            nested.shutdown().await.expect("subsequent teardown is a no-op");
        assert_eq!(status, again);
    }

    #[tokio::test]
    async fn teardown_requires_a_process_identity_fd() {
        let mut child =
            Command::new("sleep").arg("30").spawn().expect("spawn sleep child");
        let mut nested = nested_for(&child);
        nested.pidfd = File::open("/dev/null").expect("open non-pidfd").into();

        let result = nested.kill().await;
        clean_up_child(&mut child);

        assert_eq!(
            result
                .expect_err("an invalid pidfd must prevent signaling")
                .raw_os_error(),
            Some(Errno::EBADF as i32)
        );
    }

    #[test]
    fn blocking_waits_share_one_timeout_budget() {
        let mut first_child =
            Command::new("sleep").arg("30").spawn().expect("spawn first child");
        let mut second_child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn second child");
        let mut first = nested_for(&first_child);
        let mut second = nested_for(&second_child);
        let timeout = Duration::from_millis(100);
        let start = Instant::now();
        let deadline = start + timeout;

        assert!(
            first
                .wait_bounded_blocking(deadline)
                .expect("first wait")
                .is_none()
        );
        assert!(
            second
                .wait_bounded_blocking(deadline)
                .expect("second wait")
                .is_none()
        );
        let elapsed = start.elapsed();

        clean_up_child(&mut first_child);
        clean_up_child(&mut second_child);
        assert!(
            elapsed < Duration::from_millis(170),
            "blocking waits used separate timeout budgets: {elapsed:?}"
        );
    }

    #[test]
    fn signaled_exit_status_preserves_core_dump() {
        use std::os::unix::process::ExitStatusExt as _;

        let status = NestedAuraed::exit_status_from(
            Pid::from_raw(42),
            WaitStatus::Signaled(Pid::from_raw(42), Signal::SIGABRT, true),
        )
        .expect("convert wait status");

        assert!(status.core_dumped());
    }
}
