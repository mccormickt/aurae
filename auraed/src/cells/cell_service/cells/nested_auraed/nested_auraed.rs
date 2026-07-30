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
    libc::{self, SIGCHLD},
    sys::{
        signal::{Signal, Signal::SIGKILL, Signal::SIGTERM},
        wait::{Id, WaitPidFlag, WaitStatus, waitid},
    },
    unistd::Pid,
};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use std::{
    io,
    os::unix::process::{CommandExt, ExitStatusExt},
    process::{Command, ExitStatus},
};
use tracing::{error, info, trace, warn};

/// Async per-signal timeout and shared synchronous Drop reap budget.
pub(crate) const REAP_TIMEOUT: Duration = Duration::from_secs(5);
/// Poll interval for the bounded reap loop.
const REAP_POLL_INTERVAL: Duration = Duration::from_millis(20);

fn reap_timed_out(pid: Pid) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!("process {pid} did not exit before the teardown deadline"),
    )
}

#[derive(Debug)]
pub struct NestedAuraed {
    pid: Pid,
    pidfd: OwnedFd,
    #[allow(unused)]
    iso_ctl: IsolationControls,
    pub client_socket: AuraeSocket,
    /// Cached after reaping so cgroup-cleanup retries do not signal again.
    exit_status: Option<ExitStatus>,
    /// The owner's reap deadline also applies to implicit field destruction.
    drop_deadline: Option<Instant>,
}

impl NestedAuraed {
    pub fn new(name: String, iso_ctl: IsolationControls) -> io::Result<Self> {
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

                // `CLONE_VFORK` suspends the spawning thread until exec or exit.
                // If exec fails, exit without running the inherited daemon
                // control flow or destructors.
                let _exec_error = command.exec();
                unsafe { libc::_exit(127) }
            }
            pid => {
                // parent
                info!("Nested auraed running with host pid {}", pid.clone());
                // clone3 with CLONE_PIDFD installed this descriptor for the parent.
                let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };

                Ok(Self {
                    pid: Pid::from_raw(pid),
                    pidfd,
                    iso_ctl,
                    client_socket,
                    exit_status: None,
                    drop_deadline: None,
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
                self.pid
            );
            return Ok(());
        }

        self.send_signal_tolerating_esrch(SIGKILL)
    }

    pub(crate) fn reap_for_drop(
        &mut self,
        deadline: Instant,
    ) -> io::Result<ExitStatus> {
        let deadline = *self.drop_deadline.get_or_insert(deadline);
        if let Some(exit_status) = self.exit_status {
            return Ok(exit_status);
        }

        let exit_status = self
            .wait_bounded_blocking(deadline)?
            .ok_or_else(|| reap_timed_out(self.pid))?;

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
                self.pid
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
                    self.pid,
                    REAP_TIMEOUT.as_secs()
                );
                self.send_signal_tolerating_esrch(SIGKILL)?;
                self.wait_bounded(REAP_TIMEOUT)
                    .await?
                    .ok_or_else(|| reap_timed_out(self.pid))?
            }
            None => {
                return Err(reap_timed_out(self.pid));
            }
        };

        self.exit_status = Some(exit_status);
        Ok(exit_status)
    }

    /// Treats ESRCH as process exit and lets waitid determine the reap state.
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
        let pid = self.pid;
        match waitid(
            Id::PIDFd(self.pidfd.as_fd()),
            WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG,
        ) {
            Ok(WaitStatus::StillAlive) => Ok(None),
            Ok(status) => Ok(Some(Self::exit_status_from(pid, status)?)),
            // Allow cleanup to continue after another waiter reaps it.
            Err(Errno::ECHILD) => {
                trace!("Pid {pid} already reaped; synthesizing clean exit");
                Ok(Some(ExitStatus::from_raw(0)))
            }
            Err(e) => Err(e.into()),
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
                error!("Pid {pid} still alive after waitid");
                return Err(io::Error::other(format!(
                    "process {pid} still alive after waitid"
                )));
            }
        };

        Ok(exit_status)
    }

    pub fn pid(&self) -> Pid {
        self.pid
    }
}

impl Drop for NestedAuraed {
    /// Makes a bounded best-effort reap attempt; a timeout is not an exit.
    fn drop(&mut self) {
        let deadline =
            self.drop_deadline.unwrap_or_else(|| Instant::now() + REAP_TIMEOUT);
        let _ = self.signal_kill_for_drop();
        let _ = self.reap_for_drop(deadline);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    use test_helpers::skip;

    fn open_pidfd(pid: u32) -> OwnedFd {
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(fd >= 0, "open pidfd: {}", io::Error::last_os_error());
        unsafe { OwnedFd::from_raw_fd(fd as i32) }
    }

    /// Wraps a child without namespaces, certificates, or root access.
    fn nested_for(child: &std::process::Child) -> NestedAuraed {
        NestedAuraed {
            pid: Pid::from_raw(child.id() as i32),
            pidfd: open_pidfd(child.id()),
            iso_ctl: IsolationControls {
                isolate_process: false,
                isolate_network: false,
            },
            client_socket: AuraeSocket::Path("/dev/null".into()),
            exit_status: None,
            drop_deadline: None,
        }
    }

    /// A child that ignores SIGTERM is killed after the timeout and reaped.
    // nested.shutdown reaps the child directly.
    #[allow(clippy::zombie_processes)]
    #[tokio::test]
    async fn shutdown_escalates_to_sigkill_when_sigterm_is_ignored() {
        // `exec` keeps the ignored disposition; "ready" confirms the trap is set.
        let mut child = Command::new("sh")
            .args(["-c", "trap '' TERM; echo ready; exec sleep 30"])
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn sh child");
        let mut ready = String::new();
        let _ = BufReader::new(child.stdout.take().expect("piped stdout"))
            .read_line(&mut ready)
            .expect("read ready line");
        assert_eq!(ready.trim(), "ready");
        let mut nested = nested_for(&child);

        let start = Instant::now();
        let status = nested.shutdown().await.expect("shutdown reaps the child");

        assert_eq!(status.signal(), Some(SIGKILL as i32));
        assert!(
            start.elapsed() >= REAP_TIMEOUT,
            "SIGKILL was sent before the SIGTERM timeout elapsed"
        );
    }

    /// Repeated teardown returns the cached status without signaling again.
    // nested.kill reaps the child directly.
    #[allow(clippy::zombie_processes)]
    #[tokio::test]
    async fn teardown_is_idempotent_after_reap() {
        let child =
            Command::new("sleep").arg("30").spawn().expect("spawn sleep child");
        let mut nested = nested_for(&child);

        let first = nested.kill().await.expect("first kill reaps the child");
        let second = nested.kill().await.expect("second kill is a no-op");
        let third =
            nested.shutdown().await.expect("shutdown after kill is a no-op");
        assert_eq!(first.signal(), Some(SIGKILL as i32));
        assert_eq!(first, second);
        assert_eq!(first, third);
    }

    /// A stale numeric PID must not select another child for signaling or reaping.
    #[tokio::test]
    async fn teardown_uses_pidfd_after_external_reap() {
        let mut child = Command::new("true").spawn().expect("spawn true child");
        // Open the pidfd before reaping the child.
        let mut nested = nested_for(&child);
        let _ = child.wait().expect("reap the child out from under us");

        let mut replacement =
            Command::new("sleep").arg("30").spawn().expect("replacement child");
        // Inject the identity mismatch caused by PID reuse without cycling kernel PIDs.
        nested.pid = Pid::from_raw(replacement.id() as i32);
        let result = nested.kill().await;
        let replacement_status = replacement.try_wait();
        let _ = replacement.kill();
        let _ = replacement.wait();

        assert!(
            replacement_status
                .expect("replacement remains our child")
                .is_none()
        );
        let status = result.expect("teardown of a reaped child must succeed");
        assert!(status.success(), "synthesized status is a clean exit");

        let again =
            nested.shutdown().await.expect("subsequent teardown is a no-op");
        assert_eq!(status, again);
    }

    #[test]
    fn drop_reaps_child() {
        let mut child = Command::new("sleep").arg("30").spawn().expect("child");
        drop(nested_for(&child));
        assert_eq!(
            child.try_wait().expect_err("Drop reaped the child").raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[test]
    fn drop_preserves_shared_deadline_after_signal_failure() {
        let mut children: Vec<_> = (0..2)
            .map(|_| Command::new("sleep").arg("30").spawn().expect("child"))
            .collect();
        let mut nested: Vec<_> = children.iter().map(nested_for).collect();
        // Only this test thread denies pidfd signaling. Numeric kill remains
        // available to clean up the fixtures after the Drop attempts.
        let filter: seccompiler::BpfProgram = seccompiler::SeccompFilter::new(
            [(libc::SYS_pidfd_send_signal, vec![])].into_iter().collect(),
            seccompiler::SeccompAction::Allow,
            seccompiler::SeccompAction::Errno(libc::EPERM as u32),
            std::env::consts::ARCH.try_into().expect("target architecture"),
        )
        .expect("signal filter")
        .try_into()
        .expect("compile filter");
        seccompiler::apply_filter(&filter).expect("deny pidfd signaling");

        let signals: Vec<_> =
            nested.iter_mut().map(NestedAuraed::signal_kill_for_drop).collect();
        let deadline = Instant::now();
        let reaps: Vec<_> = nested
            .iter_mut()
            .map(|child| child.reap_for_drop(deadline))
            .collect();
        let start = Instant::now();
        let retries: Vec<_> = nested
            .iter_mut()
            .map(|child| child.reap_for_drop(Instant::now() + REAP_TIMEOUT))
            .collect();
        let cached_exit =
            nested.iter().any(|child| child.exit_status.is_some());
        drop(nested);
        let elapsed = start.elapsed();
        for child in &mut children {
            child.kill().expect("cleanup child");
            let _ = child.wait().expect("reap child");
        }

        for signal in signals {
            assert_eq!(
                signal.expect_err("signal denied").raw_os_error(),
                Some(libc::EPERM)
            );
        }
        for reap in reaps.into_iter().chain(retries) {
            assert_eq!(
                reap.expect_err("expired deadline").kind(),
                io::ErrorKind::TimedOut
            );
        }
        assert!(!cached_exit, "a timeout is not a successful reap");
        assert!(
            elapsed < REAP_TIMEOUT,
            "implicit Drop restarted the expired budget: {elapsed:?}"
        );
    }

    #[test]
    fn failed_exec_exits_127_without_procfs() {
        test_helpers::skip_if_not_root!("failed_exec_exits_127_without_procfs");
        test_helpers::skip_if_seccomp!("failed_exec_exits_127_without_procfs");

        // Run with a separate runtime configuration and mount namespace.
        const CHILD: &str = "AURAE_TEST_FAILED_EXEC_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let test_thread = std::thread::current();
            let status =
                Command::new(std::env::current_exe().expect("test binary"))
                    .args([
                        "--exact",
                        test_thread.name().expect("test name"),
                        "--nocapture",
                    ])
                    .env(CHILD, "1")
                    .status()
                    .expect("run spawn test");
            assert!(status.success());
            return;
        }

        let directory = tempfile::tempdir().expect("directory");
        AURAED_RUNTIME
            .set(crate::AuraedRuntime {
                auraed: crate::AuraedPath::from_path(
                    directory.path().join("missing"),
                ),
                ..crate::AuraedRuntime::default()
            })
            .expect("runtime");
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS)
            .expect("mount namespace");
        nix::mount::mount(
            None::<&str>,
            "/",
            None::<&str>,
            nix::mount::MsFlags::MS_PRIVATE | nix::mount::MsFlags::MS_REC,
            None::<&str>,
        )
        .expect("private mounts");
        nix::mount::mount(
            Some("tmpfs"),
            "/proc",
            Some("tmpfs"),
            nix::mount::MsFlags::empty(),
            None::<&str>,
        )
        .expect("hide procfs");

        let mut nested = NestedAuraed::new(
            "failed-exec".into(),
            IsolationControls::default(),
        )
        .expect("clone without procfs");
        let status = nested
            .reap_for_drop(Instant::now() + REAP_TIMEOUT)
            .expect("reap failed exec");
        assert_eq!(status.code(), Some(127));
    }
}
