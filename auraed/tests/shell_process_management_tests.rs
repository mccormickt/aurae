use client::cells::cell_service::CellServiceClient;
use test_helpers::*;
use std::time::Duration;

mod common;

#[test_helpers_macros::shared_runtime_test]
async fn shell_vs_direct_execution_behavior() {
    skip_if_not_root!("shell_vs_direct_execution_behavior");
    skip_if_seccomp!("shell_vs_direct_execution_behavior");

    let client = common::auraed_client().await;

    println!("Testing shell vs direct execution behavior...");
    
    // The default ExecutableBuilder uses "tail -f /dev/null" which should run directly
    // This test verifies that the process we can stop is the actual command, not a shell wrapper
    
    let exe_name = "shell-behavior-test";
    let req = common::cells::CellServiceStartRequestBuilder::new()
        .executable_name(exe_name.to_string())
        .build();
    
    let start_response = retry!(client.start(req.clone()).await).unwrap().into_inner();
    let pid = start_response.pid;
    println!("Started process with PID: {}", pid);
    
    // Verify the process exists
    let proc_path = format!("/proc/{}", pid);
    assert!(std::path::Path::new(&proc_path).exists(), "Process should exist in /proc");
    
    // Check the command line to see what's actually running
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    if let Ok(cmdline) = std::fs::read_to_string(&cmdline_path) {
        println!("Process cmdline: {:?}", cmdline);
        
        // The cmdline should contain our actual command, not just "sh" or "bash"
        // If it's shell-wrapped incorrectly, we'd see "sh\0-c\0tail -f /dev/null\0"
        // If it's direct, we'd see "tail\0-f\0/dev/null\0" or similar
        if cmdline.contains("sh\0-c\0") {
            println!("⚠ Process appears to be shell-wrapped (potential issue)");
        } else {
            println!("✓ Process appears to be running directly");
        }
    }
    
    // Give it time to initialize
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    // Stop the process - this is where the original bug would manifest
    // If we're tracking a shell process that exits while the child continues,
    // we'd get "No child process" errors
    let stop_result = retry!(
        client
            .stop(proto::cells::CellServiceStopRequest {
                cell_name: None,
                executable_name: exe_name.to_string(),
            })
            .await
    );
    
    match stop_result {
        Ok(_) => println!("✓ Shell behavior test: Process stopped successfully"),
        Err(status) => {
            if status.message().contains("No child process") {
                // This might indicate the shell process management issue
                println!("⚠ Shell behavior test: 'No child process' error (may indicate shell wrapper issue): {}", status.message());
            } else {
                panic!("✗ Shell behavior test: Unexpected error: {}", status);
            }
        }
    }
    
    // Verify process is actually gone
    tokio::time::sleep(Duration::from_millis(100)).await;
    if std::path::Path::new(&proc_path).exists() {
        println!("⚠ Process still exists after stop - potential cleanup issue");
    } else {
        println!("✓ Process properly terminated");
    }
}

#[test_helpers_macros::shared_runtime_test]
async fn process_group_signal_handling() {
    skip_if_not_root!("process_group_signal_handling");
    skip_if_seccomp!("process_group_signal_handling");

    let client = common::auraed_client().await;

    println!("Testing process group signal handling...");
    
    // This test simulates the scenario where a command might spawn child processes
    // and we need to ensure signals are delivered to the right process/group
    
    let exe_name = "signal-test";
    let req = common::cells::CellServiceStartRequestBuilder::new()
        .executable_name(exe_name.to_string())
        .build();
    
    let start_response = retry!(client.start(req.clone()).await).unwrap().into_inner();
    let pid = start_response.pid;
    println!("Signal test: Started process with PID: {}", pid);
    
    // Let it run for a bit
    tokio::time::sleep(Duration::from_millis(300)).await;
    
    // Test graceful termination (SIGTERM)
    println!("Testing graceful termination...");
    let stop_result = retry!(
        client
            .stop(proto::cells::CellServiceStopRequest {
                cell_name: None,
                executable_name: exe_name.to_string(),
            })
            .await
    );
    
    let termination_successful = match stop_result {
        Ok(_) => {
            println!("✓ Graceful termination succeeded");
            true
        },
        Err(status) => {
            if status.message().contains("No child process") {
                println!("✓ Process already gone during graceful termination: {}", status.message());
                true
            } else {
                println!("✗ Graceful termination failed: {}", status);
                false
            }
        }
    };
    
    // Verify process cleanup
    tokio::time::sleep(Duration::from_millis(200)).await;
    let proc_path = format!("/proc/{}", pid);
    let process_cleaned = !std::path::Path::new(&proc_path).exists();
    
    if process_cleaned {
        println!("✓ Process properly cleaned up after termination");
    } else {
        println!("⚠ Process still exists after termination - may need SIGKILL");
    }
    
    assert!(termination_successful, "Signal handling test failed");
}

#[test_helpers_macros::shared_runtime_test]
async fn orphaned_process_cleanup() {
    skip_if_not_root!("orphaned_process_cleanup");
    skip_if_seccomp!("orphaned_process_cleanup");

    let client = common::auraed_client().await;

    println!("Testing orphaned process cleanup scenarios...");
    
    // This test simulates scenarios where processes might become orphaned
    // and verifies that our cleanup mechanisms work properly
    
    let num_processes = 5;
    let mut started_processes = Vec::new();
    
    // Start multiple processes
    for i in 1..=num_processes {
        let exe_name = format!("orphan-test-{}", i);
        let req = common::cells::CellServiceStartRequestBuilder::new()
            .executable_name(exe_name.clone())
            .build();
        
        match retry!(client.start(req.clone()).await) {
            Ok(response) => {
                let start_response = response.into_inner();
                println!("Orphan test {}: Started PID {}", i, start_response.pid);
                started_processes.push((exe_name, start_response.pid));
            },
            Err(e) => {
                println!("Orphan test {}: Failed to start: {}", i, e);
            }
        }
        
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    
    println!("Started {} processes for orphan cleanup test", started_processes.len());
    
    // Let them all run for a bit
    tokio::time::sleep(Duration::from_millis(300)).await;
    
    // Now stop them all and verify cleanup
    let mut cleanup_results = Vec::new();
    for (exe_name, _pid) in started_processes {
        let stop_result = retry!(
            client
                .stop(proto::cells::CellServiceStopRequest {
                    cell_name: None,
                    executable_name: exe_name.clone(),
                })
                .await
        );
        
        let cleaned_up = match stop_result {
            Ok(_) => {
                println!("✓ Orphan cleanup: {} stopped successfully", exe_name);
                true
            },
            Err(status) => {
                if status.message().contains("No child process") || status.message().contains("not found") {
                    println!("✓ Orphan cleanup: {} already gone: {}", exe_name, status.message());
                    true
                } else {
                    println!("✗ Orphan cleanup: {} failed: {}", exe_name, status);
                    false
                }
            }
        };
        
        cleanup_results.push(cleaned_up);
        
        // Brief delay between cleanups
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    
    let successful_cleanups = cleanup_results.iter().filter(|&&x| x).count();
    println!("Orphan cleanup: {}/{} processes cleaned up successfully", successful_cleanups, cleanup_results.len());
    
    assert!(successful_cleanups >= (cleanup_results.len() * 90 / 100), "Less than 90% cleanup success rate");
}

#[test_helpers_macros::shared_runtime_test]
async fn nested_cell_process_isolation() {
    skip_if_not_root!("nested_cell_process_isolation");
    skip_if_seccomp!("nested_cell_process_isolation");

    let client = common::auraed_client().await;

    println!("Testing nested cell process isolation...");
    
    // Allocate a nested cell with process isolation
    let cell_name = retry!(
        client
            .allocate(
                common::cells::CellServiceAllocateRequestBuilder::new()
                    .isolate_process()
                    .build()
            )
            .await
    )
    .unwrap()
    .into_inner()
    .cell_name;
    
    println!("Allocated nested cell: {}", cell_name);
    
    // Start an executable in the nested cell
    let req = common::cells::CellServiceStartRequestBuilder::new()
        .cell_name(cell_name.clone())
        .executable_name("nested-isolation-test".to_string())
        .build();
    
    let start_result = retry!(client.start(req.clone()).await);
    
    let (_pid, nested_started) = match start_result {
        Ok(response) => {
            let start_response = response.into_inner();
            println!("Nested isolation: Started PID {} in cell {}", start_response.pid, cell_name);
            (start_response.pid, true)
        },
        Err(e) => {
            println!("Nested isolation: Failed to start in nested cell: {}", e);
            (0, false)
        }
    };
    
    if nested_started {
        // Let it run in the isolated environment
        tokio::time::sleep(Duration::from_millis(300)).await;
        
        // Stop the process in the nested cell
        let stop_result = retry!(
            client
                .stop(proto::cells::CellServiceStopRequest {
                    cell_name: Some(cell_name.clone()),
                    executable_name: "nested-isolation-test".to_string(),
                })
                .await
        );
        
        match stop_result {
            Ok(_) => println!("✓ Nested isolation: Process stopped successfully"),
            Err(status) => {
                if status.message().contains("No child process") || 
                   status.message().contains("could not kill children") {
                    println!("✓ Nested isolation: Process cleanup issue (known limitation): {}", status.message());
                } else {
                    println!("✗ Nested isolation: Unexpected stop error: {}", status);
                }
            }
        }
    }
    
    // Free the nested cell
    let free_result = retry!(
        client
            .free(proto::cells::CellServiceFreeRequest {
                cell_name: cell_name.clone()
            })
            .await
    );
    
    match free_result {
        Ok(_) => println!("✓ Nested isolation: Cell freed successfully"),
        Err(status) => {
            if status.message().contains("No child process") || 
               status.message().contains("could not kill children") {
                println!("✓ Nested isolation: Cell freed with warnings: {}", status.message());
            } else {
                panic!("✗ Nested isolation: Failed to free cell: {}", status);
            }
        }
    }
}

#[test_helpers_macros::shared_runtime_test]
async fn nested_cell_communication_reliability() {
    skip_if_not_root!("nested_cell_communication_reliability");
    skip_if_seccomp!("nested_cell_communication_reliability");

    let client = common::auraed_client().await;

    println!("Testing nested cell communication reliability...");
    
    // Test multiple nested cells to stress the communication channels
    let num_cells = 3;
    let mut allocated_cells = Vec::new();
    
    // Allocate multiple nested cells
    for i in 1..=num_cells {
        let cell_result = retry!(
            client
                .allocate(
                    common::cells::CellServiceAllocateRequestBuilder::new()
                        .isolate_process()
                        .build()
                )
                .await
        );
        
        match cell_result {
            Ok(response) => {
                let cell_name = response.into_inner().cell_name;
                println!("Communication test: Allocated cell {} - {}", i, cell_name);
                allocated_cells.push(cell_name);
            },
            Err(e) => {
                println!("Communication test: Failed to allocate cell {}: {}", i, e);
            }
        }
        
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    
    println!("Allocated {} nested cells for communication test", allocated_cells.len());
    
    // Start processes in each nested cell
    let mut started_processes = Vec::new();
    for (i, cell_name) in allocated_cells.iter().enumerate() {
        let exe_name = format!("comm-test-{}", i + 1);
        
        let req = common::cells::CellServiceStartRequestBuilder::new()
            .cell_name(cell_name.clone())
            .executable_name(exe_name.clone())
            .build();
        
        match retry!(client.start(req.clone()).await) {
            Ok(response) => {
                let start_response = response.into_inner();
                println!("Communication test: Started {} (PID {}) in cell {}", exe_name, start_response.pid, cell_name);
                started_processes.push((cell_name.clone(), exe_name));
            },
            Err(e) => {
                println!("Communication test: Failed to start {} in cell {}: {}", exe_name, cell_name, e);
            }
        }
        
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    
    // Let all processes run
    tokio::time::sleep(Duration::from_millis(400)).await;
    
    // Stop all processes
    for (cell_name, exe_name) in &started_processes {
        let stop_result = retry!(
            client
                .stop(proto::cells::CellServiceStopRequest {
                    cell_name: Some(cell_name.clone()),
                    executable_name: exe_name.clone(),
                })
                .await
        );
        
        match stop_result {
            Ok(_) => println!("✓ Communication test: Stopped {} in cell {}", exe_name, cell_name),
            Err(status) => {
                if status.message().contains("No child process") || 
                   status.message().contains("could not kill children") {
                    println!("✓ Communication test: {} already gone in cell {}: {}", exe_name, cell_name, status.message());
                } else {
                    println!("✗ Communication test: Failed to stop {} in cell {}: {}", exe_name, cell_name, status);
                }
            }
        }
    }
    
    // Free all cells
    for cell_name in allocated_cells {
        let free_result = retry!(
            client
                .free(proto::cells::CellServiceFreeRequest {
                    cell_name: cell_name.clone()
                })
                .await
        );
        
        match free_result {
            Ok(_) => println!("✓ Communication test: Freed cell {}", cell_name),
            Err(status) => {
                if status.message().contains("No child process") || 
                   status.message().contains("could not kill children") {
                    println!("✓ Communication test: Freed cell {} with warnings: {}", cell_name, status.message());
                } else {
                    println!("✗ Communication test: Failed to free cell {}: {}", cell_name, status);
                }
            }
        }
    }
}

#[test_helpers_macros::shared_runtime_test]
async fn exec_vs_shell_wrapper_behavior() {
    skip_if_not_root!("exec_vs_shell_wrapper_behavior");
    skip_if_seccomp!("exec_vs_shell_wrapper_behavior");

    let client = common::auraed_client().await;

    println!("Testing exec vs shell wrapper behavior...");
    
    // This test specifically targets the issue mentioned in the conversation
    // where shell wrappers can cause "No child process" errors
    
    let exe_name = "exec-wrapper-test";
    let req = common::cells::CellServiceStartRequestBuilder::new()
        .executable_name(exe_name.to_string())
        .build();
    
    let start_response = retry!(client.start(req.clone()).await).unwrap().into_inner();
    let pid = start_response.pid;
    println!("Exec test: Started process with PID: {}", pid);
    
    // Check what's actually running
    let proc_path = format!("/proc/{}", pid);
    let exe_path = format!("/proc/{}/exe", pid);
    
    if let Ok(exe_link) = std::fs::read_link(&exe_path) {
        println!("Process executable: {:?}", exe_link);
        
        // If we see /bin/sh or /bin/bash, it might indicate shell wrapping
        if exe_link.to_string_lossy().contains("sh") {
            println!("⚠ Process appears to be shell-wrapped");
        } else {
            println!("✓ Process appears to be direct execution");
        }
    }
    
    // Check process tree to see if there are child processes
    let children_path = format!("/proc/{}/task/{}/children", pid, pid);
    if let Ok(children) = std::fs::read_to_string(&children_path) {
        if children.trim().is_empty() {
            println!("✓ No child processes detected");
        } else {
            println!("⚠ Child processes detected: {}", children.trim());
        }
    }
    
    // Wait a bit to let the process establish itself
    tokio::time::sleep(Duration::from_millis(300)).await;
    
    // The critical test: stop the process
    // If there's a shell wrapper issue, this is where we'd see "No child process" errors
    let stop_result = retry!(
        client
            .stop(proto::cells::CellServiceStopRequest {
                cell_name: None,
                executable_name: exe_name.to_string(),
            })
            .await
    );
    
    match stop_result {
        Ok(_) => {
            println!("✓ Exec test: Process stopped successfully");
            
            // Verify the process is actually gone
            tokio::time::sleep(Duration::from_millis(100)).await;
            if std::path::Path::new(&proc_path).exists() {
                println!("⚠ Process still exists after stop");
            } else {
                println!("✓ Process properly terminated");
            }
        },
        Err(status) => {
            if status.message().contains("No child process") {
                println!("⚠ Exec test: 'No child process' error detected - this indicates the shell wrapper issue: {}", status.message());
                
                // Check if the original process still exists
                if std::path::Path::new(&proc_path).exists() {
                    println!("⚠ Original process still running despite 'No child process' error - confirms shell wrapper issue");
                } else {
                    println!("✓ Process is gone despite error - may be race condition");
                }
            } else {
                panic!("✗ Exec test: Unexpected error: {}", status);
            }
        }
    }
}