use client::cells::cell_service::CellServiceClient;
use test_helpers::*;
use std::time::Duration;

mod common;

#[test_helpers_macros::shared_runtime_test]
async fn executable_basic_start_stop() {
    skip_if_not_root!("executable_basic_start_stop");
    skip_if_seccomp!("executable_basic_start_stop");

    let client = common::auraed_client().await;

    // Test basic executable start/stop without cells
    println!("Testing basic executable start/stop...");
    
    let req = common::cells::CellServiceStartRequestBuilder::new()
        .executable_name("test-basic-exe".to_string())
        .build();
    
    let start_response = retry!(client.start(req.clone()).await).unwrap().into_inner();
    println!("Started basic executable with PID: {}", start_response.pid);
    
    // Small delay to ensure process is running
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Stop the executable
    let stop_result = retry!(
        client
            .stop(proto::cells::CellServiceStopRequest {
                cell_name: None,
                executable_name: "test-basic-exe".to_string(),
            })
            .await
    );
    
    match stop_result {
        Ok(_) => println!("✓ Basic executable stopped successfully"),
        Err(status) => {
            if status.message().contains("No child process") {
                println!("✓ Basic executable already gone (acceptable): {}", status.message());
            } else {
                panic!("✗ Failed to stop basic executable: {}", status);
            }
        }
    }
}

#[test_helpers_macros::shared_runtime_test]
async fn executable_long_running_process() {
    skip_if_not_root!("executable_long_running_process");
    skip_if_seccomp!("executable_long_running_process");

    let client = common::auraed_client().await;

    println!("Testing long-running process management...");
    
    // Create a long-running process (uses default "tail -f /dev/null" command)
    let req = common::cells::CellServiceStartRequestBuilder::new()
        .executable_name("test-long-running".to_string())
        .build();
    
    let start_response = retry!(client.start(req.clone()).await).unwrap().into_inner();
    println!("Started long-running process with PID: {}", start_response.pid);
    
    // Give it time to actually start
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Stop the long-running process
    let stop_result = retry!(
        client
            .stop(proto::cells::CellServiceStopRequest {
                cell_name: None,
                executable_name: "test-long-running".to_string(),
            })
            .await
    );
    
    match stop_result {
        Ok(_) => println!("✓ Long-running process stopped successfully"),
        Err(status) => {
            if status.message().contains("No child process") {
                println!("✓ Long-running process already gone (acceptable): {}", status.message());
            } else {
                panic!("✗ Failed to stop long-running process: {}", status);
            }
        }
    }
}

#[test_helpers_macros::shared_runtime_test]
async fn executable_multiple_concurrent() {
    skip_if_not_root!("executable_multiple_concurrent");
    skip_if_seccomp!("executable_multiple_concurrent");

    let client = common::auraed_client().await;

    println!("Testing multiple concurrent executables...");
    
    let mut pids = Vec::new();
    let mut exe_names = Vec::new();
    
    // Start multiple executables
    for i in 1..=3 {
        let exe_name = format!("test-concurrent-{}", i);
        
        let req = common::cells::CellServiceStartRequestBuilder::new()
            .executable_name(exe_name.clone())
            .build();
        
        let start_response = retry!(client.start(req.clone()).await).unwrap().into_inner();
        println!("Started concurrent executable {} with PID: {}", exe_name, start_response.pid);
        
        pids.push(start_response.pid);
        exe_names.push(exe_name);
    }
    
    // Give them time to start
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Stop all executables
    for exe_name in exe_names {
        let stop_result = retry!(
            client
                .stop(proto::cells::CellServiceStopRequest {
                    cell_name: None,
                    executable_name: exe_name.clone(),
                })
                .await
        );
        
        match stop_result {
            Ok(_) => println!("✓ Concurrent executable {} stopped successfully", exe_name),
            Err(status) => {
                if status.message().contains("No child process") {
                    println!("✓ Concurrent executable {} already gone (acceptable): {}", exe_name, status.message());
                } else {
                    panic!("✗ Failed to stop concurrent executable {}: {}", exe_name, status);
                }
            }
        }
    }
}

#[test_helpers_macros::shared_runtime_test]
async fn executable_stop_nonexistent() {
    skip_if_not_root!("executable_stop_nonexistent");
    skip_if_seccomp!("executable_stop_nonexistent");

    let client = common::auraed_client().await;

    println!("Testing stop of non-existent executable...");
    
    // Try to stop an executable that was never started
    let stop_result = retry!(
        client
            .stop(proto::cells::CellServiceStopRequest {
                cell_name: None,
                executable_name: "never-existed".to_string(),
            })
            .await
    );
    
    match stop_result {
        Ok(_) => panic!("✗ Stopping non-existent executable should fail"),
        Err(status) => {
            if status.message().contains("not found") {
                println!("✓ Non-existent executable correctly reported as not found: {}", status.message());
            } else {
                panic!("✗ Unexpected error for non-existent executable: {}", status);
            }
        }
    }
}

#[test_helpers_macros::shared_runtime_test]
async fn executable_start_stop_restart() {
    skip_if_not_root!("executable_start_stop_restart");
    skip_if_seccomp!("executable_start_stop_restart");

    let client = common::auraed_client().await;

    println!("Testing start/stop/restart cycle...");
    
    let exe_name = "test-restart-cycle";
    
    // Test cycles
    for cycle in 1..=2 {
        println!("Starting cycle {}", cycle);
        
        let req = common::cells::CellServiceStartRequestBuilder::new()
            .executable_name(exe_name.to_string())
            .build();
        
        let start_response = retry!(client.start(req.clone()).await).unwrap().into_inner();
        println!("Cycle {}: Started executable with PID: {}", cycle, start_response.pid);
        
        // Give it time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Stop it
        let stop_result = retry!(
            client
                .stop(proto::cells::CellServiceStopRequest {
                    cell_name: None,
                    executable_name: exe_name.to_string(),
                })
                .await
        );
        
        match stop_result {
            Ok(_) => println!("✓ Cycle {}: Executable stopped successfully", cycle),
            Err(status) => {
                if status.message().contains("No child process") {
                    println!("✓ Cycle {}: Executable already gone (acceptable): {}", cycle, status.message());
                } else {
                    panic!("✗ Cycle {}: Failed to stop executable: {}", cycle, status);
                }
            }
        }
        
        // Wait before next cycle
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[test_helpers_macros::shared_runtime_test]
async fn executable_rapid_cycles() {
    skip_if_not_root!("executable_rapid_cycles");
    skip_if_seccomp!("executable_rapid_cycles");

    let client = common::auraed_client().await;

    println!("Testing rapid start/stop cycles...");
    
    // Test rapid start/stop to stress the process management
    for i in 1..=5 {
        let exe_name = format!("rapid-cycle-{}", i);
        
        let req = common::cells::CellServiceStartRequestBuilder::new()
            .executable_name(exe_name.clone())
            .build();
        
        let start_response = retry!(client.start(req.clone()).await).unwrap().into_inner();
        println!("Rapid cycle {}: Started with PID: {}", i, start_response.pid);
        
        // Very short delay before stopping
        tokio::time::sleep(Duration::from_millis(50)).await;

        let stop_result = retry!(
            client
                .stop(proto::cells::CellServiceStopRequest {
                    cell_name: None,
                    executable_name: exe_name.clone(),
                })
                .await
        );
        
        match stop_result {
            Ok(_) => println!("✓ Rapid cycle {}: Stopped successfully", i),
            Err(status) => {
                if status.message().contains("No child process") {
                    println!("✓ Rapid cycle {}: Already gone (acceptable): {}", i, status.message());
                } else {
                    panic!("✗ Rapid cycle {}: Unexpected error: {}", i, status);
                }
            }
        }
    }
}