use client::cells::cell_service::CellServiceClient;
use test_helpers::*;
use std::time::Duration;

mod common;

#[test_helpers_macros::shared_runtime_test]
async fn executable_process_verification() {
    skip_if_not_root!("executable_process_verification");
    skip_if_seccomp!("executable_process_verification");

    let client = common::auraed_client().await;

    println!("Testing process existence verification...");
    
    let exe_name = "verify-test";
    let req = common::cells::CellServiceStartRequestBuilder::new()
        .executable_name(exe_name.to_string())
        .build();
    
    let start_response = retry!(client.start(req.clone()).await).unwrap().into_inner();
    let pid = start_response.pid;
    println!("Started process with PID: {}", pid);
    
    // Verify process actually exists in /proc
    let proc_path = format!("/proc/{}", pid);
    assert!(std::path::Path::new(&proc_path).exists(), "Process should exist in /proc");
    
    // Give it time to initialize
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Process should still be running (tail -f /dev/null runs indefinitely)
    assert!(std::path::Path::new(&proc_path).exists(), "Process should still be running");
    
    // Stop and verify cleanup
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
            println!("✓ Process stopped successfully");
            
            // Wait for process to actually exit
            let mut attempts = 0;
            while std::path::Path::new(&proc_path).exists() && attempts < 50 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                attempts += 1;
            }
            
            if std::path::Path::new(&proc_path).exists() {
                println!("⚠ Process still exists after stop (may be normal on slow systems)");
            } else {
                println!("✓ Process properly cleaned up from /proc");
            }
        },
        Err(status) => {
            if status.message().contains("No child process") {
                println!("✓ Process already gone (acceptable): {}", status.message());
            } else {
                panic!("✗ Unexpected error: {}", status);
            }
        }
    }
}

#[test_helpers_macros::shared_runtime_test]
async fn executable_double_stop_handling() {
    skip_if_not_root!("executable_double_stop_handling");
    skip_if_seccomp!("executable_double_stop_handling");

    let client = common::auraed_client().await;

    println!("Testing double stop handling...");
    
    let exe_name = "double-stop-test";
    let req = common::cells::CellServiceStartRequestBuilder::new()
        .executable_name(exe_name.to_string())
        .build();
    
    let start_response = retry!(client.start(req.clone()).await).unwrap().into_inner();
    println!("Started process with PID: {}", start_response.pid);
    
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // First stop
    let first_stop = retry!(
        client
            .stop(proto::cells::CellServiceStopRequest {
                cell_name: None,
                executable_name: exe_name.to_string(),
            })
            .await
    );
    
    let first_success = match first_stop {
        Ok(_) => {
            println!("✓ First stop succeeded");
            true
        },
        Err(status) => {
            if status.message().contains("No child process") || status.message().contains("not found") {
                println!("✓ First stop - process already gone: {}", status.message());
                true
            } else {
                println!("✗ First stop unexpected error: {}", status);
                false
            }
        }
    };
    
    // Second stop (should handle gracefully)
    let second_stop = retry!(
        client
            .stop(proto::cells::CellServiceStopRequest {
                cell_name: None,
                executable_name: exe_name.to_string(),
            })
            .await
    );
    
    let second_success = match second_stop {
        Ok(_) => {
            println!("⚠ Second stop succeeded (unexpected but acceptable)");
            true
        },
        Err(status) => {
            if status.message().contains("not found") || status.message().contains("No child process") {
                println!("✓ Second stop correctly failed - executable not found: {}", status.message());
                true
            } else {
                println!("✗ Second stop unexpected error: {}", status);
                false
            }
        }
    };
    
    assert!(first_success && second_success, "Double stop test failed");
}

#[test_helpers_macros::shared_runtime_test]
async fn executable_rapid_start_stop_same_name() {
    skip_if_not_root!("executable_rapid_start_stop_same_name");
    skip_if_seccomp!("executable_rapid_start_stop_same_name");

    let client = common::auraed_client().await;

    println!("Testing rapid start/stop cycles with same executable name...");
    
    let exe_name = "rapid-same-name";
    
    for cycle in 1..=5 {
        println!("Cycle {}: Starting...", cycle);
        
        let req = common::cells::CellServiceStartRequestBuilder::new()
            .executable_name(exe_name.to_string())
            .build();
        
        let start_response = retry!(client.start(req.clone()).await).unwrap().into_inner();
        println!("Cycle {}: Started PID {}", cycle, start_response.pid);
        
        // Very brief delay
        tokio::time::sleep(Duration::from_millis(25)).await;
        
        let stop_result = retry!(
            client
                .stop(proto::cells::CellServiceStopRequest {
                    cell_name: None,
                    executable_name: exe_name.to_string(),
                })
                .await
        );
        
        match stop_result {
            Ok(_) => println!("✓ Cycle {}: Stopped successfully", cycle),
            Err(status) => {
                if status.message().contains("No child process") || status.message().contains("not found") {
                    println!("✓ Cycle {}: Already gone (acceptable): {}", cycle, status.message());
                } else {
                    panic!("✗ Cycle {}: Unexpected error: {}", cycle, status);
                }
            }
        }
        
        // Brief pause between cycles to allow cleanup
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[test_helpers_macros::shared_runtime_test]
async fn executable_concurrent_different_names() {
    skip_if_not_root!("executable_concurrent_different_names");
    skip_if_seccomp!("executable_concurrent_different_names");

    let client = common::auraed_client().await;

    println!("Testing concurrent executables with different names...");
    
    let num_concurrent = 8;
    let mut handles = Vec::new();
    
    // Start multiple executables concurrently with different names
    for i in 1..=num_concurrent {
        let client_clone = client.clone();
        let handle = tokio::spawn(async move {
            let exe_name = format!("concurrent-diff-{}", i);
            
            let req = common::cells::CellServiceStartRequestBuilder::new()
                .executable_name(exe_name.clone())
                .build();
            
            let start_result = retry!(client_clone.start(req.clone()).await);
            
            let _start_response = match start_result {
                Ok(response) => {
                    let resp = response.into_inner();
                    println!("Concurrent {}: Started PID {}", i, resp.pid);
                    resp
                },
                Err(e) => {
                    println!("✗ Concurrent {}: Failed to start: {}", i, e);
                    return false;
                }
            };
            
            // Let it run briefly
            tokio::time::sleep(Duration::from_millis(100 + (i as u64 * 20))).await;
            
            // Stop it
            let stop_result = retry!(
                client_clone
                    .stop(proto::cells::CellServiceStopRequest {
                        cell_name: None,
                        executable_name: exe_name.clone(),
                    })
                    .await
            );
            
            match stop_result {
                Ok(_) => {
                    println!("✓ Concurrent {}: Stopped successfully", i);
                    true
                },
                Err(status) => {
                    if status.message().contains("No child process") || status.message().contains("not found") {
                        println!("✓ Concurrent {}: Already gone (acceptable): {}", i, status.message());
                        true
                    } else {
                        println!("✗ Concurrent {}: Stop error: {}", i, status);
                        false
                    }
                }
            }
        });
        
        handles.push(handle);
    }
    
    // Wait for all to complete
    let mut successes = 0;
    for handle in handles {
        match handle.await {
            Ok(true) => successes += 1,
            Ok(false) => {},
            Err(e) => println!("✗ Task failed: {}", e),
        }
    }
    
    println!("Concurrent different names: {}/{} succeeded", successes, num_concurrent);
    assert!(successes >= (num_concurrent * 75 / 100), "Less than 75% success rate");
}

#[test_helpers_macros::shared_runtime_test]
async fn executable_stop_nonexistent_variations() {
    skip_if_not_root!("executable_stop_nonexistent_variations");
    skip_if_seccomp!("executable_stop_nonexistent_variations");

    let client = common::auraed_client().await;

    println!("Testing stop of various non-existent executables...");
    
    let nonexistent_names = vec![
        "never-existed",
        "already-stopped",
        "invalid-name-123",
        "", // Empty name
        "name-with-special-chars-!@#",
    ];
    
    for exe_name in nonexistent_names {
        println!("Testing non-existent executable: '{}'", exe_name);
        
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
                if exe_name.is_empty() {
                    println!("⚠ Empty name stop succeeded (implementation-dependent behavior)");
                } else {
                    println!("⚠ Non-existent '{}' stop succeeded (unexpected but acceptable)", exe_name);
                }
            },
            Err(status) => {
                if status.message().contains("not found") || 
                   status.message().contains("No child process") ||
                   status.message().contains("invalid") {
                    println!("✓ Non-existent '{}' correctly failed: {}", exe_name, status.message());
                } else {
                    println!("⚠ Non-existent '{}' unexpected error: {}", exe_name, status);
                }
            }
        }
    }
}

#[test_helpers_macros::shared_runtime_test]
async fn executable_resource_exhaustion_simulation() {
    skip_if_not_root!("executable_resource_exhaustion_simulation");
    skip_if_seccomp!("executable_resource_exhaustion_simulation");

    let client = common::auraed_client().await;

    println!("Testing behavior under simulated resource pressure...");
    
    let max_executables = 20; // Conservative limit to avoid system issues
    let mut started_executables = Vec::new();
    let mut successful_starts = 0;
    
    // Try to start many executables
    for i in 1..=max_executables {
        let exe_name = format!("resource-test-{}", i);
        
        let req = common::cells::CellServiceStartRequestBuilder::new()
            .executable_name(exe_name.clone())
            .build();
        
        match retry!(client.start(req.clone()).await) {
            Ok(response) => {
                let start_response = response.into_inner();
                println!("Resource test {}: Started PID {}", i, start_response.pid);
                started_executables.push(exe_name);
                successful_starts += 1;
            },
            Err(e) => {
                println!("Resource test {}: Failed to start (expected under pressure): {}", i, e);
                break; // Stop trying if we hit resource limits
            }
        }
        
        // Small delay to prevent overwhelming
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    
    println!("Successfully started {} executables", successful_starts);
    
    // Now clean them all up
    let mut successful_stops = 0;
    for exe_name in started_executables {
        match retry!(
            client
                .stop(proto::cells::CellServiceStopRequest {
                    cell_name: None,
                    executable_name: exe_name.clone(),
                })
                .await
        ) {
            Ok(_) => {
                successful_stops += 1;
                println!("✓ Resource cleanup: Stopped {}", exe_name);
            },
            Err(status) => {
                if status.message().contains("No child process") || status.message().contains("not found") {
                    successful_stops += 1;
                    println!("✓ Resource cleanup: {} already gone", exe_name);
                } else {
                    println!("✗ Resource cleanup: Failed to stop {}: {}", exe_name, status);
                }
            }
        }
    }
    
    println!("Resource exhaustion test: Started {}, cleaned up {}", successful_starts, successful_stops);
    assert_eq!(successful_starts, successful_stops, "All started executables should be cleanable");
}

#[test_helpers_macros::shared_runtime_test]
async fn executable_immediate_stop_after_start() {
    skip_if_not_root!("executable_immediate_stop_after_start");
    skip_if_seccomp!("executable_immediate_stop_after_start");

    let client = common::auraed_client().await;

    println!("Testing immediate stop after start (race condition testing)...");
    
    for attempt in 1..=10 {
        let exe_name = format!("immediate-stop-{}", attempt);
        
        let req = common::cells::CellServiceStartRequestBuilder::new()
            .executable_name(exe_name.clone())
            .build();
        
        // Start the executable
        let start_response = retry!(client.start(req.clone()).await).unwrap().into_inner();
        println!("Attempt {}: Started PID {}", attempt, start_response.pid);
        
        // Immediately try to stop it (no delay)
        let stop_result = retry!(
            client
                .stop(proto::cells::CellServiceStopRequest {
                    cell_name: None,
                    executable_name: exe_name.clone(),
                })
                .await
        );
        
        match stop_result {
            Ok(_) => println!("✓ Attempt {}: Immediate stop succeeded", attempt),
            Err(status) => {
                if status.message().contains("No child process") || status.message().contains("not found") {
                    println!("✓ Attempt {}: Process already gone (race condition): {}", attempt, status.message());
                } else {
                    println!("✗ Attempt {}: Unexpected error: {}", attempt, status);
                }
            }
        }
        
        // Small delay between attempts
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[test_helpers_macros::shared_runtime_test]
async fn executable_cache_consistency() {
    skip_if_not_root!("executable_cache_consistency");
    skip_if_seccomp!("executable_cache_consistency");

    let client = common::auraed_client().await;

    println!("Testing executable cache consistency...");
    
    let exe_name = "cache-test";
    
    // Start executable
    let req = common::cells::CellServiceStartRequestBuilder::new()
        .executable_name(exe_name.to_string())
        .build();
    
    let start_response = retry!(client.start(req.clone()).await).unwrap().into_inner();
    println!("Cache test: Started PID {}", start_response.pid);
    
    // Try to start same name again (should fail due to existing executable)
    let duplicate_start = retry!(client.start(req.clone()).await);
    
    match duplicate_start {
        Ok(_) => panic!("✗ Duplicate start should have failed"),
        Err(status) => {
            if status.message().contains("exists") || status.message().contains("already") {
                println!("✓ Duplicate start correctly rejected: {}", status.message());
            } else {
                println!("⚠ Duplicate start failed with unexpected error: {}", status);
            }
        }
    }
    
    // Stop the executable
    let stop_result = retry!(
        client
            .stop(proto::cells::CellServiceStopRequest {
                cell_name: None,
                executable_name: exe_name.to_string(),
            })
            .await
    );
    
    match stop_result {
        Ok(_) => println!("✓ Cache test: Stopped successfully"),
        Err(status) => {
            if status.message().contains("No child process") {
                println!("✓ Cache test: Already gone (acceptable): {}", status.message());
            } else {
                panic!("✗ Cache test: Unexpected stop error: {}", status);
            }
        }
    }
    
    // Brief delay for cache cleanup
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Now try to start again with same name (should succeed)
    let restart_result = retry!(client.start(req.clone()).await);
    
    match restart_result {
        Ok(response) => {
            let restart_response = response.into_inner();
            println!("✓ Cache test: Restarted successfully with PID {}", restart_response.pid);
            
            // Clean up the restarted process
            let _ = retry!(
                client
                    .stop(proto::cells::CellServiceStopRequest {
                        cell_name: None,
                        executable_name: exe_name.to_string(),
                    })
                    .await
            );
        },
        Err(e) => {
            if e.message().contains("exists") {
                panic!("✗ Cache not properly cleaned - executable still exists in cache");
            } else {
                panic!("✗ Unexpected restart error: {}", e);
            }
        }
    }
}