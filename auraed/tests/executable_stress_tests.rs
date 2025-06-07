use client::cells::cell_service::CellServiceClient;
use test_helpers::*;
use std::time::Duration;

mod common;

#[test_helpers_macros::shared_runtime_test]
async fn executable_rapid_start_stop() {
    skip_if_not_root!("executable_rapid_start_stop");
    skip_if_seccomp!("executable_rapid_start_stop");

    let client = common::auraed_client().await;

    println!("Testing rapid start/stop cycles...");
    
    for i in 1..=10 {
        let exe_name = format!("rapid-test-{}", i);
        
        // Start executable
        let req = common::cells::CellServiceStartRequestBuilder::new()
            .executable_name(exe_name.clone())
            .build();
        
        let start_response = match retry!(client.start(req.clone()).await) {
            Ok(response) => response.into_inner(),
            Err(e) => panic!("✗ Rapid test {}: Failed to start: {}", i, e),
        };
        
        println!("Rapid test {}: Started PID {}", i, start_response.pid);
        
        // Immediately try to stop it
        let stop_result = retry!(
            client
                .stop(proto::cells::CellServiceStopRequest {
                    cell_name: None,
                    executable_name: exe_name.clone(),
                })
                .await
        );
        
        match stop_result {
            Ok(_) => println!("✓ Rapid test {}: Stopped successfully", i),
            Err(status) => {
                if status.message().contains("No child process") || 
                   status.message().contains("not found") {
                    println!("✓ Rapid test {}: Already gone (acceptable): {}", i, status.message());
                } else {
                    panic!("✗ Rapid test {}: Unexpected stop error: {}", i, status);
                }
            },
        }
        
        // Small delay to prevent overwhelming the system
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[test_helpers_macros::shared_runtime_test]
async fn executable_concurrent_stress() {
    skip_if_not_root!("executable_concurrent_stress");
    skip_if_seccomp!("executable_concurrent_stress");

    let client = common::auraed_client().await;

    println!("Testing concurrent executable stress...");
    
    let num_concurrent = 15;
    let mut handles = Vec::new();
    
    // Start multiple executables concurrently
    for i in 1..=num_concurrent {
        let client_clone = client.clone();
        let handle = tokio::spawn(async move {
            let exe_name = format!("stress-concurrent-{}", i);
            
            // Start
            let req = common::cells::CellServiceStartRequestBuilder::new()
                .executable_name(exe_name.clone())
                .build();
            
            let start_response = match retry!(client_clone.start(req.clone()).await) {
                Ok(response) => response.into_inner(),
                Err(e) => {
                    println!("✗ Concurrent stress {}: Failed to start: {}", i, e);
                    return false;
                },
            };
            
            println!("Concurrent stress {}: Started PID {}", i, start_response.pid);
            
            // Let it run briefly
            tokio::time::sleep(Duration::from_millis(100 + (i as u64 * 10))).await;
            
            // Stop
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
                    println!("✓ Concurrent stress {}: Stopped successfully", i);
                    true
                },
                Err(status) => {
                    if status.message().contains("No child process") || 
                       status.message().contains("not found") {
                        println!("✓ Concurrent stress {}: Already gone (acceptable): {}", i, status.message());
                        true
                    } else {
                        println!("✗ Concurrent stress {}: Unexpected stop error: {}", i, status);
                        false
                    }
                },
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
            Err(e) => println!("✗ Task panicked: {}", e),
        }
    }
    
    println!("Concurrent stress test: {}/{} succeeded", successes, num_concurrent);
    assert!(successes >= (num_concurrent * 80 / 100), "Less than 80% success rate");
}

#[test_helpers_macros::shared_runtime_test]
async fn executable_memory_stress() {
    skip_if_not_root!("executable_memory_stress");
    skip_if_seccomp!("executable_memory_stress");

    let client = common::auraed_client().await;

    println!("Testing memory allocation stress with many executables...");
    
    let num_executables = 25;
    let mut exe_names = Vec::new();
    
    // Start many executables to stress memory management
    for i in 1..=num_executables {
        let exe_name = format!("memory-stress-{}", i);
        
        let req = common::cells::CellServiceStartRequestBuilder::new()
            .executable_name(exe_name.clone())
            .build();
        
        match retry!(client.start(req.clone()).await) {
            Ok(response) => {
                let start_response = response.into_inner();
                println!("Memory stress {}: Started PID {}", i, start_response.pid);
                exe_names.push(exe_name);
            },
            Err(e) => {
                println!("✗ Memory stress {}: Failed to start: {}", i, e);
            },
        }
        
        // Small delay to prevent overwhelming
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    
    println!("Started {} executables, now stopping them...", exe_names.len());
    
    // Stop all executables
    let mut stopped_count = 0;
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
            Ok(_) => {
                stopped_count += 1;
                println!("✓ Memory stress: Stopped {}", exe_name);
            },
            Err(status) => {
                if status.message().contains("No child process") || 
                   status.message().contains("not found") {
                    stopped_count += 1;
                    println!("✓ Memory stress: {} already gone (acceptable)", exe_name);
                } else {
                    println!("✗ Memory stress: Failed to stop {}: {}", exe_name, status);
                }
            },
        }
    }
    
    println!("Memory stress test: Stopped {}/{} executables", stopped_count, num_executables);
    assert!(stopped_count >= (num_executables * 85 / 100), "Less than 85% stop success rate");
}

#[test_helpers_macros::shared_runtime_test]
async fn executable_timing_edge_cases() {
    skip_if_not_root!("executable_timing_edge_cases");
    skip_if_seccomp!("executable_timing_edge_cases");

    let client = common::auraed_client().await;

    println!("Testing timing edge cases...");
    
    // Test 1: Stop immediately after start
    println!("Edge case 1: Stop immediately after start");
    let req = common::cells::CellServiceStartRequestBuilder::new()
        .executable_name("edge-immediate-stop".to_string())
        .build();
    
    let start_response = retry!(client.start(req.clone()).await).unwrap().into_inner();
    println!("Started immediate-stop test with PID: {}", start_response.pid);
    
    // Stop without any delay
    let stop_result = retry!(
        client
            .stop(proto::cells::CellServiceStopRequest {
                cell_name: None,
                executable_name: "edge-immediate-stop".to_string(),
            })
            .await
    );
    
    match stop_result {
        Ok(_) => println!("✓ Edge case 1: Immediate stop succeeded"),
        Err(status) => {
            if status.message().contains("No child process") {
                println!("✓ Edge case 1: Process already gone (acceptable): {}", status.message());
            } else {
                panic!("✗ Edge case 1: Unexpected error: {}", status);
            }
        }
    }
    
    // Test 2: Multiple stop attempts on same executable
    println!("Edge case 2: Multiple stop attempts");
    let req2 = common::cells::CellServiceStartRequestBuilder::new()
        .executable_name("edge-multi-stop".to_string())
        .build();
    
    let start_response2 = retry!(client.start(req2.clone()).await).unwrap().into_inner();
    println!("Started multi-stop test with PID: {}", start_response2.pid);
    
    tokio::time::sleep(Duration::from_millis(50)).await;
    
    // First stop
    let stop_result1 = retry!(
        client
            .stop(proto::cells::CellServiceStopRequest {
                cell_name: None,
                executable_name: "edge-multi-stop".to_string(),
            })
            .await
    );
    
    // Second stop (should handle gracefully)
    let stop_result2 = retry!(
        client
            .stop(proto::cells::CellServiceStopRequest {
                cell_name: None,
                executable_name: "edge-multi-stop".to_string(),
            })
            .await
    );
    
    // Both should either succeed or fail with expected errors
    let first_ok = match stop_result1 {
        Ok(_) => {
            println!("✓ Edge case 2: First stop succeeded");
            true
        },
        Err(status) => {
            if status.message().contains("No child process") || status.message().contains("not found") {
                println!("✓ Edge case 2: First stop - process already gone: {}", status.message());
                true
            } else {
                println!("✗ Edge case 2: First stop unexpected error: {}", status);
                false
            }
        }
    };
    
    let second_ok = match stop_result2 {
        Ok(_) => {
            println!("✓ Edge case 2: Second stop succeeded (unexpected but acceptable)");
            true
        },
        Err(status) => {
            if status.message().contains("not found") || status.message().contains("No child process") {
                println!("✓ Edge case 2: Second stop correctly failed - not found: {}", status.message());
                true
            } else {
                println!("✗ Edge case 2: Second stop unexpected error: {}", status);
                false
            }
        }
    };
    
    assert!(first_ok && second_ok, "Edge case 2 failed");
}

#[test_helpers_macros::shared_runtime_test]
async fn executable_resource_cleanup() {
    skip_if_not_root!("executable_resource_cleanup");
    skip_if_seccomp!("executable_resource_cleanup");

    let client = common::auraed_client().await;

    println!("Testing resource cleanup after process termination...");
    
    let num_cycles = 10;
    
    for cycle in 1..=num_cycles {
        let exe_name = format!("cleanup-test-{}", cycle);
        
        // Start
        let req = common::cells::CellServiceStartRequestBuilder::new()
            .executable_name(exe_name.clone())
            .build();
        
        let start_response = retry!(client.start(req.clone()).await).unwrap().into_inner();
        println!("Cleanup cycle {}: Started PID {}", cycle, start_response.pid);
        
        // Let it run briefly
        tokio::time::sleep(Duration::from_millis(50)).await;
        
        // Stop
        let stop_result = retry!(
            client
                .stop(proto::cells::CellServiceStopRequest {
                    cell_name: None,
                    executable_name: exe_name.clone(),
                })
                .await
        );
        
        match stop_result {
            Ok(_) => println!("✓ Cleanup cycle {}: Stopped successfully", cycle),
            Err(status) => {
                if status.message().contains("No child process") || 
                   status.message().contains("not found") {
                    println!("✓ Cleanup cycle {}: Already gone (acceptable): {}", cycle, status.message());
                } else {
                    panic!("✗ Cleanup cycle {}: Unexpected error: {}", cycle, status);
                }
            }
        }
        
        // Try to start the same name again (should work if cleanup was proper)
        let req_again = common::cells::CellServiceStartRequestBuilder::new()
            .executable_name(exe_name.clone())
            .build();
        
        let start_again_result = retry!(client.start(req_again.clone()).await);
        match start_again_result {
            Ok(response) => {
                let start_response = response.into_inner();
                println!("✓ Cleanup cycle {}: Restarted successfully with PID {}", cycle, start_response.pid);
                
                // Clean up the restarted process
                let _ = retry!(
                    client
                        .stop(proto::cells::CellServiceStopRequest {
                            cell_name: None,
                            executable_name: exe_name.clone(),
                        })
                        .await
                );
            },
            Err(e) => {
                if e.message().contains("exists") {
                    panic!("✗ Cleanup cycle {}: Resource not cleaned up properly - executable still exists", cycle);
                } else {
                    panic!("✗ Cleanup cycle {}: Unexpected restart error: {}", cycle, e);
                }
            }
        }
    }
    
    println!("✓ Resource cleanup test completed successfully");
}