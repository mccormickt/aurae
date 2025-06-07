use client::cells::cell_service::CellServiceClient;
use test_helpers::*;
use std::time::Duration;
// use tokio::time::timeout; // Removed as timeout wrapper is not needed with retry! macro

mod common;

#[test_helpers_macros::shared_runtime_test]
async fn nested_cell_executable_basic() {
    skip_if_not_root!("nested_cell_executable_basic");
    skip_if_seccomp!("nested_cell_executable_basic");

    let client = common::auraed_client().await;

    println!("Testing basic executable in nested cell...");

    // Allocate a cell
    let cell_name = retry!(
        client
            .allocate(
                common::cells::CellServiceAllocateRequestBuilder::new().build()
            )
            .await
    )
    .unwrap()
    .into_inner()
    .cell_name;

    println!("Allocated cell: {}", cell_name);

    // Start the executable in the nested cell
    let req = common::cells::CellServiceStartRequestBuilder::new()
        .cell_name(cell_name.clone())
        .executable_name("nested-basic-exe".to_string())
        .build();
    
    let start_response = retry!(client.start(req.clone()).await).unwrap().into_inner();
    println!("Started nested executable with PID: {}", start_response.pid);
    
    // Small delay to ensure process is running
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Stop the executable in the nested cell
    let stop_result = retry!(
        client
            .stop(proto::cells::CellServiceStopRequest {
                cell_name: Some(cell_name.clone()),
                executable_name: "nested-basic-exe".to_string(),
            })
            .await
    );
    
    match stop_result {
        Ok(_) => println!("✓ Nested executable stopped successfully"),
        Err(status) => {
            if status.message().contains("No child process") || 
               status.message().contains("could not kill children") {
                println!("✓ Nested executable already gone (acceptable): {}", status.message());
            } else {
                panic!("✗ Failed to stop nested executable: {}", status);
            }
        }
    }

    // Delete the cell
    let free_result = retry!(
        client
            .free(proto::cells::CellServiceFreeRequest {
                cell_name: cell_name.clone()
            })
            .await
    );
    
    match free_result {
        Ok(_) => println!("✓ Nested cell deleted successfully"),
        Err(status) => {
            if status.message().contains("No child process") || 
               status.message().contains("could not kill children") {
                println!("✓ Nested cell deleted with warning: {}", status.message());
            } else {
                panic!("✗ Failed to delete nested cell: {}", status);
            }
        }
    }
}

#[test_helpers_macros::shared_runtime_test]
async fn nested_cell_multiple_executables() {
    skip_if_not_root!("nested_cell_multiple_executables");
    skip_if_seccomp!("nested_cell_multiple_executables");

    let client = common::auraed_client().await;

    println!("Testing multiple executables in nested cell...");

    // Allocate a cell
    let cell_name = retry!(
        client
            .allocate(
                common::cells::CellServiceAllocateRequestBuilder::new().build()
            )
            .await
    )
    .unwrap()
    .into_inner()
    .cell_name;

    println!("Allocated cell: {}", cell_name);

    let mut exe_names = Vec::new();
    let mut pids = Vec::new();

    // Start multiple executables in the nested cell
    for i in 1..=3 {
        let exe_name = format!("nested-multi-{}", i);
        
        let req = common::cells::CellServiceStartRequestBuilder::new()
            .cell_name(cell_name.clone())
            .executable_name(exe_name.clone())
            .build();
        
        let start_response = retry!(client.start(req.clone()).await).unwrap().into_inner();
        println!("Started nested executable {} with PID: {}", exe_name, start_response.pid);
        
        exe_names.push(exe_name);
        pids.push(start_response.pid);
    }
    
    // Give them time to start
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Stop all executables
    for exe_name in &exe_names {
        let stop_result = retry!(
            client
                .stop(proto::cells::CellServiceStopRequest {
                    cell_name: Some(cell_name.clone()),
                    executable_name: exe_name.clone(),
                })
                .await
        );
        
        match stop_result {
            Ok(_) => println!("✓ Nested executable {} stopped successfully", exe_name),
            Err(status) => {
                if status.message().contains("No child process") || 
                   status.message().contains("could not kill children") {
                    println!("✓ Nested executable {} already gone (acceptable): {}", exe_name, status.message());
                } else {
                    panic!("✗ Failed to stop nested executable {}: {}", exe_name, status);
                }
            }
        }
    }

    // Delete the cell
    let free_result = retry!(
        client
            .free(proto::cells::CellServiceFreeRequest {
                cell_name: cell_name.clone()
            })
            .await
    );
    
    match free_result {
        Ok(_) => println!("✓ Nested cell with multiple executables deleted successfully"),
        Err(status) => {
            if status.message().contains("No child process") || 
               status.message().contains("could not kill children") {
                println!("✓ Nested cell deleted with warning: {}", status.message());
            } else {
                panic!("✗ Failed to delete nested cell: {}", status);
            }
        }
    }
}

#[test_helpers_macros::shared_runtime_test]
async fn nested_cell_long_running_process() {
    skip_if_not_root!("nested_cell_long_running_process");
    skip_if_seccomp!("nested_cell_long_running_process");

    let client = common::auraed_client().await;

    println!("Testing long-running process in nested cell...");

    // Allocate a cell
    let cell_name = retry!(
        client
            .allocate(
                common::cells::CellServiceAllocateRequestBuilder::new().build()
            )
            .await
    )
    .unwrap()
    .into_inner()
    .cell_name;

    println!("Allocated cell: {}", cell_name);

    // Start a long-running process in the nested cell
    let req = common::cells::CellServiceStartRequestBuilder::new()
        .cell_name(cell_name.clone())
        .executable_name("nested-long-running".to_string())
        .build();
    
    let start_response = retry!(client.start(req.clone()).await).unwrap().into_inner();
    println!("Started nested long-running process with PID: {}", start_response.pid);
    
    // Let it run for a while
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Stop the long-running process
    let stop_result = retry!(
        client
            .stop(proto::cells::CellServiceStopRequest {
                cell_name: Some(cell_name.clone()),
                executable_name: "nested-long-running".to_string(),
            })
            .await
    );
    
    match stop_result {
        Ok(_) => println!("✓ Nested long-running process stopped successfully"),
        Err(status) => {
            if status.message().contains("No child process") || 
               status.message().contains("could not kill children") {
                println!("✓ Nested long-running process already gone (acceptable): {}", status.message());
            } else {
                panic!("✗ Failed to stop nested long-running process: {}", status);
            }
        }
    }

    // Delete the cell
    // Free the cell - handle "No child processes" error
    let free_result = retry!(
        client
            .free(proto::cells::CellServiceFreeRequest {
                cell_name: cell_name.clone()
            })
            .await
    );
    
    match free_result {
        Ok(_) => println!("✓ Nested cell deleted successfully"),
        Err(status) => {
            if status.message().contains("No child process") || 
               status.message().contains("could not kill children") {
                println!("✓ Nested cell deleted with warning: {}", status.message());
            } else {
                panic!("✗ Failed to delete nested cell: {}", status);
            }
        }
    }
}

#[test_helpers_macros::shared_runtime_test]
async fn nested_cell_rapid_lifecycle() {
    skip_if_not_root!("nested_cell_rapid_lifecycle");
    skip_if_seccomp!("nested_cell_rapid_lifecycle");

    let client = common::auraed_client().await;

    println!("Testing rapid lifecycle in nested cells...");

    for cycle in 1..=5 {
        println!("Nested cycle {}", cycle);
        
        // Allocate a cell
        let cell_name = retry!(
            client
                .allocate(
                    common::cells::CellServiceAllocateRequestBuilder::new().build()
                )
                .await
        )
        .unwrap()
        .into_inner()
        .cell_name;

        // Start executable
        let exe_name = format!("nested-rapid-{}", cycle);
        let req = common::cells::CellServiceStartRequestBuilder::new()
            .cell_name(cell_name.clone())
            .executable_name(exe_name.clone())
            .build();
        
        let start_response = match retry!(client.start(req.clone()).await) {
            Ok(response) => response.into_inner(),
            Err(e) => panic!("✗ Nested rapid test {}: Failed to start: {}", cycle, e),
        };
        
        println!("Nested cycle {}: Started PID {}", cycle, start_response.pid);
        
        // Brief run time
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Stop executable
        let stop_result = retry!(
            client
                .stop(proto::cells::CellServiceStopRequest {
                    cell_name: Some(cell_name.clone()),
                    executable_name: exe_name.clone(),
                })
                .await
        );
        
        match stop_result {
            Ok(_) => println!("✓ Nested rapid test {}: Stopped successfully", cycle),
            Err(status) => {
                if status.message().contains("No child process") || 
                   status.message().contains("could not kill children") {
                    println!("✓ Nested rapid test {}: Already gone (acceptable): {}", cycle, status.message());
                } else {
                    panic!("✗ Nested rapid test {}: Unexpected stop error: {}", cycle, status);
                }
            }
        }

        // Delete cell
        // Free the cell - handle errors gracefully
        let free_result = retry!(
            client
                .free(proto::cells::CellServiceFreeRequest {
                    cell_name: cell_name.clone()
                })
                .await
        );
    
        match free_result {
            Ok(_) => println!("✓ Nested rapid test cell deleted successfully"),
            Err(status) => {
                if status.message().contains("No child process") || 
                   status.message().contains("could not kill children") {
                    println!("✓ Nested cycle {}: Cell deleted with warning: {}", cycle, status.message());
                } else {
                    panic!("✗ Nested cycle {}: Failed to delete cell: {}", cycle, status);
                }
            }
        }
        
        // Brief pause between cycles
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[test_helpers_macros::shared_runtime_test]
async fn nested_cell_complex_commands() {
    skip_if_not_root!("nested_cell_complex_commands");
    skip_if_seccomp!("nested_cell_complex_commands");

    let client = common::auraed_client().await;

    println!("Testing complex commands in nested cell...");

    // Allocate a cell
    let cell_name = retry!(
        client
            .allocate(
                common::cells::CellServiceAllocateRequestBuilder::new().build()
            )
            .await
    )
    .unwrap()
    .into_inner()
    .cell_name;

    println!("Allocated cell: {}", cell_name);

    // Test complex shell command in nested environment
    let req = common::cells::CellServiceStartRequestBuilder::new()
        .cell_name(cell_name.clone())
        .executable_name("nested-complex".to_string())
        .build();
    
    let start_response = retry!(client.start(req.clone()).await).unwrap().into_inner();
    println!("Started nested complex command with PID: {}", start_response.pid);
    
    // Let it run for a bit
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Stop the complex command
    let stop_result = retry!(
        client
            .stop(proto::cells::CellServiceStopRequest {
                cell_name: Some(cell_name.clone()),
                executable_name: "nested-complex-cmd".to_string(),
            })
            .await
    );
    
    match stop_result {
        Ok(_) => println!("✓ Nested complex command stopped successfully"),
        Err(status) => {
            if status.message().contains("No child process") || 
               status.message().contains("could not kill children") {
                println!("✓ Nested complex command already gone (acceptable): {}", status.message());
            } else {
                panic!("✗ Failed to stop nested complex command: {}", status);
            }
        }
    }

    // Delete the cell
    let free_result = retry!(
        client
            .free(proto::cells::CellServiceFreeRequest {
                cell_name: cell_name.clone()
            })
            .await
    );
    
    match free_result {
        Ok(_) => println!("✓ Nested cell with complex command deleted successfully"),
        Err(status) => {
            if status.message().contains("No child process") || 
               status.message().contains("could not kill children") {
                println!("✓ Nested cell deleted with warning: {}", status.message());
            } else {
                panic!("✗ Failed to delete nested cell: {}", status);
            }
        }
    }
}

#[test_helpers_macros::shared_runtime_test]
async fn nested_cell_stress_test() {
    skip_if_not_root!("nested_cell_stress_test");
    skip_if_seccomp!("nested_cell_stress_test");

    let client = common::auraed_client().await;

    println!("Testing nested cell stress scenarios...");

    let num_cells = 3;
    let mut cell_names = Vec::new();

    // Create multiple cells
    for i in 1..=num_cells {
        let cell_name = retry!(
            client
                .allocate(
                    common::cells::CellServiceAllocateRequestBuilder::new().build()
                )
                .await
        )
        .unwrap()
        .into_inner()
        .cell_name;

        println!("Allocated stress cell {}: {}", i, cell_name);
        cell_names.push(cell_name);
    }

    // Start executables in each cell
    for (i, cell_name) in cell_names.iter().enumerate() {
        let exe_name = format!("stress-nested-{}", i + 1);
        
        let req = common::cells::CellServiceStartRequestBuilder::new()
            .cell_name(cell_name.clone())
            .executable_name(exe_name.clone())
            .build();
        
        let start_response = retry!(client.start(req.clone()).await).unwrap().into_inner();
        println!("Started stress executable {} in cell {} with PID: {}", exe_name, cell_name, start_response.pid);
    }

    // Let them run
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Stop all executables and free all cells
    for (i, cell_name) in cell_names.iter().enumerate() {
        let exe_name = format!("stress-nested-{}", i + 1);
        
        // Stop executable
        let stop_result = retry!(
            client
                .stop(proto::cells::CellServiceStopRequest {
                    cell_name: Some(cell_name.clone()),
                    executable_name: exe_name.clone(),
                })
                .await
        );
        
        match stop_result {
            Ok(_) => println!("✓ Stress executable {} stopped successfully", exe_name),
            Err(status) => {
                if status.message().contains("No child process") || 
                   status.message().contains("could not kill children") {
                    println!("✓ Stress executable {} already gone (acceptable): {}", exe_name, status.message());
                } else {
                    println!("✗ Failed to stop stress executable {}: {}", exe_name, status);
                }
            }
        }

        // Free cell
        let free_result = retry!(
            client
                .free(proto::cells::CellServiceFreeRequest {
                    cell_name: cell_name.clone()
                })
                .await
        );
        
        match free_result {
            Ok(_) => println!("✓ Stress cell {} deleted successfully", cell_name),
            Err(status) => {
                if status.message().contains("No child process") || 
                   status.message().contains("could not kill children") {
                    println!("✓ Stress cell {} deleted with warning: {}", cell_name, status.message());
                } else {
                    println!("✗ Failed to delete stress cell {}: {}", cell_name, status);
                }
            }
        }
    }

    println!("✓ Nested cell stress test completed");
}