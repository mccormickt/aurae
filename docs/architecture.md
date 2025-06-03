# Aurae Architecture Overview

This document provides an overview of the Aurae runtime architecture, explaining how various components work together.

## High-Level Architecture

Aurae is designed as a layered system with the following major components:

```
+---------------------------------------------------------------+
|                     Client Applications                        |
|    (auraescript, aer CLI, custom TypeScript applications)      |
+--------------------------|--------------------------------------+
                          | gRPC over Unix Socket (mTLS)
+--------------------------|--------------------------------------+
|                         auraed                                 |
|  +------------------+   |   +-----------------------------+    |
|  |  Subsystems:     |   |   |  Resource Management:       |    |
|  |  - Cells         |   |   |  - cgroups controller       |    |
|  |  - Runtime       |   |   |  - namespace isolation      |    |
|  |  - Discovery     |   |   |  - process management       |    |
|  |  - Observe       |   |   |  - VM/container management  |    |
|  |  - VMs           |   |   |                             |    |
|  +------------------+   |   +-----------------------------+    |
|                         |                                      |
|  +------------------+   |   +-----------------------------+    |
|  |  Authentication: |   |   |  Observability:             |    |
|  |  - SPIFFE/SPIRE  |   |   |  - eBPF programs            |    |
|  |  - mTLS          |   |   |  - logging                  |    |
|  |  - x509 certs    |   |   |  - metrics                  |    |
|  +------------------+   |   +-----------------------------+    |
+--------------------------|--------------------------------------+
                          | Linux Kernel Interface
+--------------------------|--------------------------------------+
|                     Linux Kernel                               |
|   (cgroups, namespaces, KVM, process management)               |
+---------------------------------------------------------------+
```

## Workload Isolation Architecture

Aurae provides multiple levels of workload isolation:

```
                          Isolation Strength
                                 ↑
+----------------------------+   |
|  Virtual Machine           |   |
|  (KVM-based isolation)     |   |
+----------------------------+   |
                                 |
+----------------------------+   |
|  Spawned Aurae Instance    |   |
|  (MicroVM with nested      |   |
|   auraed daemon)           |   |
+----------------------------+   |
                                 |
+----------------------------+   |
|  Pod                       |   |
|  (Cell in spawned Aurae    |   |
|   instance)                |   |
+----------------------------+   |
                                 |
+----------------------------+   |
|  Cell                      |   |
|  (cgroup with namespace    |   |
|   isolation)               |   |
+----------------------------+   |
                                 |
+----------------------------+   |
|  Executable                |   |
|  (Basic process)           |   |
+----------------------------+   ↓
```

## Cell Architecture

Cells are the fundamental isolation boundary in Aurae:

```
+-------------------------------------------------------+
|                         Cell                          |
|                                                       |
|  +---------------------+  +----------------------+    |
|  |     Executable 1    |  |     Executable 2     |    |
|  | (e.g., sleep-500)   |  | (e.g., nginx)        |    |
|  +---------------------+  +----------------------+    |
|                                                       |
|  Shared Namespaces:                                   |
|  - Network (optional isolation from host)             |
|  - Mount (optional isolation from host)               |
|  - PID (processes can see each other)                 |
|  - IPC (processes can communicate)                    |
|                                                       |
|  Resource Constraints:                                |
|  - CPU quota/weight                                   |
|  - Memory limits                                      |
|  - CPUSet (specific cores)                            |
+-------------------------------------------------------+
```

## Authentication Flow

Aurae uses mTLS for authentication:

```
  Client                                             Server (auraed)
    |                                                    |
    | 1. Client loads certs from ~/.aurae/pki            |
    |-------------------------------------------------->|
    |                                                    | 2. Server loads certs
    |                                                    |    from /etc/aurae/pki
    | 3. TLS handshake with mutual authentication        |
    |<------------------------------------------------->|
    |                                                    |
    | 4. Client identity verified via SPIFFE/SPIRE       |
    |                                                    |
    | 5. Request with authenticated identity             |
    |-------------------------------------------------->|
    |                                                    | 6. Authorization check
    |                                                    |    based on identity
    | 7. Response if authorized                          |
    |<--------------------------------------------------|
```

## Execution Flow: Running a Process in a Cell

```
  Client                          auraed                           Linux Kernel
    |                               |                                   |
    | 1. Request to allocate cell   |                                   |
    |------------------------------>|                                   |
    |                               | 2. Create cgroup                  |
    |                               |---------------------------------->|
    |                               | 3. Set resource limits            |
    |                               |---------------------------------->|
    | 4. Cell allocated response    |                                   |
    |<------------------------------|                                   |
    |                               |                                   |
    | 5. Request to start executable|                                   |
    |------------------------------>|                                   |
    |                               | 6. Create namespaces              |
    |                               |---------------------------------->|
    |                               | 7. Start process in cell          |
    |                               |---------------------------------->|
    | 8. Process started response   |                                   |
    |<------------------------------|                                   |
```

## Pod Architecture

Pods in Aurae provide an additional isolation layer:

```
+-------------------------------------------------------+
|                Spawned Aurae Instance                 |
| (MicroVM with its own Linux kernel)                   |
|                                                       |
|  +---------------------+                              |
|  |        Cell         |                              |
|  |                     |                              |
|  |  +---------------+  |                              |
|  |  | Container 1   |  |                              |
|  |  +---------------+  |                              |
|  |                     |                              |
|  |  +---------------+  |                              |
|  |  | Container 2   |  |                              |
|  |  +---------------+  |                              |
|  +---------------------+                              |
|                                                       |
|  auraed instance running as PID 1                     |
+-------------------------------------------------------+
             |
             | Network Bridge + mTLS connection
             v
+-------------------------------------------------------+
|                   Host Aurae Instance                 |
+-------------------------------------------------------+
```

## Subsystem Architecture

Aurae's functionality is organized into subsystems:

```
+---------------------------------------------------------------+
|                         auraed                                |
|                                                               |
|  +-------------------+  +------------------+  +-------------+ |
|  |  Runtime Subsystem |  | Cells Subsystem  |  | VM Subsystem| |
|  |  - Process mgmt    |  | - cgroup mgmt    |  | - KVM mgmt  | |
|  |  - Executable API  |  | - Resource ctrl  |  | - VM API    | |
|  +-------------------+  +------------------+  +-------------+ |
|                                                               |
|  +-------------------+  +------------------+                  |
|  | Observe Subsystem  |  |Discovery Subsystem|                |
|  | - Logging          |  | - Service         |                |
|  | - POSIX signals    |  |   discovery       |                |
|  | - eBPF hooks       |  | - Health checks   |                |
|  +-------------------+  +------------------+                  |
|                                                               |
+---------------------------------------------------------------+
```

## Data Flow Architecture

```
  +----------------+     +-----------------+     +----------------+
  |                |     |                 |     |                |
  | AuraeScript    |     | aer CLI         |     | Custom Client  |
  | TypeScript     |     | Command Line    |     | Application    |
  |                |     |                 |     |                |
  +-------+--------+     +--------+--------+     +-------+-------+
          |                       |                      |
          |                       |                      |
          v                       v                      v
  +-------+-------------------------------------------+-------+
  |                                                           |
  |               gRPC over Unix Domain Socket                |
  |                  (mTLS authentication)                    |
  |                                                           |
  +---------------------------+---------------------------+---+
                              |
                              v
  +---------------------------+---------------------------+---+
  |                                                           |
  |                      auraed Daemon                        |
  |                                                           |
  +-----------+-------------------+-------------------------+-+
              |                   |                         |
              v                   v                         v
  +-----------+----+  +-----------+------+  +---------------+--+
  |                |  |                  |  |                  |
  | System Control |  | Resource Control |  | Workload Control |
  | Functionality  |  | Functionality    |  | Functionality    |
  |                |  |                  |  |                  |
  +----------------+  +------------------+  +------------------+
```

## Future Architecture Considerations

1. **High Availability**: Clustering of auraed instances for failover
2. **Multi-node Orchestration**: Coordination between multiple nodes
3. **Integration with Kubernetes**: Using Aurae as a node-level runtime for Kubernetes
4. **Enhanced Security**: More granular authorization policies
5. **Performance Optimizations**: Reducing overhead for real-time workloads