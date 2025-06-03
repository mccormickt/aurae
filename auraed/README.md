# Aurae Daemon (auraed)

The Aurae Daemon (auraed) is the core runtime daemon that powers the Aurae project. It's a memory-safe PID-1 initialization system and process manager designed to remotely schedule processes, containers, and virtual machines as well as set node configurations.

## Overview

Auraed runs as a gRPC server which listens over a Unix domain socket by default at:

```
/var/run/aurae/aurae.sock
```

Through the Aurae daemon, you can:
- Manage workloads in isolated cells (cgroups)
- Run containers and virtual machines
- Schedule processes with resource constraints
- Observe system events and logs

## Project Status

> **EARLY DEVELOPMENT!**
>
> The Aurae project and API can change without notice.
>
> Do not run the project in production until further notice!

## Features

- **Memory Safety**: Built in Rust for reliability and security
- **Workload Isolation**: Uses cgroups and namespaces to isolate workloads
- **mTLS Authentication**: [SPIFFE]/[SPIRE]-backed identity for secure communication
- **API-driven**: All functionality exposed via gRPC API
- **Resource Management**: Fine-grained control of CPU, memory, and other resources
- **Observability**: eBPF-powered introspection capabilities

## Building from Source

### Dependencies

The following dependencies are required:

- [Rust](https://rustup.rs)
- [Protocol Buffer Compiler](https://grpc.io/docs/protoc-installation/)
- [buf](https://docs.buf.build/installation)
- [musl libc](https://musl.libc.org)
- [BPF Linker](https://github.com/aya-rs/bpf-linker)

#### Ubuntu

```bash
sudo apt-get install -y protobuf-compiler musl-tools build-essential
```

#### Fedora

```bash
sudo dnf install -y protobuf-compiler musl-gcc '@Development Tools'
```

#### Arch

```bash
yay -S protobuf buf musl gcc
```

### Building

We recommend using the main Aurae repository for building:

```bash
git clone https://github.com/aurae-runtime/aurae.git
cd aurae
make pki config  # Create certificates and config
make auraed      # Build just the daemon
```

Or use Cargo directly:

```bash
cargo clippy
cargo install --debug --path .
```

## Running auraed

### As a Daemon

Aurae can run alongside your current init system:

```bash
sudo -E auraed -v
```

### As PID 1

Running as `/sbin/init` is currently under active development.

### In a Container

It's possible to run auraed in a container with the following considerations:
- You need to populate mTLS certificate material into the container
- You need to expose either the socket or a network interface

Example:

```bash
# Build the container
sudo -E docker build -t aurae:latest -f images/Dockerfile.nested .

# Run the container
make pki config  # If not already done
sudo -E docker run -v /etc/aurae:/etc/aurae aurae:latest
```

## Working with Aurae

Once auraed is running, you can interact with it using [AuraeScript](https://aurae.io/auraescript/) or the `aer` CLI tool:

```bash
# Create a new cell
auraescript examples/cells/create-cell.ts

# Run a process in the cell
auraescript examples/cells/run-sleep-in-cell.ts

# List cells
aer runtime list
```

## Documentation

- [Full Documentation](https://aurae.io/auraed)
- [API Reference](https://aurae.io/stdlib/v0)
- [Quickstart Guide](https://aurae.io/quickstart)
- [Building from Source](https://aurae.io/build)
- [Getting Started Guide](../docs/getting-started.md) - Comprehensive step-by-step instructions
- [Architecture Overview](../docs/architecture.md) - Visual guide to Aurae's design

## Contributing

The Aurae project welcomes contributions of all kinds and sizes. Please read the [getting involved](https://aurae.io/community/#getting-involved) documentation before contributing.

To get involved:
- Join the [Discord](https://discord.gg/aTe2Rjg5rq)
- Read the [Contribution Guidelines](https://github.com/aurae-runtime/community/blob/main/CONTRIBUTING.md)
- Sign the [CLA](https://cla.nivenly.org/)

## License

Aurae is licensed under [Apache License 2.0](https://github.com/aurae-runtime/aurae/blob/main/LICENSE).