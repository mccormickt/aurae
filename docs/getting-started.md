# Getting Started with Aurae

This guide will help you get started with Aurae, from installation to running your first workload.

## What is Aurae?

Aurae is a memory-safe runtime daemon, process manager, and PID-1 initialization system designed to remotely schedule processes, containers, and virtual machines. It provides enterprise workload isolation techniques and can complement higher order schedulers like Kubernetes.

## System Requirements

- Linux operating system (x86_64 architecture currently supported)
- Internet connection for downloading dependencies
- Administrative privileges

## Prerequisites

Before installing Aurae, you'll need to install the following dependencies:

### Installing Dependencies

#### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install -y protobuf-compiler musl-tools build-essential llvm-15-dev libclang-15-dev
```

#### Fedora/RHEL/CentOS

```bash
sudo dnf install -y protobuf-compiler musl-gcc '@Development Tools'
```

#### Arch Linux

```bash
yay -S protobuf buf musl gcc
```

### Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustup target add x86_64-unknown-linux-musl
```

### Install buf

```bash
# Download and install buf
curl -sSL "https://github.com/bufbuild/buf/releases/download/v1.17.0/buf-Linux-x86_64" -o buf
chmod +x buf
sudo mv buf /usr/local/bin/
```

## Installing Aurae

### Clone the Repository

```bash
git clone https://github.com/aurae-runtime/aurae.git
cd aurae
```

### Build Aurae

Build the entire project:

```bash
make pki config  # Generate certificates and config file
make build       # Build all components
```

Alternatively, build only specific components:

```bash
make auraed      # Build just the daemon
make auraescript # Build just the scripting tool
```

## Configuration

Aurae uses mTLS for authentication. The `make pki config` command creates:

1. A root CA certificate
2. Server certificates for auraed
3. Client certificates for local authentication
4. A configuration file at `~/.aurae/config`

### Creating Additional Clients

After the initial PKI has been generated, you can create additional client certificates:

```bash
./hack/certgen-client <name>
```

Where `<name>` is a unique string for your client.

## Running Aurae

### Starting the Daemon

Start the Aurae daemon with:

```bash
sudo -E auraed -v
```

This will run Aurae alongside your current init system. The daemon listens on a Unix domain socket at `/var/run/aurae/aurae.sock`.

## Your First Workload

Let's create a simple workload using AuraeScript. We'll create a cell with resource constraints and run a process inside it.

### Create a Cell

Create a file named `create-cell.ts` with the following content:

```typescript
#!/usr/bin/env auraescript
let cells = new runtime.CellServiceClient();

let allocated = await cells.allocate(<runtime.AllocateCellRequest>{
  cell: runtime.Cell.fromPartial({
    name: "my-cell",
    cpu: runtime.CpuController.fromPartial({
      weight: 2,      // CPU weight
      max: 400 * 1000 // 0.4 seconds in microseconds
    }),
  }),
});

console.log('Allocated cell:', allocated);
```

Run the script:

```bash
auraescript create-cell.ts
```

### Run a Process in the Cell

Create a file named `run-process.ts` with the following content:

```typescript
#!/usr/bin/env auraescript
let cells = new runtime.CellServiceClient();

let started = await cells.start(<runtime.StartExecutableRequest>{
  cellName: "my-cell",
  executable: runtime.Executable.fromPartial({
    command: "sleep",
    args: ["30"],
    description: "Sleep for 30 seconds",
    name: "sleep-30"
  })
});

console.log('Started process:', started);
```

Run the script:

```bash
auraescript run-process.ts
```

### List Cells

You can also use the `aer` CLI tool to interact with Aurae:

```bash
# List all cells
aer runtime list
```

## Observing the System

Aurae provides capabilities to observe system events:

```bash
# Stream Aurae daemon logs
aer observe get-aurae-daemon-log-stream

# Stream POSIX signals
aer observe get-posix-signals-stream
```

## Cleaning Up

To stop a process and free up the cell:

```typescript
#!/usr/bin/env auraescript
let cells = new runtime.CellServiceClient();

// Stop the process
await cells.stop(<runtime.StopExecutableRequest>{
  cellName: "my-cell",
  executableName: "sleep-30"
});

// Free the cell
await cells.free(<runtime.FreeCellRequest>{
  cellName: "my-cell"
});
```

## Next Steps

Now that you have Aurae up and running, here are some next steps to explore:

- [Aurae Standard Library](https://aurae.io/stdlib/) - Learn about the API
- [Examples](https://github.com/aurae-runtime/aurae/tree/main/examples) - Explore more usage examples
- [Community](https://aurae.io/community/) - Get involved with the Aurae community
- [Blog Posts](https://aurae.io/blog/2022-10-24-aurae-cells/) - Read about Aurae's design and concepts

## Troubleshooting

### Socket Connection Issues

If you encounter "connection refused" errors:

- Ensure the daemon is running: `ps aux | grep auraed`
- Check socket permissions: `ls -la /var/run/aurae/aurae.sock`
- Verify your certificates are properly configured

### Certificate Problems

If you encounter TLS or certificate errors:

- Regenerate certificates: `make pki`
- Check certificate paths in your config file: `cat ~/.aurae/config`
- Ensure the client and server certificates are valid: `openssl verify -CAfile ~/.aurae/pki/ca.crt ~/.aurae/pki/client.crt`

### Build Failures

If the build fails:

- Update your Rust toolchain: `rustup update`
- Check for missing dependencies
- Look at the error message for specific issues

For more help, join the [Aurae Discord](https://discord.gg/aTe2Rjg5rq) or open an issue on [GitHub](https://github.com/aurae-runtime/aurae/issues).