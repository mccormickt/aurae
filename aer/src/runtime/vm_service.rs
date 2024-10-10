use clap::ArgAction;

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
macros::subcommand!(
    "../api/v0/vms/vms.proto",
    vms,
    VmService,
    Allocate {
        machine_id[required = true],
        machine_mem_size_mb[long, alias = "mem-size-mb"],
        machine_vcpu_count[long, alias = "vcpu-count"],
        machine_root_drive_image_path[long, alias = "root-drive", default_value = "/var/lib/aurae/vm/image/disk.raw"],
        machine_root_drive_read_only[long, alias = "root-drive-ro", action = ArgAction::SetTrue],
        machine_kernel_img_path[long, alias = "kernel-img-path", default_value = "/var/lib/aurae/vm/kernel/vmlinux.bin"],
        machine_kernel_args[long, alias = "kernel-args", default_value = "console=hvc0,root=/dev/vda1,rw"],
        machine_drive_mounts_image_path[long, alias = "drive-mounts-img-path", default_value = ""],
        machine_drive_mounts_vm_path[long, alias = "drive-mounts-guest-path", default_value = ""],
        machine_drive_mounts_fs_type[long, alias = "drive-mounts-fs-type", default_value = ""],
        machine_drive_mounts_read_only[long, alias = "drive-mounts-ro", action = ArgAction::SetTrue],
        machine_auraed_address[long, alias = "auraed-address", default_value = ""],
    },
    Start {
        vm_id[required = true],
    },
    Stop {
        vm_id[required = true],
    },
    Free {
        vm_id[required = true],
    },
    List,
);
