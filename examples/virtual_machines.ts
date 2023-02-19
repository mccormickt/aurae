#!/usr/bin/env auraescript
/* -------------------------------------------------------------------------- *\
 *        Apache 2.0 License Copyright © 2022-2023 The Aurae Authors          *
 *                                                                            *
 *                +--------------------------------------------+              *
 *                |   █████╗ ██╗   ██╗██████╗  █████╗ ███████╗ |              *
 *                |  ██╔══██╗██║   ██║██╔══██╗██╔══██╗██╔════╝ |              *
 *                |  ███████║██║   ██║██████╔╝███████║█████╗   |              *
 *                |  ██╔══██║██║   ██║██╔══██╗██╔══██║██╔══╝   |              *
 *                |  ██║  ██║╚██████╔╝██║  ██║██║  ██║███████╗ |              *
 *                |  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ |              *
 *                +--------------------------------------------+              *
 *                                                                            *
 *                         Distributed Systems Runtime                        *
 *                                                                            *
 * -------------------------------------------------------------------------- *
 *                                                                            *
 *   Licensed under the Apache License, Version 2.0 (the "License");          *
 *   you may not use this file except in compliance with the License.         *
 *   You may obtain a copy of the License at                                  *
 *                                                                            *
 *       http://www.apache.org/licenses/LICENSE-2.0                           *
 *                                                                            *
 *   Unless required by applicable law or agreed to in writing, software      *
 *   distributed under the License is distributed on an "AS IS" BASIS,        *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. *
 *   See the License for the specific language governing permissions and      *
 *   limitations under the License.                                           *
 *                                                                            *
\* -------------------------------------------------------------------------- */
import * as helpers from "../auraescript/gen/helpers.ts";
import * as runtime from "../auraescript/gen/vms.ts";

let vms = new runtime.VmServiceClient();
const vmID = "ae-vm";

// [ Allocate ]
let allocated = await vms.allocate(<runtime.VmServiceAllocateRequest>{
    machine: runtime.VirtualMachine.fromPartial({
        id: vmID,
        memSizeMb: 2048,
        vcpuCount: 1,
        kernelArgs: ["console=ttyS0", "reboot=k", "panic=1", "pci=off"],
        kernelImgPath: "/home/jan0ski/aurae-runtime/aurae/auraed/hack/hello-vmlinux.bin",
        rootDrive: runtime.RootDrive.fromPartial({
            hostPath: "/home/jan0ski/aurae-runtime/aurae/auraed/hack/hello-rootfs.ext4",
            isWriteable: false,
        }),
        driveMounts: [
            runtime.DriveMount.fromPartial({
                hostPath: "/tmp/",
                vmPath: "/mnt/storage",
                fsType: "ext4",
                isWriteable: false,
            }),
        ],
        networkInterfaces: [
            runtime.NetworkInterface.fromPartial({
                macAddress: "06:00:c0:a8:00:02",
                hostDevName: "aurae0",
            }),
        ],
    })
})
helpers.print(allocated)

// [ Start ]
let started = await vms.start(<runtime.VmServiceStartRequest>{
    vmId: vmID,
})
helpers.print(started)

// [ Stop ]
//let stopped = await vms.stop(<runtime.VmServiceStopRequest>{
//    vmId: vmID,
//})
//helpers.print(stopped)