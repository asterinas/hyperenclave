<p align="center">
    <a href="https://github.com/HyperEnclave/hyperenclave">
        <img alt="HyperEnclave Logo" src="docs/images/logo.svg" width="75%" />
    </a>
</p>
<p align="center">
    <a href="https://github.com/HyperEnclave/hyperenclave/blob/master/LICENSE">
        <img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue" />
    </a>
</p>

HyperEnclave is an open and cross-platform trusted execution environment which runs on heterogeneous CPU platforms but decouples its root of trust from CPU vendors. In its nature, HyperEnclave calls for a better TEE ecosystem with improved transparency and trustworthiness. HyperEnclave has been implemented on various commodity CPU platforms and deployed in real-world confidential computing workloads.


# Key features

- **Unified abstractions.** Provide unified SGX-like abstraction with virtualization hardware.

- **Controlled RoT.** RoT(Root of Trust) has been decoupled from CPU vendors and built on the trustworthy TPM.

- **Proved security.** The first commerial Rust hypervisor that has been formally verified.

- **Auditability.** The core has been open-sourced and audited by the National Authority.


# Supported CPU List
We have successfully built HyperEnclave and performed tests on the following CPUs:
## [Intel](https://www.intel.com/)
- Intel(R) Xeon(R) Gold 6342 CPU @ 2.80GHz
- Intel 11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz
## [AMD](https://www.amd.com/)
- AMD EPYC 7601 64-core Processor @2.2GHz
- AMD Ryzen R3-5300G 4-core Process @4GHz
## [Hygon](https://www.hygon.cn/)
- Hygon C86 7365 24-core Processor @2.50GHz
- Hygon C86 3350 8-core Processor @2.8GHz
## [ZHAOXIN](https://www.zhaoxin.com/)
- ZHAOXIN KH-40000 @2.0/2.2GHz
- ZHAOXIN KX-6000 @3.0GHz


# Quick start

## Prerequisites

### Software version

- Ubuntu 20.04 and Ubuntu 22.04
- Linux kernel in [Supported Linux kernel version](#supported-linux-kernel-version)
- Linux kernel headers (For building the driver)
- Docker
- GCC >= 6.5


#### Supported Linux kernel version

- Linux kernel 5.10 (**Recommend**)
- Linux kernel 5.4 with fsgsbase support


**Updates on 2024.11:** We do not support Linux kernel 4.19 with Ubuntu OS anymore.


We can check the kernel version by:
```bash
$ uname -r
```

and install the required kernel (if necessary) by:

```bash
# Download scripts for installing kernel
$ sudo apt install wget
$ wget https://raw.githubusercontent.com/pimlie/ubuntu-mainline-kernel.sh/master/ubuntu-mainline-kernel.sh
$ chmod +x ubuntu-mainline-kernel.sh
# Download and install Linux 5.10 or 5.4.0 kernel.
$ sudo ./ubuntu-mainline-kernel.sh -i [5.10.0 | 5.4.0]

# Reboot the system, and we need to select the kernel in grub menu.
$ sudo reboot
```

For Linux kernel 5.4, **enabled_rdfsbase** kernel modules must be installed by following the instructions [here](https://github.com/occlum/enable_rdfsbase).

After the Linux kernel installed, check the rdfsbase/rdgsbase is enabled:
```bash
$ cd scripts
$ ./check_prereq.sh
$ cd ..
```

And the output:
```
[Check FSGSBASE]: PASS
```

indicates that the rdfsgsbase/wrfsgsbase is enabled on your platform.

### Hardware requirements
- **CPU & Virtualization**: An Intel, AMD, or HYGON processor that supports and has enabled virtualization (VMX for Intel, AMD-V for AMD) in the BIOS.
- **IOMMU**: Intel VT-d or AMD IOMMU must be supported and enabled in the BIOS.
- **Memory**: At least 8GB of RAM.

## Steps

### Step-1: Get the full system memory size and reserve secure memory for HyperEnclave in kernel’s command-line

- **Step 1.a**: Get the full system memory size: `full_system_size`, and reserved memory size: `reserved_mem_size`

```bash
$ free -h
               total        used        free      shared  buff/cache   available
Mem：       15Gi       1.3Gi        11Gi       2.0Mi       3.5Gi        14Gi
Swap：      2.0Gi          0B       2.0Gi
```

For the example above, the `full_system_size` is 15G, then `reserved_mem_size` eqauls to `full_system_size / 2` = 8G

- **Step 1.b**: Reserve secure memory for HyperEnclave

Open and modify the `/etc/default/grub` file, and append the following configurations for `GRUB_CMDLINE_LINUX`:

```
memmap=[reserved_mem_size]G\\\$0x100000000 iommu=off intremap=off no5lvl
```

For the example above, the configuration should be:
```
memmap=8G\\\$0x100000000 iommu=off intremap=off no5lvl
```

- **Step 1.c**: Take the new grub configuration into effect, and reboot the system

```bash
$ sudo update-grub
$ sudo reboot
```

- **Step 1.d**: Verify that the configuration takes effect

After reboot, check whether the modified kernel's command-line takes effect:

```bash
$ cat /proc/cmdline
```

You can see:
```
BOOT_IMAGE=/boot/vmlinuz-... root=... memmap=8G$0x100000000 iommu=off intremap=off no5lvl ...
```


### Step-2: Clone the repository

```bash
$ git clone https://github.com/asterinas/hyperenclave.git
$ git clone https://github.com/asterinas/hyperenclave-driver.git
```

### Step-3: Build the HyperEnclave's driver
```bash
$ cd hyperenclave-driver
$ make
$ cd ..
```

### Step-4: Build and install HyperEnclave

- **Step 4.a**: Install Rust toolchain

```bash
# Install rust toolchain 
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
$ source $HOME/.cargo/env
$ rustup component add rust-src
```

- **Step 4.b**: Build and install HyperEnclave

Hyperenclave now supports three CPU vendors:
1. Intel
2. AMD
3. Hygon

We need to choose the correct CPU vendor and run the following script:

```bash
$ bash -x scripts/build_and_install_hyperenclave.sh [Intel | AMD | Hygon]
```

### Step-5: Start HyperEnclave

```bash
$ cd hyperenclave/scripts
$ bash -x start_hyperenclave.sh
$ cd ../..
```

Show the messages in kernel ring buffer by:
```bash
$ dmesg
```
And you can see:
```
...
[0] Activating hypervisor on CPU 0...
[1] Activating hypervisor on CPU 1...
[2] Activating hypervisor on CPU 2...
[3] Activating hypervisor on CPU 3...
[4] Activating hypervisor on CPU 4...
[5] Activating hypervisor on CPU 5...
[6] Activating hypervisor on CPU 6...
[7] Activating hypervisor on CPU 7...
...
```

It indicates we successfully start the HyperEnclave.

### Step-6: Run TEE applications

We provide several sample TEE applications running atop of HyperEnclave. All of them are integrated into our docker image.

Here are instructions for starting the docker container:
```bash
# Pull the docker image
$ docker pull occlum/hyperenclave:0.27.10-hypermode-1.3.0-ubuntu20.04

# Start the container
$ docker run -dt --net=host --device=/dev/hyperenclave \
                --name hyperenclave_container \
                -w /root \
                occlum/hyperenclave:0.27.10-hypermode-1.3.0-ubuntu20.04 \
                bash

# Enter the container
$ docker exec -it hyperenclave_container bash
```

#### SGX SDK Samples

You can run TEE applications developed based on [Intel SGX SDK](https://github.com/intel/linux-sgx). All the SGX SDK's sample codes are preinstalled in our docker image at `/opt/intel/sgxsdk/SampleCode`. Here are two samples (Command should be done inside Docker container):

- SampleEnclave
```bash
$ cd /opt/intel/sgxsdk/SampleCode/SampleEnclave
$ make
$ ./app
Info: executing thread synchronization, please wait...
Info: SampleEnclave successfully returned.
```

- RemoteAttestation

Reference to `demos/RemoteAttestation` for more information.

#### Occlum demos

You can also run TEE applications developed based on [Occlum](https://github.com/occlum/occlum). All the Occlum demos are preinstalled in our docker image at `/root/occlum/demos`.

We take `hello_c` as an example. (Command should be done inside Docker container):
```bash
$ cd /root/occlum/demos/hello_c

# Compile the user program with the Occlum toolchain
$ occlum-gcc -o hello_world hello_world.c
# Ensure the program works well outside enclave
$ ./hello_world
Hello World

# Initialize a directory as the Occlum instance, and prepare the Occlum's environment
$ mkdir occlum_instance && cd occlum_instance
$ occlum init
$ cp ../hello_world image/bin/
$ occlum build

# Run the user program inside an HyperEnclave's enclave via occlum run
$ occlum run /bin/hello_world
Hello World!
```


# Academic publications
[**USENIX ATC'22**] [HyperEnclave: An Open and Cross-platform Trusted Execution Environment.](https://www.usenix.org/conference/atc22/presentation/jia-yuekai)
Yuekai Jia, Shuang Liu, Wenhao Wang, Yu Chen, Zhengde Zhai, Shoumeng Yan, and Zhengyu He. 2022 USENIX Annual Technical Conference (USENIX ATC 22). Carlsbad, CA, Jul, 2022.

```
@inproceedings {jia2022hyperenclave,
  author = {Yuekai Jia and Shuang Liu and Wenhao Wang and Yu Chen and Zhengde Zhai and Shoumeng Yan and Zhengyu He},
  title = {{HyperEnclave}: An Open and Cross-platform Trusted Execution Environment},
  booktitle = {2022 USENIX Annual Technical Conference (USENIX ATC 22)},
  year = {2022},
  isbn = {978-1-939133-29-48},
  address = {Carlsbad, CA},
  pages = {437--454},
  url = {https://www.usenix.org/conference/atc22/presentation/jia-yuekai},
  publisher = {USENIX Association},
  month = jul,
}
```

[**ASPLOS'24**] [Verifying Rust Implementation of Page Tables in a Software Enclave Hypervisor.](https://dl.acm.org/doi/10.1145/3620665.3640398)
Zhenyang Dai, Shuang Liu, Vilhelm Sjoberg, Xupeng Li, Yu Chen, Wenhao Wang, Yuekai Jia, Sean Noble Anderson, Laila Elbeheiry, Shubham Sondhi, Yu Zhang, Zhaozhong Ni, Shoumeng Yan, Ronghui Gu, and Zhengyu He. 2024. Verifying Rust Implementation of Page Tables in a Software Enclave Hypervisor. In Proceedings of the 29th ACM International Conference on Architectural Support for Programming Languages and Operating Systems, Volume 2 (ASPLOS '24), Vol. 2. Association for Computing Machinery, New York, NY, USA, 1218–1232.

```
@inproceedings{10.1145/3620665.3640398,
author = {Dai, Zhenyang and Liu, Shuang and Sjoberg, Vilhelm and Li, Xupeng and Chen, Yu and Wang, Wenhao and Jia, Yuekai and Anderson, Sean Noble and Elbeheiry, Laila and Sondhi, Shubham and Zhang, Yu and Ni, Zhaozhong and Yan, Shoumeng and Gu, Ronghui and He, Zhengyu},
title = {Verifying Rust Implementation of Page Tables in a Software Enclave Hypervisor},
year = {2024},
isbn = {9798400703850},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
url = {https://doi.org/10.1145/3620665.3640398},
doi = {10.1145/3620665.3640398},
abstract = {As trusted execution environments (TEE) have become the corner stone for secure cloud computing, it is critical that they are reliable and enforce proper isolation, of which a key ingredient is spatial isolation. Many TEEs are implemented in software such as hypervisors for flexibility, and in a memory-safe language, namely Rust to alleviate potential memory bugs. Still, even if memory bugs are absent from the TEE, it may contain semantic errors such as mis-configurations in its memory subsystem which breaks spatial isolation.In this paper, we present the verification of the memory subsystem of a software TEE in Rust, namely HyperEnclave. We prove spatial isolation for the secure enclave though correct configuration of page tables for an early prototype of HyperEnclave. To formally model Rust code, we introduce a lightweight formal semantics for the Mid-level intermediate representation (MIR) of Rust. To make verification scalable for such a complex system, we incorporate the MIR semantics with a layered proof framework.},
booktitle = {Proceedings of the 29th ACM International Conference on Architectural Support for Programming Languages and Operating Systems, Volume 2},
pages = {1218–1232},
numpages = {15},
keywords = {formal verification, rust, trusted execution environments, extended page tables},
location = {La Jolla, CA, USA},
series = {ASPLOS '24}
}

```

# License
Except where noted otherwise, HyperEnclave's hypervisor is under the Apache License (Version 2.0). See the [LICENSE](./LICENSE) files for details.
