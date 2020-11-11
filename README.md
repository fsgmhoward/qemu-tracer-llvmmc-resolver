# llvmmc-resolver

A server disassemble resolver using llvm-mc

Prerequisites:
1. capnproto (configured with `pkg-config`)
2. LLVM 8.0.0

You can reference the Dockerfile for dependent packages.

The executable will be the `resolver` binary in side your build directory.
The binary will *NOT* be installed into your system path automatically.

------------------------------

To build the Docker image:

```bash
docker build -t pangine/llvmmc-resolver --build-arg UID=`id -u` .
```
Please do not change the tag name, since it will be used as a dependency of other images.

<!---
Presently, this repo is a private one, to successfully clone the repo inside a container, you need to put a private ssh key named as "id_rsa" (permission 644) that can be used to access github.com/pangine in this repo before running docker build.
--->
