#To build: docker build -t pangine/llvmmc-resolver .
FROM ubuntu:20.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential \
    cmake \
    git \
    llvm-8 \
    pkg-config \
    wget

WORKDIR /root/
RUN mkdir .ssh bin
RUN wget --progress=bar:force:noscroll https://capnproto.org/capnproto-c++-0.8.0.tar.gz && \
    tar zxf capnproto-c++-0.8.0.tar.gz && \
    rm capnproto-c++-0.8.0.tar.gz && \
    cd capnproto-c++-0.8.0 && \
    ./configure && \
    make -j $(nproc) check && \
    make install && \
    ldconfig && \
    cd .. && \
    rm -rf capnproto-c++-0.8.0

ARG UID=1001
ARG USER=ubuntu
ARG USER_HOME=/home/${USER}
ENV USER=${USER}
ENV USER_HOME=${USER_HOME}
RUN useradd -m -d ${USER_HOME} -u ${UID} ${USER}
USER ${USER}
WORKDIR ${USER_HOME}

RUN mkdir .ssh bin
RUN git clone https://github.com/pangine/llvmmc-resolver && \
    cd llvmmc-resolver && \
    cmake -Bbuild . && \
    cd build && \
    make -j $(nproc) && \
    mv resolver ${USER_HOME}/bin && \
    cd ../.. && \
    rm -rf llvmmc-resolver

ENV PATH="${USER_HOME}/bin:${PATH}"
