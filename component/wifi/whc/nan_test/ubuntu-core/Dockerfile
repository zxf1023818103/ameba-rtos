FROM ubuntu:26.04@sha256:6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates build-essential gcc-15 pkg-config libnl-3-dev \
    libnl-genl-3-dev libssl-dev libjson-c-dev libelf-dev bison flex bc kmod \
    linux-headers-7.0.0-38-generic=7.0.0-38.38 \
    linux-source-7.0.0=7.0.0-38.38 \
    python3 python3-dbus python3-gi iw iproute2 procps util-linux bluez \
    python3-yaml squashfs-tools cpio udev ffmpeg v4l-utils libsrt-openssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
# stage-runtime.py uses apt-cache to resolve runtime dependencies.
# Refresh package indexes before running the build if this layer was cleaned.
CMD ["/bin/bash", "-c", "apt-get update && bash /repo/component/wifi/whc/nan_test/ubuntu-core/build-in-container.sh"]
