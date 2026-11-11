FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential autoconf automake libtool pkg-config uuid-dev liblz4-dev liblzma-dev libdeflate-dev libselinux1-dev libarchive-dev zlib1g-dev python3 && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY erofs-utils-v1.7.1.tar.gz .
RUN echo '196083d63e5e231fb5799e7ce86a944bbca564daabce3de9225a8aca9dcaff15  erofs-utils-v1.7.1.tar.gz' | sha256sum -c - && tar xf erofs-utils-v1.7.1.tar.gz
WORKDIR /build/erofs-utils-1.7.1
COPY fix_tar.py /build/fix_tar.py
RUN python3 /build/fix_tar.py
RUN ./autogen.sh && ./configure && make -j4 && make install
COPY export.c /build/export.c
RUN cc -D_GNU_SOURCE -DHAVE_CONFIG_H -Iinclude -I. /build/export.c lib/.libs/liberofs.a -o /usr/local/bin/erofs-export -larchive -llz4 -llzma -ldeflate -lz -luuid -lselinux
ENV LC_ALL=C
WORKDIR /work
