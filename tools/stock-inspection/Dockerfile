FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends erofs-utils && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["fsck.erofs"]
