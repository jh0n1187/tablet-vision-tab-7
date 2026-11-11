FROM python@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f

# Packages live only in this test image; no host services or USB access in build.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends wireshark-common kmod

USER 65534:65534
ENTRYPOINT ["dumpcap"]
CMD ["--version"]
