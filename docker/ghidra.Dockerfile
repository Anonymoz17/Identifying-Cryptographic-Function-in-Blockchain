FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jdk-headless curl unzip python3 python3-pip ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Change these variables to pin a Ghidra release and verify the checksum in your CI/build system
ARG GHIDRA_VERSION=10.2.3
ARG GHIDRA_ZIP_URL="https://ghidra-sre.org/ghidra_${GHIDRA_VERSION}_PUBLIC.zip"

WORKDIR /opt
RUN curl -L -o /tmp/ghidra.zip ${GHIDRA_ZIP_URL} && unzip /tmp/ghidra.zip -d /opt && rm /tmp/ghidra.zip

ENV GHIDRA_INSTALL_DIR=/opt/ghidra_${GHIDRA_VERSION}
ENV PATH="${GHIDRA_INSTALL_DIR}/support:${PATH}"

# Copy project files (optional; for CI runs you may mount workspace instead)
COPY . /workspace
WORKDIR /workspace

RUN pip3 install --no-cache-dir -r requirements.txt || true

CMD ["/bin/bash"]
