FROM python:3.12-slim

WORKDIR /app

# Nmap and supporting libraries for real scanner integrations.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    unzip \
    nmap \
    wget \
    git \
    build-essential \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Install a pinned official Nuclei release so the web scanner does not silently
# become a mocked/demo-only feature when the executable is absent.
ARG TARGETARCH=amd64
ARG NUCLEI_VERSION=3.11.1
RUN set -eux; \
    curl --fail --location --retry 3 --retry-all-errors \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip" \
      --output /tmp/nuclei.zip; \
    mkdir -p /tmp/nuclei; \
    unzip -q /tmp/nuclei.zip -d /tmp/nuclei; \
    install -m 0755 /tmp/nuclei/nuclei /usr/local/bin/nuclei; \
    nuclei -version; \
    rm -rf /tmp/nuclei /tmp/nuclei.zip

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/scan_results /app/malware_samples /app/pcap_files

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
