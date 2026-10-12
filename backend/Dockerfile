FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    wget \
    git \
    unzip \
    build-essential \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei (Web Vulnerability Scanner) & templates
RUN ARCH=$(dpkg --print-architecture) && \
    curl -sSL "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_${ARCH}.zip" -o /tmp/nuclei.zip && \
    unzip -q /tmp/nuclei.zip -d /usr/local/bin/ nuclei && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip && \
    nuclei -update-templates || true

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
