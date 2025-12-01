FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# Install system deps
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    git \
    net-tools \
    iputils-ping \
    tcpdump \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Clone POX
WORKDIR /
RUN git clone https://github.com/noxrepo/pox.git

# Install Python libs needed by defense_with_lm.py
RUN pip3 install --no-cache-dir \
    numpy \
    pandas \
    scikit-learn \
    matplotlib \
    scapy \
    requests \
    transformers \
    torch \
    sentencepiece

# Create pox/ext folder
RUN mkdir -p /pox/pox/ext

# Copy your defense module
COPY controllers/defense_with_ml.py /pox/pox/ext/defense_with_ml.py

WORKDIR /pox

EXPOSE 6633 8000

# Launch your custom controller
CMD ["python3", "pox.py", "ext.defense_with_lm", "--port=6633"]
