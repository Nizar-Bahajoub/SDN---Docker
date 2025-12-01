FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# 1. Dépendances système de base + celles requises par Mininet install.sh -a
RUN apt-get update && apt-get install -y \
    git \
    sudo \
    python3 \
    python3-pip \
    net-tools \
    iputils-ping \
    iproute2 \
    iperf3 \
    curl \
    wget \
    tcpdump \
    vim \
    nano \
    hping3 \
    apache2 \
    netcat-openbsd \
    openvswitch-switch \
    openvswitch-common \
    # === DÉPENDANCES MININET (obligatoires pour install.sh -a) ===
    lsb-release \
    software-properties-common \
    build-essential \
    psmisc \
    cgroup-tools \
    libcgroup1 \
    libcap-ng-utils \
    iptables \
    ebtables \
    socat \
    && rm -rf /var/lib/apt/lists/*

# 2. Installation COMPLÈTE de Mininet
RUN git clone https://github.com/mininet/mininet.git /tmp/mininet && \
    /tmp/mininet/util/install.sh -a

# 3. Compiler mnexec manuellement
RUN gcc /tmp/mininet/mnexec.c -o /usr/local/bin/mnexec && chmod +x /usr/local/bin/mnexec

# Nettoyage du dépôt Mininet
RUN rm -rf /tmp/mininet

# 4. Bibliothèques Python
RUN pip3 install --no-cache-dir \
    scapy \
    requests \
    numpy

# 5. Configuration Apache
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf

# 6. Script de démarrage OVS
RUN echo '#!/bin/bash\n\
set -e\n\
echo "Démarrage OVS..."\n\
mkdir -p /var/run/openvswitch /var/log/openvswitch /etc/openvswitch\n\
\n\
pkill -9 ovsdb-server 2>/dev/null || true\n\
pkill -9 ovs-vswitchd 2>/dev/null || true\n\
rm -f /var/run/openvswitch/*.pid\n\
\n\
if [ ! -f /etc/openvswitch/conf.db ]; then\n\
    ovsdb-tool create /etc/openvswitch/conf.db /usr/share/openvswitch/vswitch.ovsschema\n\
fi\n\
\n\
ovsdb-server --remote=punix:/var/run/openvswitch/db.sock \\\n\
    --remote=db:Open_vSwitch,Open_vSwitch,manager_options \\\n\
    --pidfile --detach --log-file\n\
\n\
sleep 2\n\
ovs-vsctl --no-wait init\n\
\n\
ovs-vswitchd --pidfile --detach --log-file\n\
\n\
sleep 2\n\
\n\
echo "OVS démarré"\n\
ovs-vsctl show\n\
\n\
exec "$@"\n\
' > /usr/local/bin/start-ovs.sh && chmod +x /usr/local/bin/start-ovs.sh

RUN mkdir -p /scripts /topologies

WORKDIR /

ENTRYPOINT ["/usr/local/bin/start-ovs.sh"]
CMD ["/bin/bash"]
