FROM rockylinux:9
COPY wazuh-agent-4.14.9-1.x86_64.rpm /tmp/
RUN dnf install -y procps-ng /tmp/wazuh-agent-4.14.9-1.x86_64.rpm && dnf clean all && rm -f /tmp/*.rpm
COPY localfile.conf /tmp/localfile.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]