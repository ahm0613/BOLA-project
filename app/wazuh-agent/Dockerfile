FROM rockylinux:9
# 설치 파일(rpm)은 저장소에 넣지 않고 빌드할 때 Wazuh 공식 저장소에서 받음
RUN dnf install -y procps-ng https://packages.wazuh.com/4.x/yum/wazuh-agent-4.14.9-1.x86_64.rpm && dnf clean all
COPY localfile.conf /tmp/localfile.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]