#!/bin/bash
CONF=/var/ossec/etc/ossec.conf

if [ -z "$WAZUH_MANAGER" ]; then
  echo "ERROR: WAZUH_MANAGER is not set"
  exit 1
fi

sed -i "s|<address>.*</address>|<address>${WAZUH_MANAGER}</address>|" "$CONF"
grep -q "/logs/kong/access.json" "$CONF" || cat /tmp/localfile.conf >> "$CONF"

echo "manager address: $(grep -m1 -o '<address>.*</address>' "$CONF")"
/var/ossec/bin/wazuh-control start || echo "WARN: wazuh-control start failed, see ossec.log below"

touch /var/ossec/logs/ossec.log
tail -n 50 -F /var/ossec/logs/ossec.log