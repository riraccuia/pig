#!/bin/sh
set -e

# Ensure the TUN device exists.
if [ ! -c /dev/net/tun ]; then
	mkdir -p /dev/net
	mknod /dev/net/tun c 10 200
	chmod 600 /dev/net/tun
fi

# Optional egress NAT (exit-node / full-tunnel gateway). On by default.
if [ "${PIG_MASQUERADE:-1}" = "1" ]; then
	oif="${PIG_NAT_OIF:-eth0}"
	nft add table inet nat
	nft add chain inet nat PIG_POSTROUTING '{ type nat hook postrouting priority 100 ; }'
	if ! nft list chain inet nat PIG_POSTROUTING | grep -q "oifname \"${oif}\" masquerade"; then
		nft add rule inet nat PIG_POSTROUTING oifname "${oif}" masquerade
	fi
fi

exec /pig -config "${PIG_CONFIG:-/etc/pig/pig.config}"
