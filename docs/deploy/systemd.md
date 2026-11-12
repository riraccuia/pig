# systemd

Run pig as a systemd service on Linux.

This is aimed at a listen / exit host that should come up on boot with IP forwarding and egress masquerade enabled before pig starts.

## Prerequisites

- Root privileges (e.g. `sudo`).
- [pig installed](../installation/linux.md) on `PATH` (for example `/usr/local/bin/pig`).
- [nftables](https://wiki.nftables.org/) (`nft`).
- A pig config file ready to load (see [Config](../reference/config/config.md) and the [exit-node](../../examples/exit-node/README.md) example).

> [!TIP]
> For IPv6, prefer prefix delegation from your provider over masquerading when you can. Many ISPs hand out a delegated prefix at no extra cost. Use addresses from that prefix as the pig tunnel addresses so clients get real routed IPv6. Keep IPv4 masquerade in the script below for IPv4 egress.

## Prepare the config and startup script

1. Determine the egress interface.

```bash
ip -br link
```

It should be something like `eth0` or `wlan0`.

2. Create the directory and script.

```bash
sudo mkdir -p /opt/pig /etc/pig
sudo tee /opt/pig/pig-sys-startup.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

# Enable IPv4 and IPv6 forwarding.
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1

# Masquerade egress traffic.
oif="eth0"
nft list table inet nat >/dev/null 2>&1 || nft add table inet nat
nft list chain inet nat PIG_POSTROUTING >/dev/null 2>&1 || \
	nft add chain inet nat PIG_POSTROUTING '{ type nat hook postrouting priority 100 ; }'
if ! nft list chain inet nat PIG_POSTROUTING | grep -q "oifname \"${oif}\" masquerade"; then
	nft add rule inet nat PIG_POSTROUTING oifname "${oif}" masquerade
fi

exec pig -config /etc/pig/pig.toml
EOF
```

3. Make it executable and place your config at `/etc/pig/pig.conf` (or change the path in the script).

```bash
sudo chmod +x /opt/pig/pig-sys-startup.sh
sudo cp /path/to/your/pig.conf /etc/pig/pig.conf
```

## Install the unit

1. Write the unit file.

```bash
sudo tee /etc/systemd/system/pig.service >/dev/null <<'EOF'
[Unit]
Description=Pig service
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=/bin/bash /opt/pig/pig-sys-startup.sh
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
```

## Enable and start

1. Reload systemd, enable the unit, and start it.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pig.service
```

2. Check status and follow logs.

```bash
sudo systemctl status pig.service
sudo journalctl -u pig -f
```

## Verify

```bash
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding
sudo nft list chain inet nat PIG_POSTROUTING
```

You should see forwarding set to `1` and a masquerade rule for your egress interface.

To stop or disable:

```bash
sudo systemctl stop pig.service
sudo systemctl disable pig.service
```

Next: [Exit node](../../examples/exit-node/README.md) or [Quick start](../getting-started/quick-start.md).
