# luci-app-portscan

A modern OpenWrt LuCI application that provides an intuitive web interface for managing `nftables`-based port scan protection.

This package automatically generates and applies dynamic firewall rules (using `fw4`) to detect and block port scanning attempts, and allows you to view and manage actively blocked IPs in real-time without leaving the browser.

## Features

- **Modern LuCI SPA Interface:** Built with client-side JavaScript (LuCI View) for a fast, page-reload-free experience.
- **Dynamic Blacklisting:** Built purely on `nftables` using dynamic sets and per-IP rate limiting. It tracks excessive SYN packets and automatically bans offending source IP addresses with minimal CPU overhead.
- **Visual Management:** View actively blocked IPs and their expiration times in a nice table format.
- **Quick Actions:** Remove specific IPs from the blacklist with a single click, or flush the entire blacklist instantly.
- **Fully Configurable (UCI):** Easily configure settings directly from the LuCI interface or via UCI:
  - Enable/Disable protection on the fly.
  - Custom block timeouts (e.g., `12h`, `30m`).
  - SYN rate limits and burst thresholds.

## Requirements & Compatibility

- **OpenWrt 22.03 or newer** (Must use `fw4` as the firewall backend).
- **nftables**: Requires `nftables` (replaces legacy `iptables`).
- **luci-base**: Required for the web interface.

*Note: This package has been actively tested and built on **OpenWrt 25.12.4** (with `fw4` and `nftables`). It is fully compatible with the new `apk` package manager as well as the legacy `opkg`.*

## Installation

### Method 1: Using pre-compiled package
1. Download the `.ipk` or `.apk` (for OpenWrt 24.xx+) file from the Releases page.
2. Upload the file to your router (e.g., to `/tmp`).
3. Install the package via SSH:
   ```bash
   # For OpenWrt 23.xx and older (opkg)
   opkg install /tmp/luci-app-portscan-1.0-r1.ipk

   # For OpenWrt 24.xx+ (apk)
   apk add --allow-untrusted /tmp/luci-app-portscan-1.0-r1.apk
   ```
4. Restart the `rpcd` service and refresh your browser window:
   ```bash
   service rpcd restart
   ```

### Method 2: Compiling with the OpenWrt SDK
1. Clone this repository into your OpenWrt SDK `package/` directory:
   ```bash
   git clone https://github.com/yourusername/luci-app-portscan.git package/luci-app-portscan
   ```
2. Update feeds to ensure `luci-base` is available:
   ```bash
   ./scripts/feeds update -a
   ./scripts/feeds install -a
   ```
3. Select the package in the SDK configuration:
   ```bash
   make menuconfig
   # Go to: LuCI -> Applications -> luci-app-portscan (<M>)
   ```
4. Compile the package:
   ```bash
   make package/luci-app-portscan/compile V=s
   ```

## Configuration

Settings can be managed directly in the LuCI interface under **Network -> Port Scan Protection** (or depending on your menu configuration).

Alternatively, you can edit the UCI configuration file at `/etc/config/portscan`:
```text
config portscan 'settings'
    option enable '1'
    option timeout '12h'
    option limit_rate '15'
    option limit_burst '10'
```
After making manual changes to the UCI file, simply restart the service to apply the new rules:
```bash
/etc/init.d/portscan restart
```

## How it works

When enabled, the application's `init.d` script generates an `nftables` file (`/etc/nftables.d/10-portscan.nft`) based on your UCI settings. This file defines a dynamic set (`portscan_rate`) to monitor incoming SYN connections and a blacklist set (`portscan_blacklist`) that drops traffic from offending IP addresses. The firewall (`fw4`) automatically includes these rules upon reload.
