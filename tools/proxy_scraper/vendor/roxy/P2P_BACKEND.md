# P2P Research Backend

This document outlines the basic approach used by the `scrape_proxies.py` script to collect IP addresses from decentralized systems. The goal is to study how peer-to-peer networks may inadvertently expose residential or rotating IP addresses.

## Targeted Networks
- **BitTorrent DHT**: The script participates in the DHT by sending standard `find_node` and `get_peers` queries to discovered nodes. Peers listening on common proxy ports are recorded.
- **Paste Sites and Public Feeds**: Several pastebin-like services are polled for `IP:PORT` patterns that might correspond to proxies.
- **Tor Relays (Onionoo)**: Public relay descriptors are fetched from the Onionoo service to observe how volunteers expose relay endpoints.

All collected addresses are appended to `proxies.txt` in `IP:PORT` form. The crawler limits request rates and uses standard protocol messages to avoid disruptive behavior.
