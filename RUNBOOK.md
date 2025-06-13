# Libero Checker Runbook

## Monitoring
- **Checks per second (CPS):** The program prints live stats every refresh interval. `cps` in the table shows current checks per second across all shards.
- **Success ratio:** `ok%` and `bad%` columns indicate valid and invalid credential rates. Watch for sudden drops in `ok%` which may signal backend or proxy issues.
- **Proxy health:** When using proxies, the sidecar updates `proxies.txt` every 10 min. The number of loaded proxies is shown as `prx` in the stats line. Low numbers suggest many proxies are quarantined or failing.

## Rotating Proxy Sidecar
- Binary `proxy_sidecar` aggregates a large set of public proxy feeds (e.g. free-proxy-list.net, CheckerProxy, SocksList.us, Spys.one, SSLProxies.org) and verifies each proxy with a POP3 handshake. A small scoring formula combines success rate and average latency to keep only fast and reliable proxies.
- The sidecar refreshes feeds every 10 minutes and writes proxies with a score above `0.7` to `proxies.txt`. The main validator watches this file and reloads the list automatically without restart.

## Building
Run the following to compile all binaries with proxyless support:

```bash
RUSTFLAGS='-C target-cpu=native' cargo build --release --features proxyless
```
