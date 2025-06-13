# Libero Checker Runbook

## Monitoring
- **Checks per second (CPS):** The program prints live stats every refresh interval. `cps` in the table shows current checks per second across all shards.
- **Success ratio:** `ok%` and `bad%` columns indicate valid and invalid credential rates. Watch for sudden drops in `ok%` which may signal backend or proxy issues.
- **Proxy health:** When using proxies, the sidecar updates `proxies.txt` every 10 min. The number of loaded proxies is shown as `prx` in the stats line. Low numbers suggest many proxies are quarantined or failing.

## Rotating Proxy Sidecar
- Binary `proxy_sidecar` fetches public proxy lists and verifies each proxy with a POP3 handshake. Proxies responding within 400 ms and with a rolling success rate above 20 % are written to `proxies.txt`.
- The main validator watches `proxies.txt` and reloads the list automatically without restart.

## Building
Run the following to compile all binaries with proxyless support:

```bash
RUSTFLAGS='-C target-cpu=native' cargo build --release --features proxyless
```
