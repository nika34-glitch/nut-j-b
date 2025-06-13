# OtoProxy

OtoProxy is a small helper utility for gathering public proxy lists. It scrapes a
set of URLs from `sites.txt`, verifies the collected proxies and saves the
working ones into files under the `feeds/` directory.

The script is written in Python and aims to be simple to run locally or from
automation. It tests proxies with a short timeout and keeps a blacklist of
previously failing addresses so they are skipped on the next run.

Generated files:

- `feeds/all-proxies.txt` – every working proxy
- `feeds/http-proxies.txt` – proxies that work as HTTP
- `feeds/socks4-proxies.txt` – proxies working as SOCKS4
- `feeds/socks5-proxies.txt` – proxies working as SOCKS5
- `feeds/blacklist.txt` – failing proxies are appended here

To run the scraper:

```bash
python otoproxy/otoproxy.py
```

This will read the URLs from `sites.txt`, test each discovered proxy and write
the results to the files above.
