import requests
import time
import sys
import threading
import random
import re
import base64
import asyncio
import os
import socket
import struct
from bs4 import BeautifulSoup

MTPROTO_URL = "https://mtpro.xyz/api/?type=mtproto"
SOCKS_URL = "https://mtpro.xyz/api/?type=socks"
OUTPUT_FILE = "proxies.txt"

MT_INTERVAL = 1  # seconds between mtpro.xyz polls
PASTE_INTERVAL = 60  # seconds between paste feed checks
FEED_DELAY_RANGE = (5, 10)  # delay between individual feed requests

PASTE_FEEDS = [
    "https://pastebin.com/feed",
    "https://ghostbin.com/recent",
    "https://paste.ee/rss",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
]

# IRC collection configuration
IRC_SERVERS = [
    "irc.undernet.org",
    "irc.rizon.net",
    "irc.libera.chat",
    "irc.abjects.net",
    "irc.efnet.org",
    "irc.darkscience.net",
    "irc.dal.net",
]

IRC_CHANNELS = [
    "#proxy",
    "#proxylist",
    "#proxies",
    "#proxyleaks",
    "#socks",
    "#socks4",
    "#socks5",
    "#leech",
    "#leechers",
    "#0day",
    "#darkweb",
    "#darkproxies",
    "#http",
    "#socks_proxy",
    "#proxyfeeds",
    "#botnet",
    "#scraperbots",
    "#anonproxies",
    "#blackhat",
    "#hackers",
    "#freeland",
    "#datadump",
    "#dump",
    "#proxy-dump",
    "#proxy_bots",
    "#proxy_scrape",
    "#dumpville",
    "#proxy_zone",
    "#openproxies",
    "#publicproxies",
    "#proxyhunt",
    "#torleaks",
    "#rawfeeds",
    "#autoproxy",
    "#scanfeeds",
    "#mirrors",
    "#ipfeeds",
    "#portscanners",
    "#hostlist",
    "#proxylogs",
]

# DHT crawling configuration
BOOTSTRAP_NODES = [
    ("router.bittorrent.com", 6881),
    ("dht.transmissionbt.com", 6881),
]
MAX_DHT_CONCURRENCY = 50
PROXY_PORTS = {8080, 3128, 1080, 9050, 8000, 8081, 8888}
DHT_LOG_EVERY = 100  # log progress every N visited nodes

# Tor relay crawling configuration
ONIONOO_URL = "https://onionoo.torproject.org/details"
TOR_INTERVAL = 3600  # seconds between Tor relay list updates

# Additional HTTP API backends
API_INTERVAL = 0.3  # delay between individual API requests
PROXYSCRAPE_HTTP_URL = (
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=no&anonymity=all"
)
PROXYSCRAPE_SOCKS4_URL = (
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000&country=all"
)
PROXYSCRAPE_SOCKS5_URL = (
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all"
)
GIMMEPROXY_URL = "https://gimmeproxy.com/api/getProxy"
PUBPROXY_URL = "http://pubproxy.com/api/proxy"
PROXYKINGDOM_URL = "https://api.proxykingdom.com/proxy?token=xN9IoZDLnMzUC0"
GEONODE_URL = (
    "https://proxylist.geonode.com/api/proxy-list"
    "?limit=500&page=4&sort_by=lastChecked&sort_type=desc"
)
GEONODE_INTERVAL = 5  # seconds between geonode API requests

# ProxySpace backend configuration
PROXYSPACE_HTTP_URL = "https://proxyspace.pro/http.txt"
PROXYSPACE_HTTPS_URL = "https://proxyspace.pro/https.txt"
PROXYSPACE_SOCKS4_URL = "https://proxyspace.pro/socks4.txt"
PROXYSPACE_SOCKS5_URL = "https://proxyspace.pro/socks5.txt"
# fetch new lists roughly every 20 minutes
PROXYSPACE_INTERVAL = 1200

# dpangestuw Free-Proxy GitHub lists
FREEPROXY_HTTP_URL = (
    "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/http_proxies.txt"
)
FREEPROXY_SOCKS4_URL = (
    "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/socks4_proxies.txt"
)
FREEPROXY_SOCKS5_URL = (
    "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/socks5_proxies.txt"
)
FREEPROXY_INTERVAL = 120  # fetch every 2 minutes
# aggregated list updated every 5 minutes
FREEPROXY_ALL_URL = (
    "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/All_proxies.txt"
)
FREEPROXY_ALL_INTERVAL = 300

# Fresh Proxy List (vakhov.github.io)
FRESHPROXY_HTTP_URL = "https://vakhov.github.io/fresh-proxy-list/http.txt"
FRESHPROXY_HTTPS_URL = "https://vakhov.github.io/fresh-proxy-list/https.txt"
FRESHPROXY_SOCKS4_URL = "https://vakhov.github.io/fresh-proxy-list/socks4.txt"
FRESHPROXY_SOCKS5_URL = "https://vakhov.github.io/fresh-proxy-list/socks5.txt"
FRESHPROXY_INTERVAL = 300  # fetch every 5 minutes

# KangProxy aggregated lists
KANGPROXY_OLD_URL = "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/xResults/old-data/RAW.txt"
KANGPROXY_URL = "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/xResults/RAW.txt"
KANGPROXY_INTERVAL = 14400  # fetch every 4 hours

# Proxifly GitHub proxy lists
PROXIFLY_HTTP_URL = (
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt"
)
PROXIFLY_SOCKS4_URL = (
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks4/data.txt"
)
PROXIFLY_SOCKS5_URL = (
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt"
)
PROXIFLY_INTERVAL = 300  # fetch every 5 minutes

# Free proxy list websites
PROXY_LIST_SITES = [
    ("https://free-proxy-list.net/", "http"),
    ("https://us-proxy.org/", "http"),
    ("https://sslproxies.org/", "http"),
    ("https://socks-proxy.net/", "socks5"),
]
PROXY_LIST_INTERVAL = 600  # sites update roughly every 10 minutes

# spys.me proxy lists
SPYS_HTTP_URL = "https://spys.me/proxy.txt"
SPYS_SOCKS_URL = "https://spys.me/socks.txt"
SPYS_INTERVAL = 300  # fetch every 5 minutes

# ProxyBros free proxy list
PROXYBROS_URL = "https://proxybros.com/free-proxy-list/"
PROXYBROS_INTERVAL = 600  # fetch every 10 minutes

proxy_set = set()
lock = threading.Lock()


def write_proxies_to_file():
    with lock:
        with open(OUTPUT_FILE, "w") as f:
            f.write("\n".join(sorted(proxy_set)))


def fetch_json(url):
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    return response.json()


def scrape_mt_proxies(interval: int = MT_INTERVAL) -> None:
    while True:
        proxies = []
        try:
            mt_list = fetch_json(MTPROTO_URL)
            for item in mt_list:
                host = item.get("host")
                port = item.get("port")
                if host and port:
                    proxies.append(f"{host}:{port}")
        except Exception as e:
            print(f"Error fetching mtproto proxies: {e}", file=sys.stderr)
        try:
            socks_list = fetch_json(SOCKS_URL)
            for item in socks_list:
                ip = item.get("ip")
                port = item.get("port")
                if ip and port:
                    proxies.append(f"{ip}:{port}")
        except Exception as e:
            print(f"Error fetching socks proxies: {e}", file=sys.stderr)

        if proxies:
            with lock:
                added = False
                for p in proxies:
                    if p not in proxy_set:
                        proxy_set.add(p)
                        added = True
                if added:
                    write_proxies_to_file()
        time.sleep(interval)


def scrape_freeproxy_world(interval: int = 20) -> None:
    """Fetch all proxies listed on freeproxy.world."""
    base_url = "https://www.freeproxy.world/"
    while True:
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        proxies: list[str] = []
        try:
            resp = requests.get(base_url, headers=headers, timeout=10)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")
            count_div = soup.select_one(".proxy_table_pages")
            total = int(count_div.get("data-counts", "0")) if count_div else 0
            pages = max(1, (total + 49) // 50)
            for page in range(1, pages + 1):
                try:
                    resp = requests.get(base_url, params={"page": page}, headers=headers, timeout=10)
                    resp.raise_for_status()
                    soup = BeautifulSoup(resp.text, "html.parser")
                    for row in soup.select("tbody tr"):
                        cols = [td.get_text(strip=True) for td in row.find_all("td")]
                        if len(cols) >= 6 and cols[0] and cols[1].isdigit():
                            proto = cols[5].split()[0].lower()
                            proxies.append(f"{proto}:{cols[0]}:{cols[1]}")
                except Exception as e:
                    print(f"Error fetching freeproxy.world page {page}: {e}", file=sys.stderr)
                    break
        except Exception as e:
            print(f"Error fetching freeproxy.world: {e}", file=sys.stderr)

        if proxies:
            with lock:
                added = False
                for p in proxies:
                    if p not in proxy_set:
                        proxy_set.add(p)
                        added = True
                if added:
                    write_proxies_to_file()

        time.sleep(interval)


def _parse_free_proxy_cz_page(soup: BeautifulSoup) -> list[str]:
    """Extract proxies from a free-proxy.cz page soup."""
    proxies: list[str] = []
    for row in soup.select("tbody tr"):
        script = row.find("script")
        if not script or not script.string:
            continue
        m = re.search(r'Base64.decode\("([^"]+)"\)', script.string)
        if not m:
            continue
        try:
            ip = base64.b64decode(m.group(1)).decode()
        except Exception:
            continue
        port_span = row.find("span", class_="fport")
        if not port_span:
            continue
        port = port_span.get_text(strip=True)
        proto_elem = row.find("small")
        proto = proto_elem.get_text(strip=True).lower() if proto_elem else "http"
        proxies.append(f"{proto}:{ip}:{port}")
    return proxies


def scrape_free_proxy_cz(interval: int = 20) -> None:
    """Fetch proxies from http://free-proxy.cz/en/ across all pages."""
    base_url = "http://free-proxy.cz"
    while True:
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        proxies: list[str] = []
        pages = 1
        try:
            resp = requests.get(f"{base_url}/en/", headers=headers, timeout=10)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")
            proxies.extend(_parse_free_proxy_cz_page(soup))
            links = soup.select('a[href^="/en/proxylist/main/"]')
            for a in links:
                m = re.search(r"/en/proxylist/main/(\d+)", a.get("href", ""))
                if m:
                    pages = max(pages, int(m.group(1)))
            for page in range(2, pages + 1):
                try:
                    url = f"{base_url}/en/proxylist/main/{page}"
                    resp = requests.get(url, headers=headers, timeout=10)
                    resp.raise_for_status()
                    soup = BeautifulSoup(resp.text, "html.parser")
                    proxies.extend(_parse_free_proxy_cz_page(soup))
                except Exception as e:
                    print(f"Error fetching free-proxy.cz page {page}: {e}", file=sys.stderr)
                    break
        except Exception as e:
            print(f"Error fetching free-proxy.cz: {e}", file=sys.stderr)

        if proxies:
            with lock:
                added = False
                for p in proxies:
                    if p not in proxy_set:
                        proxy_set.add(p)
                        added = True
                if added:
                    write_proxies_to_file()

        time.sleep(interval)


def fetch_with_backoff(url: str, max_retries: int = 5) -> str:
    delay = 1
    for _ in range(max_retries):
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code >= 400:
                raise requests.HTTPError(resp.status_code)
            return resp.text
        except Exception:
            sleep_time = delay + random.uniform(0, 1)
            time.sleep(sleep_time)
            delay = min(delay * 2, 60)
    return ""


def extract_proxies(text: str) -> list[str]:
    found = []
    for m in re.finditer(r"((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})", text):
        ip = m.group(1)
        port = int(m.group(2))
        if not (1 <= port <= 65535):
            continue
        octets = ip.split(".")
        if any(not 0 <= int(o) <= 255 for o in octets):
            continue
        snippet = text[max(0, m.start() - 20): m.end() + 20].lower()
        protocol = "socks5" if "socks5" in snippet else "http"
        found.append(f"{protocol}:{ip}:{port}")
    return found


def monitor_paste_feeds(interval: int = PASTE_INTERVAL) -> None:
    while True:
        for feed in PASTE_FEEDS:
            text = fetch_with_backoff(feed)
            if text:
                proxies = extract_proxies(text)
                with lock:
                    added = False
                    for p in proxies:
                        if p not in proxy_set:
                            proxy_set.add(p)
                            added = True
                    if added:
                        write_proxies_to_file()
            time.sleep(random.uniform(*FEED_DELAY_RANGE))
        time.sleep(interval)


def scrape_tor_relays(interval: int = TOR_INTERVAL) -> None:
    """Fetch relay descriptors from Onionoo and record their addresses."""
    while True:
        try:
            data = fetch_json(ONIONOO_URL)
        except Exception as e:
            print(f"Error fetching Tor relays: {e}", file=sys.stderr)
            time.sleep(interval)
            continue

        proxies = []
        for relay in data.get("relays", []):
            for addr in relay.get("or_addresses", []):
                host_port = addr.split("?")[0]
                if ":" not in host_port:
                    continue
                host, port = host_port.rsplit(":", 1)
                if port.isdigit():
                    proxies.append(f"{host}:{port}")

        if proxies:
            with lock:
                added = False
                for p in proxies:
                    if p not in proxy_set:
                        proxy_set.add(p)
                        added = True
                if added:
                    write_proxies_to_file()

        time.sleep(interval)


def scrape_proxyscrape(interval: float = API_INTERVAL) -> None:
    urls = [
        (PROXYSCRAPE_HTTP_URL, "http"),
        (PROXYSCRAPE_SOCKS4_URL, "socks4"),
        (PROXYSCRAPE_SOCKS5_URL, "socks5"),
    ]
    while True:
        proxies = []
        for url, proto in urls:
            try:
                resp = requests.get(url, timeout=10)
                resp.raise_for_status()
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line:
                        proxies.append(f"{proto}:{line}")
            except Exception as e:
                print(f"Error fetching {url}: {e}", file=sys.stderr)
            time.sleep(interval)
        if proxies:
            with lock:
                added = False
                for p in proxies:
                    if p not in proxy_set:
                        proxy_set.add(p)
                        added = True
                if added:
                    write_proxies_to_file()
        time.sleep(interval)


def scrape_gimmeproxy(interval: float = API_INTERVAL) -> None:
    while True:
        try:
            resp = requests.get(GIMMEPROXY_URL, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            ip = data.get("ip")
            port = data.get("port")
            protocol = data.get("protocol")
            if ip and port and protocol:
                entry = f"{protocol.lower()}:{ip}:{port}"
                with lock:
                    if entry not in proxy_set:
                        proxy_set.add(entry)
                        write_proxies_to_file()
        except Exception as e:
            print(f"Error fetching gimmeproxy: {e}", file=sys.stderr)
        time.sleep(interval)


def scrape_pubproxy(interval: float = API_INTERVAL) -> None:
    while True:
        try:
            resp = requests.get(PUBPROXY_URL, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            items = data.get("data", [])
            if items:
                item = items[0]
                ip_port = item.get("ipPort")
                if ip_port and ":" in ip_port:
                    ip, port = ip_port.split(":", 1)
                else:
                    ip = item.get("ip")
                    port = item.get("port")
                protocol = item.get("type", "http")
                if ip and port:
                    entry = f"{protocol.lower()}:{ip}:{port}"
                    with lock:
                        if entry not in proxy_set:
                            proxy_set.add(entry)
                            write_proxies_to_file()
        except Exception as e:
            print(f"Error fetching pubproxy: {e}", file=sys.stderr)
        time.sleep(interval)


def scrape_proxykingdom(interval: float = API_INTERVAL) -> None:
    while True:
        try:
            resp = requests.get(PROXYKINGDOM_URL, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            ip = data.get("address") or data.get("ip")
            port = data.get("port")
            protocol = data.get("protocol")
            if ip and port and protocol:
                entry = f"{protocol.lower()}:{ip}:{port}"
                with lock:
                    if entry not in proxy_set:
                        proxy_set.add(entry)
                        write_proxies_to_file()
        except Exception as e:
            print(f"Error fetching proxykingdom: {e}", file=sys.stderr)
        time.sleep(interval)


def scrape_geonode(interval: int = GEONODE_INTERVAL) -> None:
    """Fetch proxies from the geonode API."""
    while True:
        proxies = []
        try:
            data = fetch_json(GEONODE_URL)
            for item in data.get("data", []):
                ip = item.get("ip")
                port = item.get("port")
                protocols = item.get("protocols") or []
                proto = protocols[0].lower() if protocols else "http"
                if ip and port:
                    proxies.append(f"{proto}:{ip}:{port}")
        except Exception as e:
            print(f"Error fetching geonode proxies: {e}", file=sys.stderr)

        if proxies:
            with lock:
                added = False
                for p in proxies:
                    if p not in proxy_set:
                        proxy_set.add(p)
                        added = True
                if added:
                    write_proxies_to_file()
        time.sleep(interval)


def scrape_proxyspace(interval: int = PROXYSPACE_INTERVAL) -> None:
    """Fetch proxies from proxyspace.pro lists."""
    urls = [
        (PROXYSPACE_HTTP_URL, "http"),
        (PROXYSPACE_HTTPS_URL, "https"),
        (PROXYSPACE_SOCKS4_URL, "socks4"),
        (PROXYSPACE_SOCKS5_URL, "socks5"),
    ]
    while True:
        proxies = []
        for url, proto in urls:
            try:
                resp = requests.get(url, timeout=10)
                resp.raise_for_status()
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line:
                        proxies.append(f"{proto}:{line}")
            except Exception as e:
                print(f"Error fetching {url}: {e}", file=sys.stderr)
            time.sleep(1)
        if proxies:
            with lock:
                added = False
                for p in proxies:
                    if p not in proxy_set:
                        proxy_set.add(p)
                        added = True
                if added:
                    write_proxies_to_file()
        time.sleep(interval)


def scrape_proxy_list_sites(interval: int = PROXY_LIST_INTERVAL) -> None:
    """Fetch proxies from free-proxy-list.net and similar sites."""
    while True:
        for url, proto in PROXY_LIST_SITES:
            try:
                resp = requests.get(url, timeout=10)
                resp.raise_for_status()
                soup = BeautifulSoup(resp.text, "html.parser")
                proxies = []
                textarea = soup.find("textarea")
                if textarea:
                    text = textarea.get_text()
                    for line in text.splitlines():
                        line = line.strip()
                        if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}:\d+$", line):
                            proxies.append(f"{proto}:{line}")
                else:
                    for row in soup.select("table tbody tr"):
                        cols = row.find_all("td")
                        if len(cols) >= 2:
                            ip = cols[0].get_text(strip=True)
                            port = cols[1].get_text(strip=True)
                            if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", ip) and port.isdigit():
                                proxies.append(f"{proto}:{ip}:{port}")
                if proxies:
                    with lock:
                        added = False
                        for p in proxies:
                            if p not in proxy_set:
                                proxy_set.add(p)
                                added = True
                        if added:
                            write_proxies_to_file()
            except Exception as e:
                print(f"Error fetching {url}: {e}", file=sys.stderr)
            time.sleep(random.uniform(1, 3))
        time.sleep(interval)


def scrape_proxy_list_download(interval: float = API_INTERVAL) -> None:
    """Fetch proxies from https://www.proxy-list.download/api."""
    types = ["http", "https", "socks4", "socks5"]
    while True:
        proxies = []
        for proto in types:
            url = f"https://www.proxy-list.download/api/v1/get?type={proto}"
            try:
                resp = requests.get(url, timeout=10)
                resp.raise_for_status()
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line:
                        proxies.append(f"{proto}:{line}")
            except Exception as e:
                print(f"Error fetching {url}: {e}", file=sys.stderr)
            time.sleep(interval)
        if proxies:
            with lock:
                added = False
                for p in proxies:
                    if p not in proxy_set:
                        proxy_set.add(p)
                        added = True
                if added:
                    write_proxies_to_file()
        time.sleep(interval)


def scrape_freeproxy(interval: int = FREEPROXY_INTERVAL) -> None:
    """Fetch proxies from dpangestuw Free-Proxy GitHub lists."""
    urls = [
        (FREEPROXY_HTTP_URL, "http"),
        (FREEPROXY_SOCKS4_URL, "socks4"),
        (FREEPROXY_SOCKS5_URL, "socks5"),
    ]
    while True:
        proxies = []
        for url, proto in urls:
            try:
                resp = requests.get(url, timeout=10)
                resp.raise_for_status()
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line:
                        proxies.append(f"{proto}:{line}")
            except Exception as e:
                print(f"Error fetching {url}: {e}", file=sys.stderr)
            time.sleep(1)
        if proxies:
            with lock:
                added = False
                for p in proxies:
                    if p not in proxy_set:
                        proxy_set.add(p)
                        added = True
                if added:
                    write_proxies_to_file()
        time.sleep(interval)


def scrape_freshproxy(interval: int = FRESHPROXY_INTERVAL) -> None:
    """Fetch proxies from the Fresh Proxy List project."""
    urls = [
        (FRESHPROXY_HTTP_URL, "http"),
        (FRESHPROXY_HTTPS_URL, "https"),
        (FRESHPROXY_SOCKS4_URL, "socks4"),
        (FRESHPROXY_SOCKS5_URL, "socks5"),
    ]
    while True:
        proxies = []
        for url, proto in urls:
            try:
                resp = requests.get(url, timeout=10)
                resp.raise_for_status()
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line and re.match(r"^(?:\d{1,3}\.){3}\d{1,3}:\d+$", line):
                        proxies.append(f"{proto}:{line}")
            except Exception as e:
                print(f"Error fetching {url}: {e}", file=sys.stderr)
            time.sleep(1)
        if proxies:
            with lock:
                added = False
                for p in proxies:
                    if p not in proxy_set:
                        proxy_set.add(p)
                        added = True
                if added:
                    write_proxies_to_file()
        time.sleep(interval)


def scrape_proxifly(interval: int = PROXIFLY_INTERVAL) -> None:
    """Fetch proxies from the Proxifly free-proxy lists."""
    urls = [
        (PROXIFLY_HTTP_URL, "http"),
        (PROXIFLY_SOCKS4_URL, "socks4"),
        (PROXIFLY_SOCKS5_URL, "socks5"),
    ]
    while True:
        proxies = []
        for url, proto in urls:
            try:
                resp = requests.get(url, timeout=10)
                resp.raise_for_status()
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line:
                        if '://' in line:
                            _, line = line.split('://', 1)
                        proxies.append(f"{proto}:{line}")
            except Exception as e:
                print(f"Error fetching {url}: {e}", file=sys.stderr)
            time.sleep(1)
        if proxies:
            with lock:
                added = False
                for p in proxies:
                    if p not in proxy_set:
                        proxy_set.add(p)
                        added = True
                if added:
                    write_proxies_to_file()
        time.sleep(interval)


def scrape_freeproxy_all(interval: int = FREEPROXY_ALL_INTERVAL) -> None:
    """Fetch aggregated proxies from dpangestuw Free-Proxy."""
    while True:
        proxies = []
        try:
            resp = requests.get(FREEPROXY_ALL_URL, timeout=10)
            resp.raise_for_status()
            for line in resp.text.splitlines():
                line = line.strip()
                if not line:
                    continue
                if '://' in line:
                    proto, rest = line.split('://', 1)
                    proxies.append(f"{proto.lower()}:{rest}")
                elif re.match(r"^(?:\d{1,3}\.){3}\d{1,3}:\d+$", line):
                    proxies.append(f"http:{line}")
        except Exception as e:
            print(f"Error fetching {FREEPROXY_ALL_URL}: {e}", file=sys.stderr)

        if proxies:
            with lock:
                added = False
                for p in proxies:
                    if p not in proxy_set:
                        proxy_set.add(p)
                        added = True
                if added:
                    write_proxies_to_file()
        time.sleep(interval)


def scrape_kangproxy(interval: int = KANGPROXY_INTERVAL) -> None:
    """Fetch proxies from the KangProxy raw lists."""
    urls = [KANGPROXY_OLD_URL, KANGPROXY_URL]
    while True:
        proxies = []
        for url in urls:
            try:
                resp = requests.get(url, timeout=10)
                resp.raise_for_status()
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    if '://' in line:
                        proto, rest = line.split('://', 1)
                        proxies.append(f"{proto.lower()}:{rest}")
                    elif re.match(r"^(?:\d{1,3}\.){3}\d{1,3}:\d+$", line):
                        proxies.append(f"http:{line}")
            except Exception as e:
                print(f"Error fetching {url}: {e}", file=sys.stderr)
            time.sleep(1)

        if proxies:
            with lock:
                added = False
                for p in proxies:
                    if p not in proxy_set:
                        proxy_set.add(p)
                        added = True
                if added:
                    write_proxies_to_file()
        time.sleep(interval)


def _parse_spys_list(text: str) -> list[tuple[str, str]]:
    """Return list of (ip, port) from spys.me proxy list text."""
    proxies = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("Proxy list") or line.startswith("Http proxy") \
                or line.startswith("Socks proxy") or line.startswith("Support") \
                or line.startswith("BTC") or line.startswith("IP address") \
                or line.lower().startswith("free "):
            continue
        ip_port = line.split()[0]
        if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}:\d+$", ip_port):
            ip, port = ip_port.split(":", 1)
            proxies.append((ip, port))
    return proxies


def scrape_spys(interval: int = SPYS_INTERVAL) -> None:
    """Fetch proxies from spys.me lists and store as type;ip;port."""
    urls = [
        (SPYS_HTTP_URL, "http"),
        (SPYS_SOCKS_URL, "socks5"),
    ]
    while True:
        proxies = []
        for url, proto in urls:
            try:
                resp = requests.get(url, timeout=10)
                resp.raise_for_status()
                for ip, port in _parse_spys_list(resp.text):
                    proxies.append(f"{proto};{ip};{port}")
            except Exception as e:
                print(f"Error fetching {url}: {e}", file=sys.stderr)
            time.sleep(1)

        if proxies:
            with lock:
                added = False
                for p in proxies:
                    if p not in proxy_set:
                        proxy_set.add(p)
                        added = True
                if added:
                    write_proxies_to_file()

        time.sleep(interval)


def scrape_proxybros(interval: int = PROXYBROS_INTERVAL) -> None:
    """Fetch proxies from proxybros.com free proxy list."""
    while True:
        proxies = []
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            resp = requests.get(PROXYBROS_URL, headers=headers, timeout=10)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")
            for row in soup.select("table.proxylist-table tbody tr"):
                ip_el = row.select_one("span.proxy-ip[data-ip]")
                port_el = row.select_one("td[data-port]")
                cells = row.find_all("td")
                if ip_el and port_el and len(cells) >= 5:
                    ip = ip_el.get_text(strip=True)
                    port = port_el.get_text(strip=True)
                    proto = cells[4].get_text(strip=True).lower()
                    proxies.append(f"{proto}:{ip}:{port}")
        except Exception as e:
            print(f"Error fetching proxybros proxies: {e}", file=sys.stderr)

        if proxies:
            with lock:
                added = False
                for p in proxies:
                    if p not in proxy_set:
                        proxy_set.add(p)
                        added = True
                if added:
                    write_proxies_to_file()
        time.sleep(interval)


async def _irc_listener(server: str, port: int = 6667) -> None:
    """Connect to an IRC server and monitor channels for proxy announcements."""
    import string

    while True:
        reader = writer = None
        try:
            reader, writer = await asyncio.open_connection(server, port)
            nick = "bot" + "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
            writer.write(f"NICK {nick}\r\n".encode())
            writer.write(f"USER {nick} 0 * :{nick}\r\n".encode())
            await writer.drain()

            await asyncio.sleep(5)
            channels = IRC_CHANNELS[:]
            random.shuffle(channels)
            for chan in channels:
                writer.write(f"JOIN {chan}\r\n".encode())
                await writer.drain()
                await asyncio.sleep(random.uniform(1, 3))

            while True:
                line = await reader.readline()
                if not line:
                    raise ConnectionError("EOF")
                text = line.decode(errors="ignore").strip()
                if text.startswith("PING"):
                    token = text.split()[1]
                    writer.write(f"PONG {token}\r\n".encode())
                    await writer.drain()
                    continue
                proxies = extract_proxies(text)
                if proxies:
                    with lock:
                        added = False
                        for p in proxies:
                            if p not in proxy_set:
                                proxy_set.add(p)
                                added = True
                        if added:
                            write_proxies_to_file()
        except Exception as e:
            print(f"IRC {server} error: {e}", file=sys.stderr)
        finally:
            if writer:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
        await asyncio.sleep(10)


async def monitor_irc_channels() -> None:
    tasks = [asyncio.create_task(_irc_listener(s)) for s in IRC_SERVERS]
    await asyncio.gather(*tasks)


def bencode(value) -> bytes:
    if isinstance(value, int):
        return b"i" + str(value).encode() + b"e"
    if isinstance(value, bytes):
        return str(len(value)).encode() + b":" + value
    if isinstance(value, str):
        b = value.encode()
        return str(len(b)).encode() + b":" + b
    if isinstance(value, list):
        return b"l" + b"".join(bencode(v) for v in value) + b"e"
    if isinstance(value, dict):
        items = sorted(value.items())
        return b"d" + b"".join(bencode(k) + bencode(v) for k, v in items) + b"e"
    raise TypeError("Unsupported type for bencoding")


def bdecode(data: bytes):
    def parse(index: int):
        lead = data[index:index + 1]
        if lead == b"i":
            end = data.index(b"e", index + 1)
            return int(data[index + 1:end]), end + 1
        if lead == b"l":
            index += 1
            lst = []
            while data[index:index + 1] != b"e":
                item, index = parse(index)
                lst.append(item)
            return lst, index + 1
        if lead == b"d":
            index += 1
            d = {}
            while data[index:index + 1] != b"e":
                key, index = parse(index)
                val, index = parse(index)
                d[key] = val
            return d, index + 1
        if lead.isdigit():
            colon = data.index(b":", index)
            length = int(data[index:colon])
            start = colon + 1
            end = start + length
            return data[start:end], end
        raise ValueError("Invalid bencode")

    value, _ = parse(0)
    return value


class DHTClient(asyncio.DatagramProtocol):
    def __init__(self, node_id: bytes):
        self.node_id = node_id
        self.transactions: dict[bytes, asyncio.Future] = {}
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore

    def datagram_received(self, data: bytes, addr) -> None:
        try:
            msg = bdecode(data)
        except Exception:
            return
        tid = msg.get(b"t")
        fut = self.transactions.pop(tid, None)
        if fut and not fut.done():
            fut.set_result((msg, addr))

    async def _query(self, addr: tuple[str, int], msg: dict) -> tuple[dict, tuple[str, int]]:
        tid = os.urandom(2)
        msg[b"t"] = tid
        data = bencode(msg)
        fut = asyncio.get_running_loop().create_future()
        self.transactions[tid] = fut
        assert self.transport is not None
        self.transport.sendto(data, addr)
        try:
            return await asyncio.wait_for(fut, timeout=5)
        finally:
            self.transactions.pop(tid, None)

    async def find_node(self, addr: tuple[str, int], target: bytes):
        msg = {b"y": b"q", b"q": b"find_node", b"a": {b"id": self.node_id, b"target": target}}
        return await self._query(addr, msg)

    async def get_peers(self, addr: tuple[str, int], info_hash: bytes):
        msg = {b"y": b"q", b"q": b"get_peers", b"a": {b"id": self.node_id, b"info_hash": info_hash}}
        return await self._query(addr, msg)


def _decode_nodes(data: bytes) -> list[tuple[str, int]]:
    nodes = []
    for i in range(0, len(data), 26):
        segment = data[i:i + 26]
        if len(segment) < 26:
            continue
        ip = socket.inet_ntoa(segment[20:24])
        port = struct.unpack("!H", segment[24:26])[0]
        nodes.append((ip, port))
    return nodes


def _decode_peers(values: list) -> list[tuple[str, int]]:
    peers = []
    for val in values:
        if len(val) != 6:
            continue
        ip = socket.inet_ntoa(val[:4])
        port = struct.unpack("!H", val[4:6])[0]
        peers.append((ip, port))
    return peers


async def crawl_dht() -> None:
    loop = asyncio.get_running_loop()
    node_id = os.urandom(20)
    transport, client = await loop.create_datagram_endpoint(
        lambda: DHTClient(node_id), local_addr=("0.0.0.0", 0)
    )

    queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
    visited: set[tuple[str, int]] = set()

    for host, port in BOOTSTRAP_NODES:
        try:
            ip = socket.gethostbyname(host)
            queue.put_nowait((ip, port))
        except Exception as e:
            print(f"Failed to resolve {host}: {e}")

    sem = asyncio.Semaphore(MAX_DHT_CONCURRENCY)
    count = 0

    async def worker() -> None:
        nonlocal count
        while True:
            ip, port = await queue.get()
            if (ip, port) in visited:
                queue.task_done()
                continue
            visited.add((ip, port))
            async with sem:
                try:
                    resp, _ = await client.find_node((ip, port), os.urandom(20))
                    nodes = _decode_nodes(resp.get(b"r", {}).get(b"nodes", b""))
                    for n in nodes:
                        if n not in visited:
                            queue.put_nowait(n)
                except Exception:
                    pass
                try:
                    resp, _ = await client.get_peers((ip, port), os.urandom(20))
                    vals = resp.get(b"r", {}).get(b"values", [])
                    peers = _decode_peers(vals)
                    if peers:
                        with lock:
                            added = False
                            for p_ip, p_port in peers:
                                if p_port in PROXY_PORTS:
                                    entry = f"{p_ip}:{p_port}"
                                    if entry not in proxy_set:
                                        proxy_set.add(entry)
                                        added = True
                            if added:
                                write_proxies_to_file()
                except Exception:
                    pass

                count += 1
                if count % DHT_LOG_EVERY == 0:
                    print(f"DHT: visited {len(visited)} nodes, proxies {len(proxy_set)}")
            queue.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(MAX_DHT_CONCURRENCY)]
    await asyncio.gather(*workers)


def main() -> None:
    threads = [
        threading.Thread(target=scrape_mt_proxies, daemon=True),
        threading.Thread(target=monitor_paste_feeds, daemon=True),
        threading.Thread(target=lambda: asyncio.run(crawl_dht()), daemon=True),
        threading.Thread(target=scrape_tor_relays, daemon=True),
        threading.Thread(target=lambda: asyncio.run(monitor_irc_channels()), daemon=True),
        threading.Thread(target=scrape_proxyscrape, daemon=True),
        threading.Thread(target=scrape_gimmeproxy, daemon=True),
        threading.Thread(target=scrape_pubproxy, daemon=True),
        threading.Thread(target=scrape_proxykingdom, daemon=True),
        threading.Thread(target=scrape_geonode, daemon=True),
        threading.Thread(target=scrape_proxyspace, daemon=True),
        threading.Thread(target=scrape_proxy_list_sites, daemon=True),
        threading.Thread(target=scrape_proxy_list_download, daemon=True),
        threading.Thread(target=scrape_freeproxy, daemon=True),
        threading.Thread(target=scrape_freshproxy, daemon=True),
        threading.Thread(target=scrape_proxifly, daemon=True),
        threading.Thread(target=scrape_free_proxy_cz, daemon=True),
        threading.Thread(target=scrape_freeproxy_world, daemon=True),
        threading.Thread(target=scrape_freeproxy_all, daemon=True),
        threading.Thread(target=scrape_kangproxy, daemon=True),
        threading.Thread(target=scrape_spys, daemon=True),
        threading.Thread(target=scrape_proxybros, daemon=True),
    ]
    for t in threads:
        t.start()
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
