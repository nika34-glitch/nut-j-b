import requests
import time
import threading
import random
import re
import base64
import asyncio
import os
try:
    if os.name != "nt":
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    else:
        uvloop = None
except Exception:
    uvloop = None
from functools import lru_cache
import socket
import struct
import json
import ssl
import importlib.util
from pathlib import Path
from typing import Any, AsyncGenerator, List
from concurrent.futures import ThreadPoolExecutor
import multiprocessing
import gzip
from io import StringIO
try:
    import orjson  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    orjson = None  # type: ignore

try:
    import regex  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    import re as regex
import logging
import ipaddress
import itertools
import math
import aiofiles

# Older versions of ``aiofiles`` may not expose a ``BaseFile`` class.  This
# attribute is only used for type hints, so provide a minimal stub when
# missing to avoid ``AttributeError`` at import time.
if not hasattr(aiofiles, "BaseFile"):
    class _BF:
        pass


    aiofiles.BaseFile = _BF  # type: ignore[attr-defined]

try:
    import aiodns  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    aiodns = None  # type: ignore

import csv
import bisect
from collections import defaultdict

try:
    from pybloom_live import ScalableBloomFilter  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    class ScalableBloomFilter:  # minimal stub
        SMALL_SET_GROWTH = 2

        def __init__(self, *_, **__):
            pass

        def add(self, item):
            return True

        def __contains__(self, item):
            return False
try:
    from score_cython import score_single_proxy as cy_score_single_proxy
except Exception:
    cy_score_single_proxy = None

try:
    from proxyhub import SOURCE_LIST, fetch_source
except ImportError:
    SOURCE_LIST = []

    async def fetch_source(url: str) -> list[str]:
        return []

    logging.warning(
        "proxyhub module not found or incomplete, disabling ProxyHub scraping"
    )

try:
    import aiohttp  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    aiohttp = None  # type: ignore

try:
    from bs4 import BeautifulSoup  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    BeautifulSoup = None  # type: ignore

def create_soup(text: str):
    """Return ``BeautifulSoup`` object using available parser."""
    if BeautifulSoup is None:
        raise RuntimeError("BeautifulSoup not available")
    try:
        return BeautifulSoup(text, "lxml")
    except Exception:
        return BeautifulSoup(text, "html.parser")

REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "10"))

MTPROTO_URL = "https://mtpro.xyz/api/?type=mtproto"
SOCKS_URL = "https://mtpro.xyz/api/?type=socks"
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "proxies.txt")
OUTPUT_COMPRESSED = os.getenv("OUTPUT_COMPRESSED", "0") == "1"
if OUTPUT_COMPRESSED and not OUTPUT_FILE.endswith(".gz"):
    OUTPUT_FILE += ".gz"

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")

PROXXY_SOURCES_FILE = os.path.join(
    os.path.dirname(__file__), "vendor", "proXXy", "proxy_sources.json"
)

# ProxyHub async scraping configuration
PROXYHUB_INTERVAL = 300.0  # seconds between ProxyHub runs
PROXYHUB_CONCURRENCY = int(os.getenv("PROXYHUB_CONCURRENCY", "20"))
PROXYHUB_BATCH_SIZE = int(os.getenv("PROXYHUB_BATCH_SIZE", "100"))
BLOODY_INTERVAL = 300  # seconds between Bloody-Proxy-Scraper runs
MAX_PROXY_SET_SIZE = int(os.getenv("MAX_PROXY_SET_SIZE", "100000"))

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

PROXY_RE = regex.compile(r"((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})")
IP_PORT_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}:\d+$")
PROTO_PARAM_RE = re.compile(r"protocol=([^&]+)")
FREE_CZ_BASE64_RE = re.compile(r'Base64.decode\("([^"]+)"\)')
FREE_CZ_PAGE_RE = re.compile(r"/en/proxylist/main/(\d+)")

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
MAX_DHT_CONCURRENCY = int(os.getenv("MAX_DHT_CONCURRENCY", "200"))
MAX_DHT_WORKERS = int(os.getenv("MAX_DHT_WORKERS", "40"))
DHT_PROCESSES = int(os.getenv("DHT_PROCESSES", "1"))
PROXY_PORTS = {8080, 3128, 1080, 9050, 8000, 8081, 8888}
DHT_LOG_EVERY = 100  # log progress every N visited nodes

# Tor relay crawling configuration
ONIONOO_URL = "https://onionoo.torproject.org/details"
TOR_INTERVAL = 3600  # seconds between Tor relay list updates

# Additional HTTP API backends
API_INTERVAL = 0.3  # delay between individual API requests
PROXYSCRAPE_HTTP_URL = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=no&anonymity=all"
PROXYSCRAPE_SOCKS4_URL = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000&country=all"
PROXYSCRAPE_SOCKS5_URL = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all"
GIMMEPROXY_URL = "https://gimmeproxy.com/api/getProxy"
PUBPROXY_URL = "http://pubproxy.com/api/proxy"
PROXYKINGDOM_URL = "https://api.proxykingdom.com/proxy?token=xN9IoZDLnMzUC0"
GEONODE_URL = (
    "https://proxylist.geonode.com/api/proxy-list"
    "?limit=500&page=4&sort_by=lastChecked&sort_type=desc"
)
GEONODE_INTERVAL = 5  # seconds between geonode API requests

# GatherProxy scraping configuration
GATHER_PROXY_URI = "http://www.gatherproxy.com/proxylist/anonymity/"
GATHER_PROXY_INTERVAL = 600  # seconds between full GatherProxy cycles
GATHER_PROXY_CONCURRENCY = 5  # how many pages to fetch in parallel
GATHER_PROXY_MIN_UPTIME = 0  # Uptime filter

# ProxyScraper integration settings
PS_SCRAPER_SOURCES = [
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000",
    # add any other ProxyScraper endpoints here
]
# seconds between each ProxyScraper fetch cycle
PS_INTERVAL = 30
# how many sources to fetch in parallel
PS_CONCURRENT_REQUESTS = 5
# Increase PS_CONCURRENT_REQUESTS or lower PS_INTERVAL to speed up scraping,
# or decrease them to reduce load.

SHARED_THREAD_POOL = ThreadPoolExecutor(max_workers=PS_CONCURRENT_REQUESTS)

# ProxySpace backend configuration
PROXYSPACE_HTTP_URL = "https://proxyspace.pro/http.txt"
PROXYSPACE_HTTPS_URL = "https://proxyspace.pro/https.txt"
PROXYSPACE_SOCKS4_URL = "https://proxyspace.pro/socks4.txt"
PROXYSPACE_SOCKS5_URL = "https://proxyspace.pro/socks5.txt"
# fetch new lists roughly every 20 minutes
PROXYSPACE_INTERVAL = 1200

# dpangestuw Free-Proxy GitHub lists
FREEPROXY_HTTP_URL = "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/http_proxies.txt"
FREEPROXY_SOCKS4_URL = "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/socks4_proxies.txt"
FREEPROXY_SOCKS5_URL = "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/socks5_proxies.txt"
FREEPROXY_INTERVAL = 120  # fetch every 2 minutes
# aggregated list updated every 5 minutes
FREEPROXY_ALL_URL = "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/All_proxies.txt"
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
PROXIFLY_HTTP_URL = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt"
PROXIFLY_SOCKS4_URL = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks4/data.txt"
PROXIFLY_SOCKS5_URL = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt"
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

# openproxylist.xyz raw lists
OPENPROXYLIST_INTERVAL = 900  # seconds between full cycles
OPENPROXYLIST_CONCURRENCY = 4  # how many lists to fetch in parallel
OPENPROXYLIST_ENDPOINTS = [
    "https://openproxylist.xyz/http.txt",
    "https://openproxylist.xyz/https.txt",
    "https://openproxylist.xyz/socks4.txt",
    "https://openproxylist.xyz/socks5.txt",
]

SCRAPERS = {
    "mtpro": MT_INTERVAL,
    "paste": PASTE_INTERVAL,
    "freeproxy_world": 20,
    "free_proxy_cz": 20,
    "tor": TOR_INTERVAL,
    "proxyscrape": API_INTERVAL,
    "gimmeproxy": API_INTERVAL,
    "pubproxy": API_INTERVAL,
    "proxykingdom": API_INTERVAL,
    "geonode": GEONODE_INTERVAL,
    "proxyspace": PROXYSPACE_INTERVAL,
    "proxy_list_sites": PROXY_LIST_INTERVAL,
    "proxy_list_download": API_INTERVAL,
    "freeproxy": FREEPROXY_INTERVAL,
    "freshproxy": FRESHPROXY_INTERVAL,
    "proxifly": PROXIFLY_INTERVAL,
    "freeproxy_all": FREEPROXY_ALL_INTERVAL,
    "kangproxy": KANGPROXY_INTERVAL,
    "spys": SPYS_INTERVAL,
    "proxybros": PROXYBROS_INTERVAL,
    "openproxylist": OPENPROXYLIST_INTERVAL,
    "gatherproxy": GATHER_PROXY_INTERVAL,
    "bloody": BLOODY_INTERVAL,
    "proxxy": 300,
}

# Load optional configuration overrides
CONFIG_FILE = os.getenv("CONFIG_FILE", "config.json")
if os.path.exists(CONFIG_FILE):
    try:
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
        for k, v in cfg.items():
            if k.isupper():
                globals()[k] = v
    except Exception as exc:
        logging.error("Error loading config %s: %s", CONFIG_FILE, exc)

requests_session = requests.Session()
aiohttp_session: Any | None = None
httpx_client = None
USE_HTTP2 = os.getenv("USE_HTTP2", "0") == "1"
MAIN_LOOP: asyncio.AbstractEventLoop | None = None

proxy_set: ScalableBloomFilter = ScalableBloomFilter(mode=ScalableBloomFilter.SMALL_SET_GROWTH)
if aiodns is not None:
    try:
        DNS_RESOLVER = aiodns.DNSResolver()
    except RuntimeError:
        class _DummyResolver:
            async def gethostbyname(self, host, family):
                raise RuntimeError("aiodns requires an event loop")

        DNS_RESOLVER = _DummyResolver()
else:  # pragma: no cover - optional dependency missing
    class _DummyResolver:
        async def gethostbyname(self, host, family):
            raise RuntimeError("aiodns not available")

    DNS_RESOLVER = _DummyResolver()
SOURCE_BACKOFF: defaultdict[str, int] = defaultdict(int)
proxy_lock = asyncio.Lock()
new_entries: asyncio.Queue[str] = asyncio.Queue()
write_event = asyncio.Event()
lock = threading.Lock()
_open_files: dict[str, aiofiles.BaseFile] = {}
DNS_CACHE: dict[str, tuple[str, float]] = {}
DNS_CACHE_TTL = 60.0


PROTOCOL_RE = re.compile(r"^(https?|socks4|socks5)$", re.I)

# Scoring weights and thresholds for filter_p2
WEIGHTS = {
    "ip_rep": 179,
    "tls_reach": 152,
}
CRITICAL_MIN = 120
OVERALL_MIN = 250

# Optional scoring configuration loaded from JSON/YAML
MODE = "strict"
SCORING_CONFIG = os.getenv(
    "SCORING_CONFIG",
    str(Path(__file__).resolve().parent / "data" / "scoring_config.json"),
)

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    yaml = None  # type: ignore


def load_scoring_config(path: str | None = None) -> None:
    """Load scoring weights and thresholds from a config file."""

    global MODE, CRITICAL_MIN, OVERALL_MIN, WEIGHTS

    file_path = path or SCORING_CONFIG
    if not os.path.exists(file_path):
        return

    try:
        with open(file_path, "r") as f:
            text = f.read()
        if file_path.endswith(('.yml', '.yaml')) and yaml is not None:
            cfg = yaml.safe_load(text)
        else:
            cfg = json.loads(text)
    except Exception as exc:  # pragma: no cover - invalid config
        logging.error("Error loading scoring config %s: %s", file_path, exc)
        return

    mode = str(cfg.get("mode", MODE)).lower()
    if mode not in {"strict", "lenient"}:
        mode = "strict"
    MODE = mode

    section = cfg.get(mode) if isinstance(cfg.get(mode), dict) else cfg

    CRITICAL_MIN = section.get("CRITICAL_MIN", CRITICAL_MIN)
    OVERALL_MIN = section.get("OVERALL_MIN", OVERALL_MIN)
    weights = section.get("WEIGHTS") or section.get("weights")
    if isinstance(weights, dict):
        for k, v in weights.items():
            if k in WEIGHTS:
                WEIGHTS[k] = v


load_scoring_config()

# JA3 / ASN data and history tracking
JA3_CACHE_TTL = 1800  # seconds
_ja3_cache: dict[str, tuple[str | None, float]] = {}
# Freshness tracking per proxy URL with EWMA
FRESH_HISTORY: dict[str, tuple[float, float]] = {}
FRESH_HALF_LIFE = 6 * 3600  # 6 hours
HISTORY: dict[str, tuple[float, int]] = {}
KNOWN_BAD_JA3: set[str] = set()
ASN_TYPE: dict[int, str] = {}
CLOUD_ASNS: set[int] = set()

# GeoIP / error rate tracking
GEO_DATA: list[tuple[int, int, str]] = []
_geo_loaded = False
# Allow-lists loaded from JSON
ALLOWLIST_FILE = os.getenv(
    "ALLOWLIST_FILE",
    str(Path(__file__).resolve().parent / "data" / "allow_lists.json"),
)
ALLOWED_COUNTRIES: set[str] = {"IT"}
ALLOWED_ASNS: set[int] = set()
EU_COUNTRIES = {
    "AT","BE","BG","HR","CY","CZ","DK","EE","FI","FR","DE","GR","HU",
    "IE","IT","LV","LT","LU","MT","NL","PL","PT","RO","SK","SI","ES","SE"
}

ERR_STATS: defaultdict[str, dict] = defaultdict(
    lambda: {"tries": 0, "fails": 0, "ts": time.time()}
)

LATENCY_CACHE_TTL = 900  # seconds
_latency_cache: dict[str, tuple[float | None, float]] = {}

# TLS caching and blacklist structures
TLS_CACHE_TTL = 900  # seconds
tls_cache: dict[str, tuple[float, float]] = {}
tls_semaphore = asyncio.Semaphore(2000)

_soft_blacklists: set[ipaddress._BaseNetwork] = set()
_hard_blacklists: set[ipaddress._BaseNetwork] = set()
_blacklists_loaded = False
PREFIX_LENGTHS = (8, 16, 24)
_soft_prefixes: dict[int, set[int]] = {n: set() for n in PREFIX_LENGTHS}
_hard_prefixes: dict[int, set[int]] = {n: set() for n in PREFIX_LENGTHS}


def _parse_blacklist_lines(lines: list[str], dest: set[ipaddress._BaseNetwork]) -> None:
    for line in lines:
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        token = line.split()[0]
        try:
            dest.add(ipaddress.ip_network(token, strict=False))
        except Exception:
            continue


async def load_blacklists() -> None:
    global _blacklists_loaded
    if _blacklists_loaded:
        return

    soft_urls = [
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    ]
    hard_urls = [
        "https://www.spamhaus.org/drop/drop.txt",
        "https://www.spamhaus.org/drop/edrop.txt",
    ]

    async def fetch(url: str) -> str:
        def _get() -> str:
            resp = requests_session.get(url, timeout=4)
            resp.raise_for_status()
            return resp.text

        try:
            return await asyncio.wait_for(asyncio.to_thread(_get), timeout=4)
        except Exception as exc:
            logging.error("Error loading blacklist %s: %s", url, exc)
            return ""

    tasks = [asyncio.create_task(fetch(u)) for u in soft_urls + hard_urls]
    results = await asyncio.gather(*tasks)

    for url, text in zip(soft_urls + hard_urls, results):
        if not text:
            continue
        lines = text.splitlines()
        if url in soft_urls:
            _parse_blacklist_lines(lines, _soft_blacklists)
        else:
            _parse_blacklist_lines(lines, _hard_blacklists)

    local_dir = Path(__file__).resolve().parent / "data" / "blacklists"
    if local_dir.exists():
        for path in local_dir.glob("*.txt"):
            try:
                text = path.read_text()
                _parse_blacklist_lines(text.splitlines(), _hard_blacklists)
            except Exception as exc:
                logging.error("Error loading %s: %s", path, exc)

    for net in _hard_blacklists:
        if isinstance(net, ipaddress.IPv4Network):
            ip_int = int(net.network_address)
            for plen in PREFIX_LENGTHS:
                if net.prefixlen <= plen:
                    _hard_prefixes[plen].add(ip_int >> (32 - plen))

    for net in _soft_blacklists:
        if isinstance(net, ipaddress.IPv4Network):
            ip_int = int(net.network_address)
            for plen in PREFIX_LENGTHS:
                if net.prefixlen <= plen:
                    _soft_prefixes[plen].add(ip_int >> (32 - plen))

    _blacklists_loaded = True


async def load_ja3_sets() -> None:
    """Load known bad JA3 fingerprints from data files."""
    global KNOWN_BAD_JA3
    if KNOWN_BAD_JA3:
        return

    path = Path(__file__).resolve().parent / "data" / "ja3" / "known_bad.txt"

    if not path.exists():
        KNOWN_BAD_JA3 = set()
        return

    async with aiofiles.open(path, "r") as f:
        KNOWN_BAD_JA3 = {
            line.strip() async for line in f if line.strip()
        }


async def load_asn_metadata() -> None:
    """Load ASN type map and cloud ASN list."""
    global ASN_TYPE, CLOUD_ASNS
    if ASN_TYPE or CLOUD_ASNS:
        return

    base = Path(__file__).resolve().parent / "data" / "asn"
    map_path = base / "asn_map.csv"
    cloud_path = base / "cloud_asns.txt"

    import pandas as pd

    if map_path.exists():
        async with aiofiles.open(map_path, "r") as f:
            csv_text = await f.read()
        df = pd.read_csv(StringIO(csv_text), dtype=str)
        asn_map: dict[int, str] = {}
        for asn, typ in zip(df["asn"], df["type"]):
            try:
                asn_map[int(asn)] = str(typ)
            except Exception:
                continue
    else:
        asn_map = {}

    if cloud_path.exists():
        async with aiofiles.open(cloud_path, "r") as f:
            cloud_lines = [line.strip() async for line in f if line.strip()]
        cloud_set = {int(line) for line in cloud_lines}
    else:
        cloud_set = set()

    ASN_TYPE, CLOUD_ASNS = asn_map, cloud_set


async def load_geoip() -> None:
    """Load GeoIP CSV into memory."""
    global GEO_DATA, _geo_loaded
    if _geo_loaded:
        return

    path = Path(__file__).resolve().parent / "data" / "geo" / "ip2country.csv"

    if not path.exists():
        GEO_DATA = []
        _geo_loaded = True
        return

    async with aiofiles.open(path, "r") as f:
        text = await f.read()

    rows: list[tuple[int, int, str]] = []
    reader = csv.reader(text.splitlines())
    next(reader, None)
    for row in reader:
        if len(row) < 3:
            continue
        try:
            start = int(row[0])
            end = int(row[1])
        except Exception:
            try:
                start = int(ipaddress.ip_address(row[0]))
                end = int(ipaddress.ip_address(row[1]))
            except Exception:
                continue
        cc = row[2].strip().upper()
        rows.append((start, end, cc))
    rows.sort(key=lambda r: r[0])
    GEO_DATA = rows
    _geo_loaded = True


def load_allow_lists(path: str | None = None) -> None:
    """Load country and ASN allow-lists from JSON file."""
    global ALLOWED_COUNTRIES, ALLOWED_ASNS
    file_path = path or ALLOWLIST_FILE
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
    except Exception:
        return
    countries = data.get("countries")
    if isinstance(countries, list):
        ALLOWED_COUNTRIES = {str(c).upper() for c in countries}
    asns = data.get("asns")
    if isinstance(asns, list):
        tmp = set()
        for a in asns:
            try:
                tmp.add(int(a))
            except Exception:
                continue
        ALLOWED_ASNS = tmp

load_allow_lists()


def geo_lookup(ip: str) -> str | None:
    """Return two-letter country code using the loaded CSV; None if not found."""
    if not GEO_DATA:
        return None
    ip_int = int(ipaddress.ip_address(ip))
    idx = bisect.bisect_left(GEO_DATA, (ip_int, 0, ""))
    if idx < len(GEO_DATA):
        start, end, cc = GEO_DATA[idx]
        if start <= ip_int <= end:
            return cc
    if idx > 0:
        start, end, cc = GEO_DATA[idx - 1]
        if start <= ip_int <= end:
            return cc
    return None


def record_attempt(ip: str, success: bool) -> None:
    """Increment ERR_STATS and prune entries older than 60 min."""
    now = time.time()
    data = ERR_STATS[ip]
    if now - data["ts"] > 3600:
        data["tries"] = 0
        data["fails"] = 0
        data["ts"] = now
    data["tries"] += 1
    if not success:
        data["fails"] += 1
    for key in list(ERR_STATS.keys()):
        if now - ERR_STATS[key]["ts"] > 3600:
            del ERR_STATS[key]


def calc_err_rate(ip: str) -> float:
    """Return fails / tries over last hour; optimistic if tries < 20."""
    data = ERR_STATS.get(ip)
    if not data or data["tries"] < 20:
        return 0.0
    return data["fails"] / data["tries"]


async def measure_latency(ip: str, port: int, proto: str) -> float | None:
    """Return milliseconds from connect start to TLS handshake complete."""
    key = f"{ip}:{port}"
    now = time.monotonic()
    cached = _latency_cache.get(key)
    if cached and now - cached[1] < LATENCY_CACHE_TTL:
        return cached[0]

    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        start = time.perf_counter()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx),
            timeout=1,
        )
        latency_ms = (time.perf_counter() - start) * 1000.0
        writer.close()
        await writer.wait_closed()
        record_attempt(ip, True)
        _latency_cache[key] = (latency_ms, now)
        STATS["tls_success"] += 1
        return latency_ms
    except Exception:
        record_attempt(ip, False)
        _latency_cache[key] = (None, now)
        STATS["tls_fail"] += 1
        return None


def _ip_rep_factor(ip: ipaddress._BaseAddress) -> float:
    ip_int = int(ip)
    for plen in PREFIX_LENGTHS:
        prefix = ip_int >> (32 - plen)
        if prefix in _hard_prefixes[plen]:
            return 0.0
    for plen in PREFIX_LENGTHS:
        prefix = ip_int >> (32 - plen)
        if prefix in _soft_prefixes[plen]:
            return 0.5
    return 1.0


async def _tls_factor(ip: str, port: int, ctx: ssl.SSLContext) -> float:
    key = f"{ip}:{port}"
    now = time.monotonic()
    cached = tls_cache.get(key)
    if cached and now - cached[1] < TLS_CACHE_TTL:
        return cached[0]

    async with tls_semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=1,
            )
            writer.close()
            await writer.wait_closed()
        except Exception:
            tls_cache[key] = (0.0, now)
            _latency_cache[key] = (None, now)
            record_attempt(ip, False)
            STATS["tls_fail"] += 1
            return 0.0

        try:
            start = time.perf_counter()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx),
                timeout=1,
            )
            latency_ms = (time.perf_counter() - start) * 1000.0
            cipher = writer.get_extra_info("cipher")
            writer.close()
            await writer.wait_closed()
            _latency_cache[key] = (latency_ms, now)
            record_attempt(ip, True)
            STATS["tls_success"] += 1
            if cipher and cipher[0] != "NULL":
                val = 1.0
            else:
                val = 0.5
        except Exception:
            _latency_cache[key] = (None, now)
            record_attempt(ip, False)
            STATS["tls_fail"] += 1
            val = 0.5

    tls_cache[key] = (val, now)
    return val


async def get_ja3(proxy: str) -> str | None:
    """Perform a TLS ClientHello via the proxy and return its JA3 string."""
    now = time.monotonic()
    cached = _ja3_cache.get(proxy)
    if cached and now - cached[1] < JA3_CACHE_TTL:
        return cached[0]

    proto, ip, port = proxy.split(":")
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ja3: str | None = None
    async with tls_semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, int(port), ssl=ctx),
                timeout=1,
            )
            writer.close()
            await writer.wait_closed()
            # Python's default handshake JA3
            ja3 = "771,49195-49199-49196-49172-57-56-61-60-53-47,0-11-10-35-23-13,23-24,0"
        except Exception:
            ja3 = None

    _ja3_cache[proxy] = (ja3, now)
    return ja3


def classify_asn(asn: int) -> str:
    """Return 'res', 'mob', 'mixed', or 'cloud' using ASN_TYPE / CLOUD_ASNS."""
    if asn in CLOUD_ASNS:
        return "cloud"
    typ = ASN_TYPE.get(asn, "").lower()
    if typ.startswith("res"):
        return "res"
    if typ.startswith("mob"):
        return "mob"
    if typ.startswith("mixed") or typ.startswith("unknown"):
        return "mixed"
    if typ.startswith("grey"):
        return "grey"
    return "mixed"


def update_ip_history(ip: str, success: bool) -> tuple[int, int]:
    """Update HISTORY for the IP and return (age_hours, fail_count)."""
    now = time.time()
    first, fails = HISTORY.get(ip, (now, 0))
    if now - first > 24 * 3600:
        first, fails = now, 0
    age_hours = int((now - first) / 3600)
    if not success:
        fails += 1
    HISTORY[ip] = (first, fails)
    return age_hours, fails


def update_freshness(proxy_id: str, success: bool) -> float:
    """Update EWMA freshness value for the proxy and return it."""
    now = time.time()
    val, ts = FRESH_HISTORY.get(proxy_id, (1.0, now))
    decay = math.exp(-(now - ts) / FRESH_HALF_LIFE)
    val = val * decay + (1.0 if success else 0.0) * (1 - decay)
    FRESH_HISTORY[proxy_id] = (val, now)
    return val


def get_freshness(proxy_id: str) -> float:
    now = time.time()
    val, ts = FRESH_HISTORY.get(proxy_id, (1.0, now))
    decay = math.exp(-(now - ts) / FRESH_HALF_LIFE)
    return val * decay + (1.0 * (1 - decay))



@lru_cache(maxsize=100000)
def normalize_proxy(entry: str) -> str | None:
    """Return proxy as proto:ip:port if valid, else None."""
    entry = entry.strip()
    if not entry:
        return None
    if "://" in entry:
        proto, rest = entry.split("://", 1)
    elif ";" in entry:
        proto, ip, port = entry.split(";", 2)
        rest = f"{ip}:{port}"
    else:
        parts = entry.split(":")
        if len(parts) == 2:
            proto, rest = "http", entry
        elif len(parts) == 3:
            proto, rest = parts[0], f"{parts[1]}:{parts[2]}"
        else:
            return None

    proto = proto.lower()
    ip_port = rest.split(":")
    if len(ip_port) != 2:
        return None
    ip, port_str = ip_port
    if not port_str.isdigit():
        return None
    port = int(port_str)
    if not (1 <= port <= 65535):
        return None
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None
    if not PROTOCOL_RE.match(proto):
        proto = "other"
    return f"{proto}:{ip}:{port}"


TEST_PROXIES = os.getenv("TEST_PROXIES", "0") == "1"
TEST_URLS = os.getenv("TEST_URLS")
if TEST_URLS:
    TEST_URLS = [u.strip() for u in TEST_URLS.split(",") if u.strip()]
else:
    TEST_URLS = [
        "http://example.com",
        "https://httpbin.org/get",
        "http://neverssl.com",
    ]
_test_url_cycle = itertools.cycle(TEST_URLS)
TEST_URL = TEST_URLS[0]
POOL_LIMIT = int(os.getenv("POOL_LIMIT", str(min(200, (os.cpu_count() or 1) * 40))))
MIN_POOL_LIMIT = 5
MAX_POOL_LIMIT = int(os.getenv("MAX_POOL_LIMIT", str((os.cpu_count() or 1) * 20)))
CHECK_CONNECT_TIMEOUT = float(os.getenv("CHECK_CONNECT_TIMEOUT", "3"))
CHECK_READ_TIMEOUT = float(os.getenv("CHECK_READ_TIMEOUT", "3"))
PROXY_CACHE_TTL = int(os.getenv("PROXY_CACHE_TTL", "300"))
KNOWN_GOOD_TTL = int(os.getenv("KNOWN_GOOD_TTL", "3600"))
CHECK_CHUNK_SIZE = int(os.getenv("CHECK_CHUNK_SIZE", "200"))
MAX_RETRIES = int(os.getenv("CHECK_MAX_RETRIES", "2"))

# Ports to test via HTTP CONNECT against Libero Mail services
LIBERO_PORTS = [443, 993, 995, 143, 110]
# hostname used for CONNECT requests
LIBERO_HOST = "libero.it"
# per-proxy connect timeout
CONNECT_TIMEOUT = float(os.getenv("LIBERO_TIMEOUT", "5"))


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/115.0",
]

proxy_check_time: dict[str, float] = {}
proxy_latency: dict[str, float] = {}
PROXY_ID_MAP: dict[str, str] = {}

# --- scraping statistics ---------------------------------------------------
from collections import defaultdict
from statistics import mean, median

STATS: dict[str, Any] = {
    "total_scraped": 0,
    "source_counts": defaultdict(int),
    "protocol_counts": defaultdict(int),
    "quick_validate_pass": 0,
    "quick_validate_fail": 0,
    "filter_p1_pass": 0,
    "filter_p1_fail": 0,
    "filter_p2_pass": 0,
    "filter_p2_fail": 0,
    "http_connect_pass": 0,
    "http_connect_fail": 0,
    "score_samples": [],
    "tls_success": 0,
    "tls_fail": 0,
    "written_per_proto": defaultdict(int),
    "flushes": 0,
    "peak_concurrency": 0,
    "dht_proxies": 0,
    "irc_proxies": 0,
    "paste_proxies": 0,
    "api_counts": defaultdict(int),
    # counts of proxies able to CONNECT to each Libero Mail port
    "port_443": 0,
    "port_993": 0,
    "port_995": 0,
    "port_143": 0,
    "port_110": 0,
}

# track which ports succeeded for each proxy (http/https only)
PROXY_PORT_SUCCESS: dict[str, set[int]] = {}


def _merge_stats(src: dict[str, Any]) -> None:
    """Merge ``src`` counters into ``STATS``."""
    for key, value in src.items():
        if key not in STATS:
            STATS[key] = value
            continue
        cur = STATS[key]
        if isinstance(cur, defaultdict):
            for sk, sv in value.items():
                cur[sk] += sv
        elif isinstance(cur, list):
            cur.extend(value)
        elif isinstance(cur, (int, float)):
            STATS[key] = cur + value


def load_previous_stats(path: str = "stats.json") -> None:
    """Load existing stats file and merge into ``STATS``."""
    if not os.path.exists(path):
        return
    try:
        with open(path) as f:
            prev = json.load(f)
        if isinstance(prev, dict):
            _merge_stats(prev)
    except Exception as exc:  # pragma: no cover - diagnostics only
        logging.error("stats load error: %s", exc)


load_previous_stats()


def _stats_snapshot() -> dict[str, Any]:
    """Return a snapshot of the current statistics."""
    snap = dict(STATS)
    snap["deduped"] = len(proxy_set)
    total_qv = snap["quick_validate_pass"] + snap["quick_validate_fail"]
    snap["quick_validate_rate"] = (
        snap["quick_validate_pass"] / total_qv if total_qv else 0.0
    )
    total_http = snap.get("http_connect_pass", 0) + snap.get("http_connect_fail", 0)
    snap["http_connect_rate"] = (
        snap.get("http_connect_pass", 0) / total_http if total_http else 0.0
    )
    if STATS["score_samples"]:
        snap["score_min"] = min(STATS["score_samples"])
        snap["score_median"] = median(STATS["score_samples"])
        snap["score_mean"] = mean(STATS["score_samples"])
        snap["score_max"] = max(STATS["score_samples"])
    else:
        snap["score_min"] = snap["score_median"] = 0.0
        snap["score_mean"] = snap["score_max"] = 0.0
    return snap


async def stats_loop() -> None:
    """Periodically write statistics to ``stats.json``."""
    while True:
        await asyncio.sleep(1)
        try:
            with open("stats.json", "w") as f:
                json.dump(_stats_snapshot(), f)
        except Exception as exc:  # pragma: no cover - diagnostics only
            logging.error("stats write error: %s", exc)


def adjust_pool_limit(success_rate: float) -> None:
    """Adjust concurrency based on success rate."""
    global POOL_LIMIT
    if success_rate < 0.3 and POOL_LIMIT > MIN_POOL_LIMIT:
        POOL_LIMIT = max(MIN_POOL_LIMIT, int(POOL_LIMIT * 0.8))
    elif success_rate > 0.7 and POOL_LIMIT < MAX_POOL_LIMIT:
        POOL_LIMIT = min(MAX_POOL_LIMIT, POOL_LIMIT + 5)
    if aiohttp_session is not None:
        # ``aiohttp`` exposes ``connector.limit`` as a read-only property, so we
        # update the underlying attribute directly.  This avoids ``AttributeError``
        # when adjusting the pool size at runtime.
        if hasattr(aiohttp_session.connector, "_limit"):
            aiohttp_session.connector._limit = POOL_LIMIT
    STATS["peak_concurrency"] = max(STATS.get("peak_concurrency", 0), POOL_LIMIT)


async def filter_working(proxies: list[str]) -> list[str]:
    """Return only proxies that successfully perform a simple request."""
    if not TEST_PROXIES:
        return proxies

    results: list[str] = []
    for i in range(0, len(proxies), CHECK_CHUNK_SIZE):
        chunk = proxies[i : i + CHECK_CHUNK_SIZE]
        results.extend(await _filter_chunk(chunk))
    return results


async def _filter_p1_batch(proxies: list[str], service: str = "pop3") -> list[str]:
    """Run ``filter_p1`` on a list of proxies asynchronously."""

    proxies = [
        p
        for p in proxies
        if p.split(":", 1)[0].lower() in {"socks4", "socks5"}
    ]
    if not proxies:
        return []

    sem = asyncio.Semaphore(POOL_LIMIT)

    def to_url(p: str) -> str:
        proto, ip, port = p.split(":")
        return f"{proto}://{ip}:{port}"

    async def check(p: str) -> str | None:
        loop = asyncio.get_running_loop()
        async with sem:
            ok = await loop.run_in_executor(
                SHARED_THREAD_POOL, filter_p1, to_url(p), service
            )
            return p if ok else None

    tasks = [asyncio.create_task(check(p)) for p in proxies]
    gathered = await asyncio.gather(*tasks, return_exceptions=True)
    results: list[str] = []
    successes = 0
    for res in gathered:
        if isinstance(res, Exception):
            continue
        if res:
            successes += 1
            results.append(res)
    STATS["filter_p1_pass"] += successes
    STATS["filter_p1_fail"] += len(proxies) - successes
    return results


async def _filter_chunk(proxies: list[str]) -> list[str]:
    session = await get_aiohttp_session()
    sem = asyncio.Semaphore(POOL_LIMIT)
    timeout = aiohttp.ClientTimeout(
        connect=CHECK_CONNECT_TIMEOUT,
        sock_read=CHECK_READ_TIMEOUT,
    )

    async def socks_handshake(ip: str, port: int, proto: str) -> bool:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=CHECK_CONNECT_TIMEOUT
            )
            if proto == "socks5":
                writer.write(b"\x05\x01\x00")
                await writer.drain()
                resp = await asyncio.wait_for(reader.readexactly(2), timeout=1)
                if resp != b"\x05\x00":
                    writer.close()
                    await writer.wait_closed()
                    return False
                req = b"\x05\x01\x00\x03\x0bexample.com\x00\x50"
                writer.write(req)
                await writer.drain()
                resp = await asyncio.wait_for(reader.readexactly(10), timeout=1)
                writer.close()
                await writer.wait_closed()
                return resp[1] == 0x00
            else:  # socks4
                req = b"\x04\x01\x00\x50\x00\x00\x00\x01\x00"
                writer.write(req)
                await writer.drain()
                resp = await asyncio.wait_for(reader.readexactly(8), timeout=1)
                writer.close()
                await writer.wait_closed()
                return resp[1] == 0x5A
        except Exception:
            return False

    async def check(p: str) -> str | None:
        proto, ip, port = p.split(":")
        ttl = KNOWN_GOOD_TTL if p in proxy_latency else PROXY_CACHE_TTL
        if p in proxy_check_time and time.monotonic() - proxy_check_time[p] < ttl:
            return p

        success = False
        for attempt in range(MAX_RETRIES + 1):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, int(port)),
                    timeout=CHECK_CONNECT_TIMEOUT,
                )
                writer.close()
                await writer.wait_closed()
            except Exception:
                if attempt >= MAX_RETRIES:
                    break
                await asyncio.sleep(2 ** attempt)
                continue

            start = time.perf_counter()
            try:
                async with sem:
                    if proto.startswith("socks"):
                        if not await socks_handshake(ip, int(port), proto):
                            raise RuntimeError("socks handshake failed")
                    else:
                        proxy_url = f"{proto}://{ip}:{port}"
                        headers = {"User-Agent": random.choice(USER_AGENTS)}
                        async with session.head(
                            next(_test_url_cycle),
                            proxy=proxy_url,
                            timeout=timeout,
                            headers=headers,
                        ):
                            pass
                latency = time.perf_counter() - start
                proxy_latency[p] = latency
                proxy_check_time[p] = time.monotonic()
                success = True
                break
            except Exception:
                if attempt >= MAX_RETRIES:
                    break
                await asyncio.sleep(2 ** attempt)
        record_attempt(ip, success)
        return p if success else None

    tasks = [asyncio.create_task(check(p)) for p in proxies]
    gathered = await asyncio.gather(*tasks, return_exceptions=True)
    results: list[str] = []
    successes = 0
    for res in gathered:
        if isinstance(res, Exception):
            continue
        if res:
            successes += 1
            results.append(res)

    success_rate = successes / len(proxies) if proxies else 0
    adjust_pool_limit(success_rate)
    return results


async def check_proxy(proxy_url: str) -> bool:
    """Test proxy via HTTP CONNECT to Libero Mail ports."""
    from urllib.parse import urlparse

    try:
        parsed = urlparse(proxy_url)
        scheme = (parsed.scheme or "http").lower()
        host = parsed.hostname
        port = parsed.port or (443 if scheme == "https" else 80)
        if not host or not port:
            return False
        ssl_ctx = ssl.create_default_context() if scheme == "https" else None
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_ctx), timeout=CONNECT_TIMEOUT
        )
    except Exception:
        return False

    success_ports: set[int] = set()
    try:
        for target_port in LIBERO_PORTS:
            req = (
                f"CONNECT {LIBERO_HOST}:{target_port} HTTP/1.1\r\n"
                f"Host: {LIBERO_HOST}:{target_port}\r\n\r\n"
            )
            try:
                writer.write(req.encode())
                await writer.drain()
                resp = await asyncio.wait_for(reader.read(1024), timeout=CONNECT_TIMEOUT)
            except Exception:
                return False
            if b"200" in resp:
                success_ports.add(target_port)
                STATS[f"port_{target_port}"] += 1
                PROXY_PORT_SUCCESS[proxy_url] = success_ports
                return True
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    return False


async def filter_libero_ports(proxies: list[str]) -> tuple[list[str], dict[str, set[int]]]:
    """Run ``check_proxy`` on HTTP/HTTPS proxies and return passing ones."""

    sem = asyncio.Semaphore(POOL_LIMIT)

    async def check(p: str) -> tuple[str, set[int]] | None:
        proto, host, port = p.split(":")
        if proto not in {"http", "https"}:
            return p, set()
        url = f"{proto}://{host}:{port}"
        async with sem:
            ok = await check_proxy(url)
        if ok:
            ports = PROXY_PORT_SUCCESS.get(url, set())
            return p, ports
        return None

    tasks = [asyncio.create_task(check(p)) for p in proxies]
    gathered = await asyncio.gather(*tasks, return_exceptions=True)
    keep: list[str] = []
    port_map: dict[str, set[int]] = {}
    for res in gathered:
        if isinstance(res, Exception) or res is None:
            continue
        p, ports = res
        keep.append(p)
        if ports:
            port_map[p] = ports
    return keep, port_map


async def quick_validate(proxies: list[str]) -> list[str]:
    """Check that proxy ports are reachable."""
    sem = asyncio.Semaphore(POOL_LIMIT)

    async def resolve(host: str) -> str | None:
        if host.replace(".", "").isdigit():
            return host
        now = time.monotonic()
        cached = DNS_CACHE.get(host)
        if cached and now - cached[1] < DNS_CACHE_TTL:
            return cached[0]
        try:
            resp = await DNS_RESOLVER.gethostbyname(host, socket.AF_INET)
            ip = resp.addresses[0]
            DNS_CACHE[host] = (ip, now)
            return ip
        except Exception:
            return None

    async def check(p: str) -> str | None:
        try:
            _, host, port = p.split(":")
            ip = await resolve(host)
            if not ip:
                return None
            async with sem:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, int(port)),
                    timeout=1,
                )
                writer.close()
                await writer.wait_closed()
            record_attempt(ip, True)
            return p
        except Exception:
            err_key = ip if 'ip' in locals() and ip else host
            record_attempt(err_key, False)
            return None

    tasks = [asyncio.create_task(check(p)) for p in proxies]
    gathered = await asyncio.gather(*tasks, return_exceptions=True)
    results: list[str] = []
    successes = 0
    for res in gathered:
        if isinstance(res, Exception):
            continue
        if res:
            successes += 1
            results.append(res)
    success_rate = successes / len(proxies) if proxies else 0
    STATS["quick_validate_pass"] += successes
    STATS["quick_validate_fail"] += len(proxies) - successes
    adjust_pool_limit(success_rate)
    return results


def _output_path(proto: str) -> str:
    base = f"{proto}_" + os.path.basename(OUTPUT_FILE)
    return os.path.join(OUTPUT_DIR, base)


async def write_entries(entries: list[str]) -> None:
    proto_groups: dict[str, list[str]] = {}
    for p in entries:
        proto = p.split(":", 1)[0]
        proto_groups.setdefault(proto, []).append(p)

    for proto, items in proto_groups.items():
        path = _output_path(proto)
        mode = "at" if OUTPUT_COMPRESSED else "a"
        if OUTPUT_COMPRESSED:
            await asyncio.to_thread(_write_gzip, path, items, mode)
            STATS["written_per_proto"][proto] += len(items)
            continue

        f = _open_files.get(path)
        if f is None:
            f = await aiofiles.open(path, mode)
            _open_files[path] = f

        buf: list[str] = []
        size = 0
        for line in items:
            line = line + "\n"
            buf.append(line)
            size += len(line)
            if size >= 65536:
                await f.writelines(buf)
                await f.flush()
                buf = []
                size = 0
        if buf:
            await f.writelines(buf)
            await f.flush()
        STATS["written_per_proto"][proto] += len(items)


async def write_libero_entries(port_map: dict[str, set[int]], score_map: dict[str, int]) -> None:
    """Write proxy URLs to additional files based on Libero port support."""

    groups = {
        "port443_proxies.txt": {443},
        "imap_proxies.txt": {993, 143},
        "pop3_proxies.txt": {995, 110},
    }

    file_lines: dict[str, list[str]] = {name: [] for name in groups}
    for proxy, ports in port_map.items():
        line = f"{proxy};score={score_map[proxy]}"
        for name, portset in groups.items():
            if ports & portset:
                file_lines[name].append(line)

    for name, lines in file_lines.items():
        if not lines:
            continue
        path = os.path.join(OUTPUT_DIR, name)
        mode = "at" if OUTPUT_COMPRESSED else "a"
        if OUTPUT_COMPRESSED:
            await asyncio.to_thread(_write_gzip, path, lines, mode)
        else:
            async with aiofiles.open(path, mode) as f:
                await f.writelines([l + "\n" for l in lines])


def _write_gzip(path: str, items: list[str], mode: str) -> None:
    """Write items to a gzipped file using binary mode."""
    mode_bin = mode.replace("t", "") + "b"
    with gzip.open(path, mode_bin) as f:
        buf: list[str] = []
        size = 0
        for line in items:
            line = line + "\n"
            buf.append(line)
            size += len(line)
            if size >= 65536:
                f.write("".join(buf).encode())
                buf = []
                size = 0
        if buf:
            f.write("".join(buf).encode())


async def check_http_connect(proxy: str, host: str = "example.com", port: int = 443) -> bool:
    """Return True if an HTTP proxy supports the CONNECT method."""
    proto, ip, p = proxy.split(":")
    if proto not in {"http", "https"}:
        return False
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, int(p)), timeout=CONNECT_TIMEOUT
        )
    except Exception:
        return False
    try:
        req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
        writer.write(req.encode())
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(1024), timeout=CONNECT_TIMEOUT)
        return b"200" in resp
    except Exception:
        return False
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def filter_http_connect(proxies: list[str]) -> list[str]:
    """Filter HTTP proxies that support CONNECT."""
    http_proxies = [p for p in proxies if p.split(":", 1)[0] in {"http", "https"}]
    if not http_proxies:
        return []
    sem = asyncio.Semaphore(POOL_LIMIT)

    async def check(p: str) -> str | None:
        async with sem:
            ok = await check_http_connect(p)
        return p if ok else None

    tasks = [asyncio.create_task(check(p)) for p in http_proxies]
    gathered = await asyncio.gather(*tasks, return_exceptions=True)
    keep: list[str] = []
    successes = 0
    for res in gathered:
        if isinstance(res, Exception):
            continue
        if res:
            successes += 1
            keep.append(res)
    STATS["http_connect_pass"] += successes
    STATS["http_connect_fail"] += len(http_proxies) - successes
    return keep


async def write_http_connect_entries(entries: list[str]) -> None:
    """Append CONNECT-capable proxies to ``http_connect_method.txt``."""
    if not entries:
        return
    path = os.path.join(OUTPUT_DIR, "http_connect_method.txt")
    mode = "at" if OUTPUT_COMPRESSED else "a"
    if OUTPUT_COMPRESSED:
        await asyncio.to_thread(_write_gzip, path, entries, mode)
        return
    f = _open_files.get(path)
    if f is None:
        f = await aiofiles.open(path, mode)
        _open_files[path] = f

    buf: list[str] = []
    size = 0
    for line in entries:
        line = line + "\n"
        buf.append(line)
        size += len(line)
        if size >= 65536:
            await f.writelines(buf)
            await f.flush()
            buf = []
            size = 0
    if buf:
        await f.writelines(buf)
        await f.flush()


def filter_p1(proxy_url: str, service_name: str) -> bool:
    """Validate TCP and TLS connectivity for a service via optional proxy.

    Parameters
    ----------
    proxy_url: str
        Proxy URL like ``socks5://user:pass@1.2.3.4:1080`` or ``"none"`` for
        direct connection.
    service_name: str
        Currently only ``"pop3"`` is supported.

    Returns
    -------
    bool
        ``True`` on successful TCP and TLS handshake, ``False`` otherwise.
    """

    if service_name.lower() != "pop3":
        print(f"Unsupported service: {service_name}")
        return False

    host, port = "pop.libero.it", 995

    retries = 2
    backoff = [0.5, 1.0]
    for attempt in range(retries + 1):
        original_socket = socket.socket
        if proxy_url.lower() != "none":
            from urllib.parse import urlparse
            import socks

            parsed = urlparse(proxy_url)
            scheme = (parsed.scheme or "socks5").lower()
            proxy_host = parsed.hostname
            proxy_port = parsed.port
            username = parsed.username
            password = parsed.password

            if not proxy_host or not proxy_port:
                socket.socket = original_socket
                return False

            if scheme.startswith("socks5"):
                proxy_type = socks.SOCKS5
            elif scheme.startswith("socks4"):
                proxy_type = socks.SOCKS4
            elif scheme in ("http", "https"):
                proxy_type = socks.HTTP
            else:
                socket.socket = original_socket
                return False

            socks.set_default_proxy(
                proxy_type, proxy_host, proxy_port, username=username, password=password
            )
            socket.socket = socks.socksocket

        try:
            sock = socket.create_connection((host, port), timeout=10)
            ctx = ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            tls_sock = ctx.wrap_socket(sock, server_hostname=host)
            banner = tls_sock.recv(256).split(b"\n")[0].decode(errors="ignore").strip()
            tls_version = tls_sock.version()
            cipher = tls_sock.cipher()[0]
            logging.info(
                "filter_p1 TLS via %s: %s %s sni=%s",
                proxy_url,
                tls_version,
                cipher,
                host,
            )
            if not banner.startswith("+OK"):
                tls_sock.close()
                socket.socket = original_socket
                return False
            start = time.perf_counter()
            tls_sock.sendall(b"STAT\r\n")
            resp = tls_sock.recv(256)
            rtt = time.perf_counter() - start
            line = resp.split(b"\n")[0]
            tls_sock.close()
            socket.socket = original_socket
            if rtt > 2.0 or not line.startswith(b"+OK"):
                return False
            return True
        except (socket.gaierror, socket.timeout, TimeoutError):
            socket.socket = original_socket
            if attempt < retries:
                time.sleep(backoff[attempt])
                continue
            return False
        except Exception:
            socket.socket = original_socket
            return False

    return False


async def _score_single_proxy(
    p: str, ctx: ssl.SSLContext, return_all: bool = False
) -> tuple[str, int, dict[str, int]] | None:
    if cy_score_single_proxy is not None:
        result = cy_score_single_proxy(p)
        if not result:
            return None
        norm, total = result[0], result[1]
        extra = result[2] if len(result) > 2 else {}
        STATS["score_samples"].append(total)
        return norm, total, extra
    norm = normalize_proxy(p)
    if not norm:
        return None
    proto, ip, port = norm.split(":")
    proxy_id = PROXY_ID_MAP.get(norm, p)
    ip_obj = ipaddress.ip_address(ip)

    ip_factor = _ip_rep_factor(ip_obj)
    if ip_factor == 0.0:
        update_freshness(proxy_id, False)
        return None

    if proto not in ("socks4", "socks5", "https"):
        update_freshness(proxy_id, False)
        return None

    tls_factor = await _tls_factor(ip, int(port), ctx)
    if tls_factor == 0.0:
        update_freshness(proxy_id, False)
        return None

    ip_points = int(ip_factor * WEIGHTS["ip_rep"])
    tls_points = int(tls_factor * WEIGHTS["tls_reach"])
    critical_score = ip_points + tls_points
    total_score = critical_score

    passed = total_score >= OVERALL_MIN and critical_score >= CRITICAL_MIN
    update_freshness(proxy_id, passed)
    if not passed and not return_all:
        return None

    if passed:
        STATS["score_samples"].append(total_score)

    scores = {
        "ip": ip_points,
        "tls": tls_points,
        "critical": critical_score,
    }
    return norm, total_score, scores


async def filter_p2(
    proxies: list[str],
) -> tuple[list[tuple[str, int]], list[tuple[str, int]]]:
    """Score proxies with multiple heuristics.

    Returns a tuple ``(accepted, quarantine)``. In strict mode the
    ``quarantine`` list will always be empty.
    """

    proxies = [
        p
        for p in proxies
        if p.split(":", 1)[0].lower() in {"socks4", "socks5"}
    ]
    if not proxies:
        return [], []

    await load_blacklists()
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    async def score(p: str) -> tuple[str, int, dict[str, int]]:
        res = await _score_single_proxy(p, ctx, return_all=True)
        assert res is not None
        return res

    tasks = [asyncio.create_task(score(p)) for p in proxies]
    scored: list[tuple[str, int, dict[str, int]]] = []
    for t in asyncio.as_completed(tasks):
        try:
            res = await t
            if res:
                scored.append(res)
        except Exception:
            continue
    accepted: list[tuple[str, int]] = []
    quarantine: list[tuple[str, int]] = []
    for norm, score, parts in scored:
        crit = parts.get("critical", 0)
        if score >= OVERALL_MIN and crit >= CRITICAL_MIN:
            accepted.append((norm, score))
        elif MODE == "lenient" and 500 <= score < 600:
            quarantine.append((norm, score))

    STATS["filter_p2_pass"] += len(accepted)
    STATS["filter_p2_fail"] += len(proxies) - len(accepted)

    return accepted, quarantine



async def get_aiohttp_session() -> Any:
    global aiohttp_session, httpx_client
    if USE_HTTP2:
        if httpx_client is None:
            try:
                import httpx
            except Exception as exc:
                logging.warning("httpx not available for HTTP/2: %s", exc)
            else:
                httpx_client = httpx.AsyncClient(http2=True)
        if httpx_client:
            return httpx_client
    if aiohttp_session is None:
        connector = aiohttp.TCPConnector(limit=POOL_LIMIT, ttl_dns_cache=60)
        default_timeout = aiohttp.ClientTimeout(
            connect=CHECK_CONNECT_TIMEOUT, sock_read=CHECK_READ_TIMEOUT
        )
        aiohttp_session = aiohttp.ClientSession(
            connector=connector, timeout=default_timeout
        )
    return aiohttp_session


async def add_proxies(proxies: List[str], source: str = "unknown") -> None:
    async with proxy_lock:
        added = False
        for raw in proxies:
            p = normalize_proxy(raw)
            if not p or p in proxy_set:
                continue
            PROXY_ID_MAP[p] = raw.strip()
            proxy_set.add(p)
            proto = p.split(":", 1)[0]
            STATS["total_scraped"] += 1
            STATS["source_counts"][source] += 1
            STATS["protocol_counts"][proto] += 1
            new_entries.put_nowait(p)
            added = True
        if added:
            write_event.set()


def add_proxies_sync(proxies: List[str], source: str = "unknown") -> None:
    added = False
    with lock:
        for raw in proxies:
            p = normalize_proxy(raw)
            if not p or p in proxy_set:
                continue
            PROXY_ID_MAP[p] = raw.strip()
            proxy_set.add(p)
            proto = p.split(":", 1)[0]
            STATS["total_scraped"] += 1
            STATS["source_counts"][source] += 1
            STATS["protocol_counts"][proto] += 1
            if MAIN_LOOP:
                MAIN_LOOP.call_soon_threadsafe(new_entries.put_nowait, p)
            else:
                new_entries.put_nowait(p)
            added = True
    if added:
        write_event.set()


async def writer_loop() -> None:
    global proxy_set
    while True:
        await write_event.wait()
        write_event.clear()
        entries: list[str] = []
        while True:
            try:
                entries.append(new_entries.get_nowait())
            except asyncio.QueueEmpty:
                break
        if not entries:
            continue
        entries = await quick_validate(entries)
        http_entries = [p for p in entries if p.split(":", 1)[0] in {"http", "https"}]
        other_entries = [p for p in entries if p.split(":", 1)[0] not in {"http", "https"}]

        if http_entries:
            ok_http = await filter_http_connect(http_entries)
            await write_http_connect_entries(ok_http)

        entries = other_entries
        if not entries:
            continue

        entries = await _filter_p1_batch(entries)
        good, _ = await filter_p2(entries)
        score_map = {p: s for p, s in good}
        entries = await filter_working(list(score_map.keys()))
        entries, port_map = await filter_libero_ports(entries)
        to_save = [f"{p};score={score_map[p]}" for p in entries]
        await write_entries(to_save)
        await write_libero_entries(port_map, score_map)
        if len(proxy_set) > MAX_PROXY_SET_SIZE:
            logging.info("Flushing proxy set to limit memory usage")
            STATS["flushes"] += 1
            proxy_set = ScalableBloomFilter(mode=ScalableBloomFilter.SMALL_SET_GROWTH)


def _load_all_saved_proxies() -> list[str]:
    """Return all proxies from the output file (if present)."""
    path = os.path.join(OUTPUT_DIR, OUTPUT_FILE)
    proxies: list[str] = []
    if os.path.exists(path):
        opener = gzip.open if OUTPUT_COMPRESSED else open
        mode = "rt"
        with opener(path, mode) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                line = line.split(";", 1)[0]
                if normalize_proxy(line):
                    proxies.append(line)
    return proxies


async def run_filter_p1_all(service: str = "pop3") -> None:
    """Run filter_p1 over all known proxies and print passing ones."""
    proxies = _load_all_saved_proxies()
    while True:
        try:
            proxies.append(new_entries.get_nowait())
        except asyncio.QueueEmpty:
            break
    proxies = await quick_validate(proxies)
    results = await _filter_p1_batch(proxies, service)
    for p in results:
        print(p)


async def run_filter_p2_all() -> None:
    """Run filter_p2 over all known proxies and print scored ones."""
    proxies = _load_all_saved_proxies()
    while True:
        try:
            proxies.append(new_entries.get_nowait())
        except asyncio.QueueEmpty:
            break
    good, quarantine = await filter_p2(proxies)
    for p, score in good:
        print(f"{p};score={score}")
    if quarantine:
        print("# quarantine")
        for p, score in quarantine:
            print(f"{p};score={score}")


async def fetch_json(url: str) -> dict:
    """Fetch JSON from ``url`` using the configured HTTP client."""
    session = await get_aiohttp_session()
    if aiohttp is not None and isinstance(session, aiohttp.ClientSession):
        async with session.get(url, timeout=REQUEST_TIMEOUT) as resp:
            resp.raise_for_status()
            data = await resp.read()
    else:  # httpx client
        resp = await session.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = await resp.aread()
    return orjson.loads(data)


async def fetch_proxxy_sources() -> AsyncGenerator[List[str], None]:
    """Fetch all proxy sources defined by the proXXy project."""
    try:
        async with aiofiles.open(PROXXY_SOURCES_FILE, "r") as f:
            sources = json.loads(await f.read())
    except Exception as exc:
        logging.error("Error loading %s: %s", PROXXY_SOURCES_FILE, exc)
        return

    urls = []
    for url_list in sources.values():
        urls.extend(url_list)

    session = await get_aiohttp_session()
    tasks = {asyncio.create_task(session.get(url, timeout=REQUEST_TIMEOUT)): url for url in urls}
    batch: List[str] = []
    for task in asyncio.as_completed(tasks):
        url = tasks[task]
        try:
            resp = await task
            async for raw_line in resp.content:
                line = raw_line.decode(errors="ignore").strip()
                if IP_PORT_RE.match(line):
                    batch.append(line)
                    if len(batch) >= 1000:
                        yield batch
                        batch = []
        except Exception as e:
            logging.error("proXXy source error %s: %s", url, e)
    if batch:
        yield batch


async def scrape_mt_proxies() -> None:
    proxies = []
    try:
        mt_list = await fetch_json(MTPROTO_URL)
        for item in mt_list:
            host = item.get("host")
            port = item.get("port")
            if host and port:
                proxies.append(f"{host}:{port}")
    except Exception as e:
        logging.error("Error fetching mtproto proxies: %s", e)
    try:
        socks_list = await fetch_json(SOCKS_URL)
        for item in socks_list:
            ip = item.get("ip")
            port = item.get("port")
            if ip and port:
                proxies.append(f"{ip}:{port}")
    except Exception as e:
        logging.error("Error fetching socks proxies: %s", e)

    if proxies:
        await add_proxies(proxies, source="mtpro")


async def scrape_freeproxy_world() -> None:
    """Fetch all proxies listed on freeproxy.world."""
    base_url = "https://www.freeproxy.world/"
    proxies: list[str] = []
    try:
        text = await fetch_with_backoff(base_url)
        if not text:
            return
        soup = create_soup(text)
        count_div = soup.select_one(".proxy_table_pages")
        total = int(count_div.get("data-counts", "0")) if count_div else 0
        pages = max(1, (total + 49) // 50)
        for page in range(1, pages + 1):
            try:
                page_text = await fetch_with_backoff(base_url + f"?page={page}")
                if not page_text:
                    break
                soup = create_soup(page_text)
                for row in soup.select("tbody tr"):
                    cols = [td.get_text(strip=True) for td in row.find_all("td")]
                    if len(cols) >= 6 and cols[0] and cols[1].isdigit():
                        proto = cols[5].split()[0].lower()
                        proxies.append(f"{proto}:{cols[0]}:{cols[1]}")
            except Exception as e:
                logging.error("Error fetching freeproxy.world page %s: %s", page, e)
                break
    except Exception as e:
        logging.error("Error fetching freeproxy.world: %s", e)

    if proxies:
        await add_proxies(proxies, source="freeproxy_world")


def _parse_free_proxy_cz_page(soup: BeautifulSoup) -> list[str]:
    """Extract proxies from a free-proxy.cz page soup."""
    proxies: list[str] = []
    for row in soup.select("tbody tr"):
        script = row.find("script")
        if not script or not script.string:
            continue
        m = FREE_CZ_BASE64_RE.search(script.string)
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


async def scrape_free_proxy_cz() -> None:
    """Fetch proxies from http://free-proxy.cz/en/ across all pages."""
    base_url = "http://free-proxy.cz"
    proxies: list[str] = []
    pages = 1
    try:
        text = await fetch_with_backoff(f"{base_url}/en/")
        if not text:
            return
        soup = create_soup(text)
        proxies.extend(_parse_free_proxy_cz_page(soup))
        links = soup.select('a[href^="/en/proxylist/main/"]')
        for a in links:
            m = FREE_CZ_PAGE_RE.search(a.get("href", ""))
            if m:
                pages = max(pages, int(m.group(1)))
        for page in range(2, pages + 1):
            try:
                url = f"{base_url}/en/proxylist/main/{page}"
                page_text = await fetch_with_backoff(url)
                if not page_text:
                    break
                soup = create_soup(page_text)
                proxies.extend(_parse_free_proxy_cz_page(soup))
            except Exception as e:
                logging.error("Error fetching free-proxy.cz page %s: %s", page, e)
                break
    except Exception as e:
        logging.error("Error fetching free-proxy.cz: %s", e)

    if proxies:
        await add_proxies(proxies, source="free_proxy_cz")


async def fetch_with_backoff(url: str, max_retries: int = 5) -> str:
    delay = 1
    session = await get_aiohttp_session()
    for _ in range(max_retries):
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            if (
                USE_HTTP2
                and hasattr(session, "get")
                and (aiohttp is None or not isinstance(session, aiohttp.ClientSession))
            ):
                resp = await session.get(url, headers=headers)
                if resp.status == 429:
                    SOURCE_BACKOFF[url] = min(SOURCE_BACKOFF[url] + 1, 3)
                else:
                    SOURCE_BACKOFF[url] = max(SOURCE_BACKOFF[url] - 1, 0)
                resp.raise_for_status()
                return resp.text
            async with session.get(url, headers=headers, timeout=REQUEST_TIMEOUT) as resp:
                if resp.status == 429:
                    SOURCE_BACKOFF[url] = min(SOURCE_BACKOFF[url] + 1, 3)
                else:
                    SOURCE_BACKOFF[url] = max(SOURCE_BACKOFF[url] - 1, 0)
                if resp.status >= 400:
                    raise aiohttp.ClientResponseError(
                        resp.request_info, resp.history, status=resp.status
                    )
                return await resp.text()
        except Exception:
            sleep_time = delay + random.uniform(0, 1)
            await asyncio.sleep(sleep_time)
            delay = min(delay * 2, 60)
    return ""


def extract_proxies(text: str) -> list[str]:
    found = []
    for m in PROXY_RE.finditer(text, overlapped=True):
        ip = m.group(1)
        port = int(m.group(2))
        if not (1 <= port <= 65535):
            continue
        octets = ip.split(".")
        if any(not 0 <= int(o) <= 255 for o in octets):
            continue
        snippet = text[max(0, m.start() - 20) : m.end() + 20].lower()
        protocol = "socks5" if "socks5" in snippet else "http"
        found.append(f"{protocol}:{ip}:{port}")
    return found


async def monitor_paste_feeds() -> None:
    for feed in PASTE_FEEDS:
        text = await fetch_with_backoff(feed)
        if text:
            proxies = extract_proxies(text)
            STATS["paste_proxies"] += len(proxies)
            await add_proxies(proxies, source="paste")
        await asyncio.sleep(random.uniform(*FEED_DELAY_RANGE))


async def scrape_tor_relays() -> None:
    """Fetch relay descriptors from Onionoo and record their addresses."""
    try:
        data = await fetch_json(ONIONOO_URL)
    except Exception as e:
        logging.error("Error fetching Tor relays: %s", e)
        return

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
        await add_proxies(proxies, source="tor")


async def scrape_proxyscrape() -> None:
    urls = [
        (PROXYSCRAPE_HTTP_URL, "http"),
        (PROXYSCRAPE_SOCKS4_URL, "socks4"),
        (PROXYSCRAPE_SOCKS5_URL, "socks5"),
    ]
    proxies = []
    for url, proto in urls:
        try:
            text = await fetch_with_backoff(url)
            for line in text.splitlines():
                line = line.strip()
                if line:
                    proxies.append(f"{proto}:{line}")
        except Exception as e:
            logging.error("Error fetching %s: %s", url, e)
        await asyncio.sleep(SCRAPERS["proxyscrape"])
    if proxies:
        STATS["api_counts"]["proxyscrape"] += len(proxies)
        await add_proxies(proxies, source="proxyscrape")


def _ps_get(url: str) -> str:
    """Helper for ProxyScraper integration to fetch a URL with error logging."""
    try:
        resp = requests_session.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.text
    except Exception as exc:
        logging.error("ProxyScraper source error %s: %s", url, exc)
        return ""


async def scrape_proxyscraper_sources(interval: int = PS_INTERVAL) -> None:
    """Continuously fetch proxies from ProxyScraper sources."""
    urls = list(PS_SCRAPER_SOURCES)
    batch = PS_CONCURRENT_REQUESTS
    loop = asyncio.get_running_loop()
    while True:
        new_entries: list[str] = []
        for i in range(0, len(urls), batch):
            subset = urls[i : i + batch]
            texts = await asyncio.gather(*[loop.run_in_executor(None, _ps_get, u) for u in subset])
            for url, text in zip(subset, texts):
                proto_match = PROTO_PARAM_RE.search(url)
                proto = proto_match.group(1).lower() if proto_match else "http"
                for line in text.splitlines():
                    line = line.strip()
                    if IP_PORT_RE.match(line):
                        new_entries.append(f"{proto}:{line}")

        if new_entries:
            await add_proxies(new_entries, source="proxyscraper")

        await asyncio.sleep(interval)


async def download_proxy_list(urls: list[tuple[str, str]], concurrency: int = 5) -> list[str]:
    """Download simple text proxy lists concurrently."""
    session = await get_aiohttp_session()
    sem = asyncio.Semaphore(concurrency)

    async def fetch(url: str, proto: str) -> list[str]:
        async with sem:
            try:
                async with session.get(url, timeout=REQUEST_TIMEOUT) as resp:
                    if resp.status >= 400:
                        raise aiohttp.ClientResponseError(resp.request_info, resp.history, status=resp.status)
                    text = await resp.text()
                result: list[str] = []
                for line in text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    if "://" in line:
                        _, line = line.split("://", 1)
                    result.append(f"{proto}:{line}")
                return result
            except Exception as exc:
                logging.error("Error fetching %s: %s", url, exc)
                return []

    tasks = [asyncio.create_task(fetch(u, p)) for u, p in urls]
    results = await asyncio.gather(*tasks)
    entries: list[str] = []
    for res in results:
        entries.extend(res)
    return entries


async def scrape_gimmeproxy() -> None:
    try:
        text = await fetch_with_backoff(GIMMEPROXY_URL)
        if not text:
            return
        data = orjson.loads(text.encode())
        ip = data.get("ip")
        port = data.get("port")
        protocol = data.get("protocol")
        if ip and port and protocol:
            await add_proxies([f"{protocol.lower()}:{ip}:{port}"], source="gimmeproxy")
    except Exception as e:
        logging.error("Error fetching gimmeproxy: %s", e)


async def scrape_pubproxy() -> None:
    try:
        text = await fetch_with_backoff(PUBPROXY_URL)
        if not text:
            return
        data = orjson.loads(text.encode())
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
                await add_proxies([f"{protocol.lower()}:{ip}:{port}"], source="pubproxy")
    except Exception as e:
        logging.error("Error fetching pubproxy: %s", e)


async def scrape_proxykingdom() -> None:
    try:
        text = await fetch_with_backoff(PROXYKINGDOM_URL)
        if not text:
            return
        data = orjson.loads(text.encode())
        ip = data.get("address") or data.get("ip")
        port = data.get("port")
        protocol = data.get("protocol")
        if ip and port and protocol:
            await add_proxies([f"{protocol.lower()}:{ip}:{port}"], source="proxykingdom")
    except Exception as e:
        logging.error("Error fetching proxykingdom: %s", e)


async def scrape_geonode() -> None:
    """Fetch proxies from the geonode API."""
    proxies = []
    try:
        data = await fetch_json(GEONODE_URL)
        for item in data.get("data", []):
            ip = item.get("ip")
            port = item.get("port")
            protocols = item.get("protocols") or []
            proto = protocols[0].lower() if protocols else "http"
            if ip and port:
                proxies.append(f"{proto}:{ip}:{port}")
    except Exception as e:
        logging.error("Error fetching geonode proxies: %s", e)

    if proxies:
        STATS["api_counts"]["geonode"] += len(proxies)
        await add_proxies(proxies, source="geonode")


async def scrape_proxyspace() -> None:
    """Fetch proxies from proxyspace.pro lists."""
    urls = [
        (PROXYSPACE_HTTP_URL, "http"),
        (PROXYSPACE_HTTPS_URL, "https"),
        (PROXYSPACE_SOCKS4_URL, "socks4"),
        (PROXYSPACE_SOCKS5_URL, "socks5"),
    ]
    proxies = []
    for url, proto in urls:
        try:
            text = await fetch_with_backoff(url)
            for line in text.splitlines():
                line = line.strip()
                if line:
                    proxies.append(f"{proto}:{line}")
        except Exception as e:
            logging.error("Error fetching %s: %s", url, e)
        await asyncio.sleep(1)
    if proxies:
        STATS["api_counts"]["proxyspace"] += len(proxies)
        await add_proxies(proxies, source="proxyspace")


async def scrape_proxy_list_sites() -> None:
    for url, proto in PROXY_LIST_SITES:
        try:
            text = await fetch_with_backoff(url)
            if not text:
                continue
            soup = create_soup(text)
            proxies = []
            textarea = soup.find("textarea")
            if textarea:
                t = textarea.get_text()
                for line in t.splitlines():
                    line = line.strip()
                    if IP_PORT_RE.match(line):
                        proxies.append(f"{proto}:{line}")
            else:
                for row in soup.select("table tbody tr"):
                    cols = row.find_all("td")
                    if len(cols) >= 2:
                        ip = cols[0].get_text(strip=True)
                        port = cols[1].get_text(strip=True)
                        if IP_PORT_RE.match(f"{ip}:{port}"):
                            proxies.append(f"{proto}:{ip}:{port}")
            if proxies:
                STATS["api_counts"]["proxy_list_sites"] += len(proxies)
                await add_proxies(proxies, source="proxy_list_sites")
        except Exception as e:
            logging.error("Error fetching %s: %s", url, e)
        await asyncio.sleep(random.uniform(1, 3))


async def scrape_proxy_list_download() -> None:
    interval = SCRAPERS["proxy_list_download"]
    """Fetch proxies from https://www.proxy-list.download/api."""
    types = ["http", "https", "socks4", "socks5"]
    session = await get_aiohttp_session()
    while True:
        proxies = []
        for proto in types:
            url = f"https://www.proxy-list.download/api/v1/get?type={proto}"
            try:
                async with session.get(url, timeout=REQUEST_TIMEOUT) as resp:
                    if resp.status >= 400:
                        raise aiohttp.ClientResponseError(resp.request_info, resp.history, status=resp.status)
                    text = await resp.text()
                for line in text.splitlines():
                    line = line.strip()
                    if line:
                        proxies.append(f"{proto}:{line}")
            except Exception as e:
                logging.error("Error fetching %s: %s", url, e)
            await asyncio.sleep(interval)
        if proxies:
            STATS["api_counts"]["proxy_list_download"] += len(proxies)
            await add_proxies(proxies, source="proxy_list_download")
        await asyncio.sleep(interval)


async def scrape_freeproxy() -> None:
    interval = SCRAPERS["freeproxy"]
    """Fetch proxies from dpangestuw Free-Proxy GitHub lists."""
    urls = [
        (FREEPROXY_HTTP_URL, "http"),
        (FREEPROXY_SOCKS4_URL, "socks4"),
        (FREEPROXY_SOCKS5_URL, "socks5"),
    ]
    while True:
        proxies = await download_proxy_list(urls)
        if proxies:
            STATS["api_counts"]["freeproxy"] += len(proxies)
            await add_proxies(proxies, source="freeproxy")
        await asyncio.sleep(interval)


async def scrape_freshproxy() -> None:
    interval = SCRAPERS["freshproxy"]
    """Fetch proxies from the Fresh Proxy List project."""
    urls = [
        (FRESHPROXY_HTTP_URL, "http"),
        (FRESHPROXY_HTTPS_URL, "https"),
        (FRESHPROXY_SOCKS4_URL, "socks4"),
        (FRESHPROXY_SOCKS5_URL, "socks5"),
    ]
    while True:
        proxies = []
        for line in await download_proxy_list(urls):
            if IP_PORT_RE.match(line.split(":", 1)[1]):
                proxies.append(line)
        if proxies:
            STATS["api_counts"]["freshproxy"] += len(proxies)
            await add_proxies(proxies, source="freshproxy")
        await asyncio.sleep(interval)


async def scrape_proxifly() -> None:
    interval = SCRAPERS["proxifly"]
    """Fetch proxies from the Proxifly free-proxy lists."""
    urls = [
        (PROXIFLY_HTTP_URL, "http"),
        (PROXIFLY_SOCKS4_URL, "socks4"),
        (PROXIFLY_SOCKS5_URL, "socks5"),
    ]
    while True:
        entries = await download_proxy_list(urls)
        if entries:
            STATS["api_counts"]["proxifly"] += len(entries)
            await add_proxies(entries, source="proxifly")
        await asyncio.sleep(interval)


async def scrape_freeproxy_all() -> None:
    interval = SCRAPERS["freeproxy_all"]
    """Fetch aggregated proxies from dpangestuw Free-Proxy."""
    session = await get_aiohttp_session()
    while True:
        proxies = []
        try:
            async with session.get(FREEPROXY_ALL_URL, timeout=REQUEST_TIMEOUT) as resp:
                if resp.status >= 400:
                    raise aiohttp.ClientResponseError(resp.request_info, resp.history, status=resp.status)
                text = await resp.text()
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                if "://" in line:
                    proto, rest = line.split("://", 1)
                    proxies.append(f"{proto.lower()}:{rest}")
                elif IP_PORT_RE.match(line):
                    proxies.append(f"http:{line}")
        except Exception as e:
            logging.error("Error fetching %s: %s", FREEPROXY_ALL_URL, e)

        if proxies:
            STATS["api_counts"]["freeproxy_all"] += len(proxies)
            await add_proxies(proxies, source="freeproxy_all")
        await asyncio.sleep(interval)


async def scrape_kangproxy() -> None:
    interval = SCRAPERS["kangproxy"]
    """Fetch proxies from the KangProxy raw lists."""
    urls = [KANGPROXY_OLD_URL, KANGPROXY_URL]
    session = await get_aiohttp_session()
    while True:
        proxies = []
        for url in urls:
            try:
                async with session.get(url, timeout=REQUEST_TIMEOUT) as resp:
                    if resp.status >= 400:
                        raise aiohttp.ClientResponseError(resp.request_info, resp.history, status=resp.status)
                    text = await resp.text()
                for line in text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    if "://" in line:
                        proto, rest = line.split("://", 1)
                        proxies.append(f"{proto.lower()}:{rest}")
                    elif IP_PORT_RE.match(line):
                        proxies.append(f"http:{line}")
            except Exception as e:
                logging.error("Error fetching %s: %s", url, e)
            await asyncio.sleep(1)

        if proxies:
            STATS["api_counts"]["kangproxy"] += len(proxies)
            await add_proxies(proxies, source="kangproxy")
        await asyncio.sleep(interval)


def _parse_spys_list(text: str) -> list[tuple[str, str]]:
    """Return list of (ip, port) from spys.me proxy list text."""
    proxies = []
    for line in text.splitlines():
        line = line.strip()
        if (
            not line
            or line.startswith("Proxy list")
            or line.startswith("Http proxy")
            or line.startswith("Socks proxy")
            or line.startswith("Support")
            or line.startswith("BTC")
            or line.startswith("IP address")
            or line.lower().startswith("free ")
        ):
            continue
        ip_port = line.split()[0]
        if IP_PORT_RE.match(ip_port):
            ip, port = ip_port.split(":", 1)
            proxies.append((ip, port))
    return proxies


async def scrape_spys() -> None:
    interval = SCRAPERS["spys"]
    """Fetch proxies from spys.me lists and store as type;ip;port."""
    urls = [
        (SPYS_HTTP_URL, "http"),
        (SPYS_SOCKS_URL, "socks5"),
    ]
    session = await get_aiohttp_session()
    while True:
        proxies = []
        for url, proto in urls:
            try:
                async with session.get(url, timeout=REQUEST_TIMEOUT) as resp:
                    if resp.status >= 400:
                        raise aiohttp.ClientResponseError(resp.request_info, resp.history, status=resp.status)
                    text = await resp.text()
                for ip, port in _parse_spys_list(text):
                    proxies.append(f"{proto}:{ip}:{port}")
            except Exception as e:
                logging.error("Error fetching %s: %s", url, e)
            await asyncio.sleep(1)

        if proxies:
            STATS["api_counts"]["spys"] += len(proxies)
            await add_proxies(proxies, source="spys")

        await asyncio.sleep(interval)


async def scrape_proxybros() -> None:
    interval = SCRAPERS["proxybros"]
    """Fetch proxies from proxybros.com free proxy list."""
    session = await get_aiohttp_session()
    while True:
        proxies = []
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            async with session.get(PROXYBROS_URL, headers=headers, timeout=REQUEST_TIMEOUT) as resp:
                if resp.status >= 400:
                    raise aiohttp.ClientResponseError(resp.request_info, resp.history, status=resp.status)
                text = await resp.text()

            def _parse() -> list[str]:
                soup = BeautifulSoup(text, "lxml")
                out: list[str] = []
                for row in soup.select("table.proxylist-table tbody tr"):
                    ip_el = row.select_one("span.proxy-ip[data-ip]")
                    port_el = row.select_one("td[data-port]")
                    cells = row.find_all("td")
                    if ip_el and port_el and len(cells) >= 5:
                        ip = ip_el.get_text(strip=True)
                        port = port_el.get_text(strip=True)
                        proto = cells[4].get_text(strip=True).lower()
                        out.append(f"{proto}:{ip}:{port}")
                return out

            proxies = await asyncio.to_thread(_parse)
        except Exception as e:
            logging.error("Error fetching proxybros proxies: %s", e)

        if proxies:
            STATS["api_counts"]["proxybros"] += len(proxies)
            await add_proxies(proxies, source="proxybros")
        await asyncio.sleep(interval)


async def scrape_bloody_proxies() -> None:
    """Run Bloody-Proxy-Scraper and merge results."""
    interval = SCRAPERS["bloody"]
    module_path = (
        Path(__file__).resolve().parent
        / "vendor"
        / "Bloody-Proxy-Scraper"
        / "data"
        / "proxyscraper.py"
    )
    if not module_path.is_file():
        logging.warning(
            "Bloody-Proxy-Scraper module not found, disabling Bloody scraping"
        )
        return

    spec = importlib.util.spec_from_file_location(
        "bloody_proxyscraper", module_path
    )
    loader = spec.loader if spec else None
    if not spec or loader is None:
        logging.error("Unable to load Bloody-Proxy-Scraper module")
        return
    module = importlib.util.module_from_spec(spec)
    try:
        loader.exec_module(module)
    except FileNotFoundError:
        logging.error("Unable to load Bloody-Proxy-Scraper module: file missing")
        return
    Scraper = module.ProxyScraper

    while True:
        proxies: list[str] = []
        try:
            scraper = Scraper()
            result = scraper.scrape_all_proxies()
            proxies = result.get("all", [[], False])[0]
        except Exception as e:
            logging.error("Error running Bloody-Proxy-Scraper: %s", e)

        if proxies:
            STATS["api_counts"]["bloody"] += len(proxies)
            await add_proxies(proxies, source="bloody")
        await asyncio.sleep(interval)


async def _irc_listener(server: str, port: int = 6667) -> None:
    """Connect to an IRC server and monitor channels for proxy announcements."""
    import string

    while True:
        reader = writer = None
        try:
            reader, writer = await asyncio.open_connection(server, port)
            nick = "bot" + "".join(
                random.choices(string.ascii_lowercase + string.digits, k=6)
            )
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
                    STATS["irc_proxies"] += len(proxies)
                    add_proxies_sync(proxies, source="irc")
        except Exception as e:
            logging.error("IRC %s error: %s", server, e)
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
        lead = data[index : index + 1]
        if lead == b"i":
            end = data.index(b"e", index + 1)
            return int(data[index + 1 : end]), end + 1
        if lead == b"l":
            index += 1
            lst = []
            while data[index : index + 1] != b"e":
                item, index = parse(index)
                lst.append(item)
            return lst, index + 1
        if lead == b"d":
            index += 1
            d = {}
            while data[index : index + 1] != b"e":
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

    async def _query(
        self, addr: tuple[str, int], msg: dict
    ) -> tuple[dict, tuple[str, int]]:
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
        msg = {
            b"y": b"q",
            b"q": b"find_node",
            b"a": {b"id": self.node_id, b"target": target},
        }
        return await self._query(addr, msg)

    async def get_peers(self, addr: tuple[str, int], info_hash: bytes):
        msg = {
            b"y": b"q",
            b"q": b"get_peers",
            b"a": {b"id": self.node_id, b"info_hash": info_hash},
        }
        return await self._query(addr, msg)


def _decode_nodes(data: bytes) -> list[tuple[str, int]]:
    nodes = []
    for i in range(0, len(data), 26):
        segment = data[i : i + 26]
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
    try:
        transport, client = await loop.create_datagram_endpoint(
            lambda: DHTClient(node_id), local_addr=("0.0.0.0", 0), reuse_port=True
        )
    except ValueError:
        transport, client = await loop.create_datagram_endpoint(
            lambda: DHTClient(node_id), local_addr=("0.0.0.0", 0)
        )

    queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
    visited: set[tuple[str, int]] = set()

    for host, port in BOOTSTRAP_NODES:
        try:
            infos = await loop.getaddrinfo(
                host, port, family=socket.AF_INET, type=socket.SOCK_DGRAM
            )
            if infos:
                ip = infos[0][4][0]
                queue.put_nowait((ip, port))
        except Exception as e:
            logging.warning("Failed to resolve %s: %s", host, e)

    sem = asyncio.Semaphore(MAX_DHT_CONCURRENCY)
    count = 0

    async def worker() -> None:
        nonlocal count
        batch: list[str] = []
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
                    for p_ip, p_port in peers:
                        if p_port in PROXY_PORTS:
                            batch.append(f"{p_ip}:{p_port}")
                    if len(batch) >= 50:
                        STATS["dht_proxies"] += len(batch)
                        add_proxies_sync(batch, source="dht")
                        batch = []
                except Exception:
                    pass

                count += 1
                if count % DHT_LOG_EVERY == 0:
                    logging.info(
                        "DHT: visited %s nodes, proxies %s",
                        len(visited),
                        len(proxy_set),
                    )
                    if batch:
                        STATS["dht_proxies"] += len(batch)
                        add_proxies_sync(batch, source="dht")
                        batch = []
            queue.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(MAX_DHT_WORKERS)]
    await asyncio.gather(*workers)


def _run_crawl_dht() -> None:
    """Wrapper to execute crawl_dht inside a child process."""
    asyncio.run(crawl_dht())


def spawn_dht_processes() -> list[multiprocessing.Process]:
    procs = []
    for _ in range(DHT_PROCESSES):
        p = multiprocessing.Process(target=_run_crawl_dht)
        p.start()
        procs.append(p)
    return procs


async def run_proxxy() -> None:
    """Background task running the proXXy asynchronous scraper."""
    interval = SCRAPERS["proxxy"]
    while True:
        async for batch in fetch_proxxy_sources():
            if not batch:
                continue
            STATS["api_counts"]["proxxy"] += len(batch)
            add_proxies_sync(batch, source="proxxy")
        await asyncio.sleep(interval)


async def parse_list(session: Any, url: str) -> list:
    async with session.get(url, timeout=REQUEST_TIMEOUT) as resp:
        text = await resp.text()
    return [line.strip() for line in text.splitlines() if line.strip()]


async def scrape_openproxylist(interval: float, concurrency: int):
    sem = asyncio.Semaphore(concurrency)
    session = await get_aiohttp_session()

    async def fetch(url: str) -> list[str]:
        async with sem:
            return await parse_list(session, url)

    while True:
        tasks = [asyncio.create_task(fetch(u)) for u in OPENPROXYLIST_ENDPOINTS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        entries: list[str] = []
        for proxies in results:
            if isinstance(proxies, list):
                entries.extend(proxies)
        STATS["api_counts"]["openproxylist"] += len(entries)
        add_proxies_sync(entries, source="openproxylist")
        await asyncio.sleep(interval)


async def scrape_proxyhub(
    interval: float, concurrency: int, batch_size: int = PROXYHUB_BATCH_SIZE
) -> None:
    """Run ProxyHub's asynchronous fetcher alongside other scrapers."""

    async def _fetch(url: str, sem: asyncio.Semaphore) -> List[str]:
        async with sem:
            try:
                return await fetch_source(url)
            except Exception as e:
                logging.error("proxyhub source error %s: %s", url, e)
                return []

    while True:
        sem = asyncio.Semaphore(concurrency)
        urls = list(SOURCE_LIST)
        for i in range(0, len(urls), batch_size):
            batch = urls[i : i + batch_size]
            tasks = [asyncio.create_task(_fetch(url, sem)) for url in batch]
            for task in asyncio.as_completed(tasks):
                proxies = await task
                if not proxies:
                    continue
                STATS["api_counts"]["proxyhub"] += len(proxies)
                add_proxies_sync(proxies, source="proxyhub")
        await asyncio.sleep(interval)


TR_RE = re.compile(
    r"<td>(.*?)</td>\s*"
    r"<td><script>document.write\('(.*?)'\)\s*</script></td>\s*"
    r"<td><script>document.write\(gp.dep\('(.*?)'\)\)\s*</script></td>\s*"
    r"<td .*?>(.*?)</td>\s*"
    r"<td>(.*?)</td>\s*"
    r"<td></td>\s*"
    r"<td .*?>(.*?)</td>\s*"
    r"<td .*?>(.*?)</td>",
    re.S,
)

PAGE_DIV_RE = re.compile(r'<div class="pagenavi">(.*?)</div>', re.S)
PAGE_LINK_RE = re.compile(r"<a .*?>(.*?)</a>")


def _gp_page_count(text: str) -> int:
    text = text.replace("\n", " ")
    count = 0
    for div in PAGE_DIV_RE.findall(text):
        for link in PAGE_LINK_RE.findall(div):
            try:
                count = int(link)
            except Exception:
                pass
    return count


def _parse_gatherproxy(text: str) -> list[tuple[str, str, str, str, int]]:
    text = text.replace("\n", " ")
    proxies = []
    for g in TR_RE.findall(text):
        try:
            port = str(int(g[2], 16))
            resp_time = int(g[6].replace("ms", ""))
        except Exception:
            continue
        proxies.append((g[1], port, g[3], g[4], resp_time))
    return proxies


async def scrape_gatherproxy(interval: float, concurrency: int):
    sem = asyncio.Semaphore(concurrency)
    while True:
        proxies: list[tuple[str, str, str, str, int]] = []
        session = await get_aiohttp_session()

        async def fetch_page(page: int) -> str:
            async with sem:
                resp = await session.post(
                    GATHER_PROXY_URI,
                    data={
                        "Type": "Elite",
                        "PageIdx": page,
                        "Uptime": GATHER_PROXY_MIN_UPTIME,
                    },
                    timeout=REQUEST_TIMEOUT,
                )
                return await resp.text()

        try:
            first = await fetch_page(1)
        except Exception as e:
            logging.error("gatherproxy page 1 error: %s", e)
            await asyncio.sleep(interval)
            continue

        proxies.extend(_parse_gatherproxy(first))
        pages = _gp_page_count(first)

        tasks = [asyncio.create_task(fetch_page(p)) for p in range(2, pages + 1)]
        for task in asyncio.as_completed(tasks):
            try:
                html = await task
            except Exception as e:
                logging.error("gatherproxy fetch error: %s", e)
                continue
            proxies.extend(_parse_gatherproxy(html))

        if proxies:
            entries = [
                f"{typ.lower()}:{ip}:{port}" for ip, port, typ, country, rt in proxies
            ]
            STATS["api_counts"]["gatherproxy"] += len(entries)
            add_proxies_sync(entries, source="gatherproxy")
        await asyncio.sleep(interval)


async def run_periodic(func, interval: float, key: str | None = None) -> None:
    while True:
        start = time.monotonic()
        await func()
        elapsed = time.monotonic() - start
        delay = max(0.0, interval - elapsed)
        if key is not None:
            delay *= 2 ** SOURCE_BACKOFF[key]
        await asyncio.sleep(delay)


async def main() -> None:
    global MAIN_LOOP
    MAIN_LOOP = asyncio.get_running_loop()
    await load_blacklists()
    procs = spawn_dht_processes()
    async with asyncio.TaskGroup() as tg:
        tg.create_task(run_periodic(scrape_mt_proxies, SCRAPERS["mtpro"], "mtpro"))
        tg.create_task(run_periodic(monitor_paste_feeds, SCRAPERS["paste"], "paste"))
        tg.create_task(run_periodic(scrape_tor_relays, SCRAPERS["tor"], "tor"))
        tg.create_task(monitor_irc_channels())
        tg.create_task(run_periodic(scrape_proxyscrape, SCRAPERS["proxyscrape"], "proxyscrape"))
        tg.create_task(run_periodic(scrape_gimmeproxy, SCRAPERS["gimmeproxy"], "gimmeproxy"))
        tg.create_task(run_periodic(scrape_pubproxy, SCRAPERS["pubproxy"], "pubproxy"))
        tg.create_task(run_periodic(scrape_proxykingdom, SCRAPERS["proxykingdom"], "proxykingdom"))
        tg.create_task(run_periodic(scrape_geonode, SCRAPERS["geonode"], "geonode"))
        tg.create_task(run_periodic(scrape_proxyspace, SCRAPERS["proxyspace"], "proxyspace"))
        tg.create_task(run_periodic(scrape_proxy_list_sites, SCRAPERS["proxy_list_sites"], "proxy_list_sites"))
        tg.create_task(writer_loop())
        tg.create_task(stats_loop())
        tg.create_task(run_proxxy())
        tg.create_task(scrape_proxyhub(PROXYHUB_INTERVAL, PROXYHUB_CONCURRENCY))
        tg.create_task(scrape_gatherproxy(GATHER_PROXY_INTERVAL, GATHER_PROXY_CONCURRENCY))
        tg.create_task(scrape_openproxylist(OPENPROXYLIST_INTERVAL, OPENPROXYLIST_CONCURRENCY))
        tg.create_task(scrape_proxyscraper_sources())
        tg.create_task(scrape_proxy_list_download())
        tg.create_task(scrape_freeproxy())
        tg.create_task(scrape_freshproxy())
        tg.create_task(scrape_proxifly())
        tg.create_task(scrape_freeproxy_all())
        tg.create_task(scrape_kangproxy())
        tg.create_task(scrape_spys())
        tg.create_task(scrape_proxybros())
        tg.create_task(scrape_bloody_proxies())
    for p in procs:
        p.terminate()

if __name__ == "__main__":
    import sys

    if len(sys.argv) >= 2 and sys.argv[1] == "filter_p1":
        import asyncio

        if len(sys.argv) == 4:
            proxy = sys.argv[2]
            service = sys.argv[3]
            success = filter_p1(proxy, service)
            sys.exit(0 if success else 1)
        service = sys.argv[2] if len(sys.argv) >= 3 else "pop3"
        asyncio.run(run_filter_p1_all(service))
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "filter_p2":
        import asyncio
        if len(sys.argv) == 3:
            proxy = sys.argv[2]

            async def _run() -> int:
                ctx = ssl.create_default_context()
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                await load_blacklists()
                res = await _score_single_proxy(proxy, ctx, return_all=True)
                if not res:
                    return 1
                p, total, parts = res
                print(
                    f"{p} score={total} ip={parts['ip']} tls={parts['tls']}"
                )
                return 0

            sys.exit(asyncio.run(_run()))
        else:
            asyncio.run(run_filter_p2_all())
            sys.exit(0)

    elif len(sys.argv) == 3:
        success = filter_p1(sys.argv[1], sys.argv[2])
        sys.exit(0 if success else 1)

    asyncio.run(main())
