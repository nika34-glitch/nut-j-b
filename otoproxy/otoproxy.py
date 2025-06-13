import asyncio
import re
import time
from pathlib import Path
from typing import Set, Tuple, Optional

import aiohttp
from aiohttp_socks import ProxyConnector

SITES_FILE = Path(__file__).with_name("sites.txt")
FEEDS_DIR = Path(__file__).resolve().parents[1] / "feeds"
FEEDS_DIR.mkdir(exist_ok=True)

ALL_FILE = FEEDS_DIR / "all-proxies.txt"
HTTP_FILE = FEEDS_DIR / "http-proxies.txt"
SOCKS4_FILE = FEEDS_DIR / "socks4-proxies.txt"
SOCKS5_FILE = FEEDS_DIR / "socks5-proxies.txt"
BLACKLIST_FILE = FEEDS_DIR / "blacklist.txt"

TEST_URL = "https://httpbin.org/ip"
CHECK_TIMEOUT = 1.5  # seconds
MAX_CONCURRENCY = 100

PROXY_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}:\d{2,5})")


def load_sites() -> Set[str]:
    sites = set()
    if SITES_FILE.exists():
        for line in SITES_FILE.read_text().splitlines():
            line = line.strip()
            if line:
                sites.add(line)
    return sites


def load_blacklist() -> Set[str]:
    if BLACKLIST_FILE.exists():
        return set(p.strip() for p in BLACKLIST_FILE.read_text().splitlines() if p)
    return set()


async def fetch_site(session: aiohttp.ClientSession, url: str) -> Set[str]:
    try:
        async with session.get(url, timeout=10) as resp:
            text = await resp.text(errors="ignore")
            return set(PROXY_RE.findall(text))
    except Exception:
        return set()


async def gather_candidates(urls: Set[str]) -> Set[str]:
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_site(session, u) for u in urls]
        results = await asyncio.gather(*tasks)
    candidates: Set[str] = set()
    for r in results:
        candidates.update(r)
    return candidates


async def probe(proxy: str) -> Tuple[str, Optional[str]]:
    """Return (proxy, kind) if working else (proxy, None)."""
    for kind in ("http", "socks4", "socks5"):
        try:
            if kind == "http":
                conn = aiohttp.TCPConnector(ssl=False)
                async with aiohttp.ClientSession(connector=conn) as session:
                    start = time.monotonic()
                    async with session.get(TEST_URL, proxy=f"http://{proxy}", timeout=CHECK_TIMEOUT) as resp:
                        await resp.text()
                    if time.monotonic() - start <= CHECK_TIMEOUT:
                        return proxy, kind
            else:
                conn = ProxyConnector.from_url(f"{kind}://{proxy}")
                async with aiohttp.ClientSession(connector=conn) as session:
                    start = time.monotonic()
                    async with session.get(TEST_URL, timeout=CHECK_TIMEOUT) as resp:
                        await resp.text()
                    if time.monotonic() - start <= CHECK_TIMEOUT:
                        return proxy, kind
        except Exception:
            pass
    return proxy, None


async def verify(proxies: Set[str]) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
    sem = asyncio.Semaphore(MAX_CONCURRENCY)
    http_set, s4_set, s5_set = set(), set(), set()
    blacklist = set()

    async def worker(p: str):
        async with sem:
            prx, kind = await probe(p)
            if kind == "http":
                http_set.add(prx)
            elif kind == "socks4":
                s4_set.add(prx)
            elif kind == "socks5":
                s5_set.add(prx)
            else:
                blacklist.add(prx)

    tasks = [asyncio.create_task(worker(p)) for p in proxies]
    await asyncio.gather(*tasks)
    all_set = http_set | s4_set | s5_set
    return all_set, http_set, s4_set, s5_set, blacklist


def save_set(path: Path, items: Set[str]):
    if items:
        path.write_text("\n".join(sorted(items)))
    else:
        path.write_text("")


async def main():
    sites = load_sites()
    blacklist = load_blacklist()
    candidates = await gather_candidates(sites)
    candidates -= blacklist

    all_set, http_set, s4_set, s5_set, bad_set = await verify(candidates)

    save_set(ALL_FILE, all_set)
    save_set(HTTP_FILE, http_set)
    save_set(SOCKS4_FILE, s4_set)
    save_set(SOCKS5_FILE, s5_set)

    if bad_set:
        with BLACKLIST_FILE.open("a") as f:
            for b in sorted(bad_set):
                f.write(b + "\n")


if __name__ == "__main__":
    asyncio.run(main())
