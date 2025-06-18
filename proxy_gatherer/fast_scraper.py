import asyncio
import aiohttp
import aiofiles
import gzip
import time
import os
import socket
from typing import Dict, List
from bs4 import BeautifulSoup
from pybloom_live import ScalableBloomFilter

try:
    import uvloop  # type: ignore
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except Exception:
    uvloop = None  # pragma: no cover

OUTPUT_COMPRESSED = os.getenv("OUTPUT_COMPRESSED", "0") == "1"
CHECK_CONNECT = os.getenv("CHECK_CONNECT", "0") == "1"
OUT_PATH = "p1_pass.txt" + (".gz" if OUTPUT_COMPRESSED else "")

POOL_LIMIT_MIN = 50
POOL_LIMIT_MAX = 800
POOL_LIMIT = 300
_sem = asyncio.Semaphore(POOL_LIMIT)
_connector = aiohttp.TCPConnector(limit=POOL_LIMIT)
_session: aiohttp.ClientSession | None = None

_last_fetch: Dict[str, float] = {}
_bloom = ScalableBloomFilter(mode=ScalableBloomFilter.SMALL_SET_GROWTH)
_success = 0
_checked = 0

SOURCES = {
    "http_github": {
        "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "cooldown": 300,
    },
    "socks5_github": {
        "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        "cooldown": 300,
    },
}


async def adjust_pool_limit(success_rate: float) -> None:
    global POOL_LIMIT, _sem, _connector, _session
    old = POOL_LIMIT
    if success_rate < 0.3:
        POOL_LIMIT = max(POOL_LIMIT_MIN, POOL_LIMIT - 50)
    elif success_rate > 0.7:
        POOL_LIMIT = min(POOL_LIMIT_MAX, POOL_LIMIT + 10)
    if POOL_LIMIT != old:
        _sem = asyncio.Semaphore(POOL_LIMIT)
        _connector = aiohttp.TCPConnector(limit=POOL_LIMIT)
        if _session is not None:
            await _session.close()
        _session = aiohttp.ClientSession(connector=_connector)


def parse_proxies(text: str) -> List[str]:
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    proxies = []
    for line in lines:
        if line.startswith("http://") or line.startswith("https://") or line.startswith("socks"):
            proto, rest = line.split("://", 1)
            ip_port = rest
        else:
            proto = "http"
            ip_port = line
        if ":" not in ip_port:
            continue
        ip, port = ip_port.split(":", 1)
        proxies.append(f"{proto}://{ip}:{port}")
    return proxies


async def fetch_source(name: str, cfg: Dict[str, str | int]) -> List[str]:
    global _session
    now = time.monotonic()
    last = _last_fetch.get(name, 0)
    cooldown = cfg["cooldown"]
    if now - last < cooldown:
        await asyncio.sleep(cooldown - (now - last))
    _last_fetch[name] = time.monotonic()
    if _session is None:
        _session = aiohttp.ClientSession(connector=_connector)
    url = cfg["url"]
    async with _sem:
        async with _session.get(url, timeout=10) as resp:
            text = await resp.text()
    return parse_proxies(text)


async def quick_tcp_connect(ip: str, port: int, timeout: float = 3.0) -> bool:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def http_connect_check(proxy: str) -> bool:
    proto, ip, port = proxy.split(":")
    port = int(port)
    if proto not in {"http", "https"}:
        return True
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), 5)
    except Exception:
        return False
    try:
        req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
        writer.write(req.encode())
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(1024), 5)
        return b"200" in resp
    except Exception:
        return False
    finally:
        writer.close()
        await writer.wait_closed()


async def validate_proxy(proxy: str, out_f) -> None:
    global _success, _checked
    if proxy in _bloom:
        return
    _bloom.add(proxy)
    proto, ip, port = proxy.split(":")
    port = int(port)
    ok = await quick_tcp_connect(ip, port)
    if ok and CHECK_CONNECT:
        ok = await http_connect_check(f"{proto}:{ip}:{port}")
    _checked += 1
    if ok:
        _success += 1
        line = f"{proto}://{ip}:{port}\n"
        if OUTPUT_COMPRESSED:
            await asyncio.to_thread(out_f.write, line)
            await asyncio.to_thread(out_f.flush)
        else:
            await out_f.write(line)
            await out_f.flush()

    if _checked % 50 == 0:
        rate = _success / max(1, _checked)
        await adjust_pool_limit(rate)


async def worker(queue: asyncio.Queue, out_f) -> None:
    while True:
        proxy = await queue.get()
        try:
            await validate_proxy(proxy, out_f)
        finally:
            queue.task_done()


async def main() -> None:
    queue: asyncio.Queue[str] = asyncio.Queue()
    tasks = []
    if OUTPUT_COMPRESSED:
        out_f = gzip.open(OUT_PATH, "at", buffering=1)
    else:
        out_f = await aiofiles.open(OUT_PATH, "a", buffering=1)
    for _ in range(POOL_LIMIT):
        tasks.append(asyncio.create_task(worker(queue, out_f)))

    async def produce(name: str, cfg: Dict[str, str | int]):
        while True:
            try:
                proxies = await fetch_source(name, cfg)
                for p in proxies:
                    await queue.put(p)
            except Exception:
                pass

    prod_tasks = [asyncio.create_task(produce(n, c)) for n, c in SOURCES.items()]
    await asyncio.gather(*prod_tasks)


if __name__ == "__main__":
    asyncio.run(main())
