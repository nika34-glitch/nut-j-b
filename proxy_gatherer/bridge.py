import asyncio
from .fast_scraper import fetch_source, SOURCES

async def run(sender):
    async def produce(name, cfg):
        while True:
            try:
                proxies = await fetch_source(name, cfg)
                for p in proxies:
                    await sender.send(p)
            except Exception:
                await asyncio.sleep(1)
    tasks = [asyncio.create_task(produce(n, c)) for n, c in SOURCES.items()]
    await asyncio.gather(*tasks)
