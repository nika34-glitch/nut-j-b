import importlib
import sys
import types
import asyncio


def test_proxyhub_fallback(monkeypatch):
    # Remove already imported scrape_proxies module if present
    if 'scrape_proxies' in sys.modules:
        del sys.modules['scrape_proxies']
    # Provide an empty proxyhub module so attributes are missing
    proxyhub = types.ModuleType('proxyhub')
    monkeypatch.setitem(sys.modules, 'proxyhub', proxyhub)

    sp = importlib.import_module('scrape_proxies')

    assert sp.SOURCE_LIST == []
    assert asyncio.run(sp.fetch_source('http://example.com')) == []
