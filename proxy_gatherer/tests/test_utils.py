import gzip
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Provide minimal stub for optional proxyhub dependency
proxyhub = types.ModuleType('proxyhub')
proxyhub.SOURCE_LIST = []
def fetch_source(url):
    return []
proxyhub.fetch_source = fetch_source
sys.modules.setdefault('proxyhub', proxyhub)

# Some packages used only for type hints might not expose the expected classes.
import aiofiles  # type: ignore
if not hasattr(aiofiles, 'BaseFile'):
    class _BF:  # minimal stub for type checks
        pass
    aiofiles.BaseFile = _BF  # type: ignore

from scrape_proxies import normalize_proxy, _write_gzip, bencode, bdecode


def test_normalize_proxy_basic():
    assert normalize_proxy('http://1.2.3.4:80') == 'http:1.2.3.4:80'
    assert normalize_proxy('1.2.3.4:8080') == 'http:1.2.3.4:8080'
    assert normalize_proxy('socks5://5.6.7.8:1080') == 'socks5:5.6.7.8:1080'
    assert normalize_proxy('foo://1.2.3.4:1') == 'other:1.2.3.4:1'
    assert normalize_proxy('bad') is None


def test_write_gzip(tmp_path):
    path = tmp_path / 'out.gz'
    _write_gzip(str(path), ['a', 'b'], 'at')
    with gzip.open(path, 'rt') as f:
        data = f.read().splitlines()
    assert data == ['a', 'b']


def test_bencode_roundtrip():
    value = {'a': [1, b'2']}
    encoded = bencode(value)
    assert bdecode(encoded) == {b'a': [1, b'2']}
