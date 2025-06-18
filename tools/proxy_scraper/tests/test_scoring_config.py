import importlib
import sys
import types
import json
import asyncio


def _prepare(monkeypatch, config_path=None):
    if 'scrape_proxies' in sys.modules:
        del sys.modules['scrape_proxies']
    proxyhub = types.ModuleType('proxyhub')
    monkeypatch.setitem(sys.modules, 'proxyhub', proxyhub)
    if config_path:
        monkeypatch.setenv('SCORING_CONFIG', str(config_path))
    else:
        monkeypatch.delenv('SCORING_CONFIG', raising=False)
    return importlib.import_module('scrape_proxies')


def test_default_mode_strict(monkeypatch):
    sp = _prepare(monkeypatch)
    assert sp.MODE == 'strict'
    assert sp.CRITICAL_MIN == 120
    assert sp.WEIGHTS['tls_reach'] == 152


def test_lenient_quarantine(monkeypatch, tmp_path):
    cfg = {
        "mode": "lenient",
        "lenient": {
            "CRITICAL_MIN": 100,
            "OVERALL_MIN": 200,
            "WEIGHTS": {
                "ip_rep": 120,
                "tls_reach": 152,
            },
        },
    }
    path = tmp_path / 'cfg.json'
    path.write_text(json.dumps(cfg))
    sp = _prepare(monkeypatch, path)

    async def fake_score(p, ctx, return_all=False):
        mapping = {
            'socks5:1.1.1.1:1': ('socks5:1.1.1.1:1', 700, {'critical': 400}),
            'socks5:2.2.2.2:2': ('socks5:2.2.2.2:2', 550, {'critical': 90}),
            'socks5:3.3.3.3:3': ('socks5:3.3.3.3:3', 150, {'critical': 80}),
        }
        return mapping[p]

    async def nop(*args, **kwargs):
        return None

    monkeypatch.setattr(sp, '_score_single_proxy', fake_score)
    monkeypatch.setattr(sp, 'load_blacklists', nop)

    good, quarantine = asyncio.run(sp.filter_p2([
        'socks5:1.1.1.1:1',
        'socks5:2.2.2.2:2',
        'socks5:3.3.3.3:3',
    ]))
    assert good == [('socks5:1.1.1.1:1', 700)]
    assert quarantine == [('socks5:2.2.2.2:2', 550)]
