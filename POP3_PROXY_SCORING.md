# POP3 Proxy Scoring Pipeline

This document describes a high performance method to evaluate large proxy lists for POP3 usage.

## Score Computation
Each proxy is measured for the following metrics:

- `latency_ms` – round trip time for a POP3 handshake.
- `success_rate` – fraction of successful handshakes in recent attempts.
- `throughput_kbps` – data transfer rate during a short download.
- `error_rate` – fraction of protocol errors (TCP resets, banner issues…).
- `anonymity_level` – 0 = transparent, 1 = anonymous, 2 = elite.
- `uptime_pct` – observed availability during the last 24 h.
- `proxy_type` – 0 = HTTP, 1 = SOCKS, 2 = CONNECT/other.
- `location_score` – preference score based on geo location (0–1).

Each metric is normalized to the range 0…1. Latency is inverted so lower
values result in a higher score. A weighted sum yields a final score in the
range 0…100:

```
score = 100 * (
  w_latency    * latency_norm +
  w_success    * success_rate +
  w_throughput * throughput_norm +
  w_error      * (1 - error_rate) +
  w_anonymity  * (anonymity_level / 2) +
  w_uptime     * uptime_pct +
  w_type       * (proxy_type / 2) +
  w_location   * location_score
)
```

The default weights sum to 1.0:

```
w_latency=0.20
w_success=0.20
w_throughput=0.15
w_error=0.15
w_anonymity=0.10
w_uptime=0.10
w_type=0.05
w_location=0.05
```

## Suitability Threshold
A proxy is marked as suitable for POP3 testing when `score ≥ θ`.
The example implementation uses `θ = 0.75` (i.e. 75 / 100).

## Audit Pipeline
The `proxy_scoring.py` module implements an asynchronous pipeline:

1. Proxies are loaded from a list or file.
2. `asyncio` tasks probe proxies in batches using a semaphore to limit
   concurrency. The demo uses a batch size of 100 and a concurrency
   level of 200.
3. Measurements return a `ProxyMetrics` structure which is scored
   immediately.
4. Results are streamed to `proxy_results.csv` to avoid holding all
   data in memory.

The code is capable of handling millions of proxies given appropriate
batch size and concurrency settings. Aggressive timeouts, connection
pooling and DNS caching would be added in a real network probe
implementation.

## Example Run
Running `python3 proxy_scoring.py` performs a simulated audit of
1000 proxies:

```
Audited 1000 proxies in 0.02s - pass:69 fail:931 mem:22.8MB
```

The example writes a small CSV file containing each proxy, the computed
score and the suitability flag.
