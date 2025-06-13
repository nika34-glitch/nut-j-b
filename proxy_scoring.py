import asyncio
import csv
import random
import time
from dataclasses import dataclass, field
from typing import List, Dict
import psutil

@dataclass
class ProxyMetrics:
    latency_ms: float
    success_rate: float
    throughput_kbps: float
    error_rate: float
    anonymity_level: int
    uptime_pct: float
    proxy_type: int  # 0=http,1=socks,2=connect etc
    location_score: float

@dataclass
class ProxyResult:
    address: str
    metrics: ProxyMetrics
    score: float
    suitable: bool

class ProxyScorer:
    def __init__(self, weights: Dict[str, float], threshold: float = 0.75):
        if abs(sum(weights.values()) - 1.0) > 1e-6:
            raise ValueError("weights must sum to 1")
        self.w = weights
        self.threshold = threshold

    @staticmethod
    def _norm(value: float, min_v: float, max_v: float) -> float:
        if max_v == min_v:
            return 0.0
        return max(0.0, min(1.0, (value - min_v) / (max_v - min_v)))

    def score_metrics(self, m: ProxyMetrics) -> float:
        latency_norm = 1.0 - self._norm(m.latency_ms, 0, 2000)
        throughput_norm = self._norm(m.throughput_kbps, 0, 10_000)
        score = (
            self.w['latency'] * latency_norm
            + self.w['success'] * m.success_rate
            + self.w['throughput'] * throughput_norm
            + self.w['error'] * (1.0 - m.error_rate)
            + self.w['anonymity'] * (m.anonymity_level / 2)
            + self.w['uptime'] * m.uptime_pct
            + self.w['type'] * (m.proxy_type / 2)
            + self.w['location'] * m.location_score
        )
        return max(0.0, min(1.0, score)) * 100

    def suitable(self, score: float) -> bool:
        return score >= self.threshold * 100

async def simulate_probe(proxy: str) -> ProxyMetrics:
    await asyncio.sleep(0)  # placeholder for real I/O
    return ProxyMetrics(
        latency_ms=random.uniform(50, 1000),
        success_rate=random.uniform(0.5, 1.0),
        throughput_kbps=random.uniform(100, 5000),
        error_rate=random.uniform(0.0, 0.2),
        anonymity_level=random.randint(0, 2),
        uptime_pct=random.uniform(0.7, 1.0),
        proxy_type=random.randint(0, 2),
        location_score=random.uniform(0.0, 1.0),
    )

async def audit_proxies(proxies: List[str], scorer: ProxyScorer, batch_size: int = 1000, concurrency: int = 100):
    sem = asyncio.Semaphore(concurrency)
    results: List[ProxyResult] = []

    async def worker(p: str):
        async with sem:
            m = await simulate_probe(p)
            s = scorer.score_metrics(m)
            results.append(ProxyResult(address=p, metrics=m, score=s, suitable=scorer.suitable(s)))

    for i in range(0, len(proxies), batch_size):
        tasks = [asyncio.create_task(worker(p)) for p in proxies[i:i+batch_size]]
        await asyncio.gather(*tasks)
    return results

def main():
    weights = {
        'latency': 0.2,
        'success': 0.2,
        'throughput': 0.15,
        'error': 0.15,
        'anonymity': 0.1,
        'uptime': 0.1,
        'type': 0.05,
        'location': 0.05,
    }
    scorer = ProxyScorer(weights, threshold=0.75)

    proxies = [f"192.0.2.{i}:1080" for i in range(1, 1001)]

    start = time.time()
    results = asyncio.run(audit_proxies(proxies, scorer, batch_size=100, concurrency=200))
    elapsed = time.time() - start

    passed = sum(r.suitable for r in results)
    failed = len(results) - passed

    with open('proxy_results.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['proxy', 'score', 'suitable'])
        for r in results:
            writer.writerow([r.address, f"{r.score:.2f}", r.suitable])

    process = psutil.Process()
    mem_mb = process.memory_info().rss / (1024 * 1024)
    print(f"Audited {len(results)} proxies in {elapsed:.2f}s - pass:{passed} fail:{failed} mem:{mem_mb:.1f}MB")

if __name__ == '__main__':
    main()
