use criterion::{criterion_group, criterion_main, Criterion};
use memchr::memchr_iter;
use memmap2::Mmap;
use std::fs::File;
use std::io::{BufRead, BufReader};

fn bench_bufreader(c: &mut Criterion) {
    c.bench_function("bufreader", |b| {
        b.iter(|| {
            let file = File::open("combos.txt").unwrap();
            let reader = BufReader::new(file);
            let mut cnt = 0usize;
            for line in reader.lines() {
                let _ = line.unwrap();
                cnt += 1;
            }
            cnt
        })
    });
}

fn bench_mmap(c: &mut Criterion) {
    c.bench_function("mmap", |b| {
        b.iter(|| {
            let file = File::open("combos.txt").unwrap();
            let mmap = unsafe { Mmap::map(&file).unwrap() };
            let mut cnt = 0usize;
            let mut start = 0;
            for nl in memchr_iter(b'\n', &mmap[..]) {
                let _ = &mmap[start..nl];
                start = nl + 1;
                cnt += 1;
            }
            if start < mmap.len() {
                cnt += 1;
            }
            cnt
        })
    });
}

criterion_group!(benches, bench_bufreader, bench_mmap);
criterion_main!(benches);
