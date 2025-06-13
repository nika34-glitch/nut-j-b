use std::fs::File;
use std::io::Write;

use libero_validator::estimate_bloom_size;

#[test]
fn bloom_estimate_minimum_one() {
    let path = "./test_small.txt";
    let mut f = File::create(path).unwrap();
    writeln!(f, "a@b:c").unwrap();
    drop(f);
    let file = File::open(path).unwrap();
    let size = estimate_bloom_size(&file);
    assert!(size >= 1);
    std::fs::remove_file(path).unwrap();
}
