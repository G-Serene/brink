//! Simple Fibonacci series program.
//!
//! Run with: cargo run --example fibonacci -- 10

use std::env;

fn fibonacci_series(count: usize) -> Vec<u64> {
    let mut series = Vec::with_capacity(count);
    let (mut a, mut b) = (0u64, 1u64);
    for _ in 0..count {
        series.push(a);
        let next = a + b;
        a = b;
        b = next;
    }
    series
}

fn main() {
    let count = env::args()
        .nth(1)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(10);

    let series = fibonacci_series(count);
    let printable: Vec<String> = series.iter().map(u64::to_string).collect();
    println!("{}", printable.join(", "));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_ten() {
        assert_eq!(
            fibonacci_series(10),
            vec![0, 1, 1, 2, 3, 5, 8, 13, 21, 34]
        );
    }

    #[test]
    fn zero_count() {
        assert!(fibonacci_series(0).is_empty());
    }
}
