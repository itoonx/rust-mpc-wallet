//! Per-key rate limiting for handshake endpoints using a token bucket.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Mutex;

/// Shared rate limiter state.
#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<Mutex<HashMap<String, TokenBucket>>>,
    max_tokens: u32,
    refill_rate: u32,
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(10) // 10 requests/sec default
    }
}

impl RateLimiter {
    /// Create a new rate limiter.
    /// `max_rps` = maximum requests per second per key.
    pub fn new(max_rps: u32) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            max_tokens: max_rps,
            refill_rate: max_rps,
        }
    }

    /// Check if a request is allowed for the given key.
    /// Returns `true` if allowed, `false` if rate limited.
    pub async fn check(&self, key: &str) -> bool {
        let mut buckets = self.buckets.lock().await;
        let now = Instant::now();

        let bucket = buckets.entry(key.to_string()).or_insert(TokenBucket {
            tokens: self.max_tokens as f64,
            last_refill: now,
        });

        // Refill tokens based on elapsed time.
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens =
            (bucket.tokens + elapsed * self.refill_rate as f64).min(self.max_tokens as f64);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}
