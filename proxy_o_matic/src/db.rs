use sqlx::{sqlite::{SqlitePoolOptions}, SqlitePool};
use serde::{Serialize, Deserialize};

/// Proxy statistics stored in the database.
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct ProxyStats {
    pub ip: String,
    pub port: i64,
    pub last_success: Option<i64>,
    pub last_failure: Option<i64>,
    pub tries: i64,
    pub success_count: i64,
    pub avg_rtt: f64,
    pub avg_throughput: f64,
    pub score: f64,
}

/// Database handle.
#[derive(Clone)]
pub struct Database {
    pool: SqlitePool,
}

impl Database {
    /// Open database at path and run migrations.
    pub async fn open(path: &str) -> sqlx::Result<Self> {
        let pool = SqlitePoolOptions::new().max_connections(5).connect(path).await?;
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS proxy_stats(
            ip TEXT PRIMARY KEY,
            port INTEGER,
            last_success INTEGER,
            last_failure INTEGER,
            tries INTEGER,
            success_count INTEGER,
            avg_rtt REAL,
            avg_throughput REAL,
            score REAL
        )"#,
        )
        .execute(&pool)
        .await?;
        Ok(Self { pool })
    }

    /// Insert or update proxy statistics.
    pub async fn upsert(&self, stats: &ProxyStats) -> sqlx::Result<()> {
        sqlx::query(
            r#"INSERT INTO proxy_stats(ip, port, last_success, last_failure, tries, success_count, avg_rtt, avg_throughput, score)
            VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(ip) DO UPDATE SET
                port=excluded.port,
                last_success=excluded.last_success,
                last_failure=excluded.last_failure,
                tries=excluded.tries,
                success_count=excluded.success_count,
                avg_rtt=excluded.avg_rtt,
                avg_throughput=excluded.avg_throughput,
                score=excluded.score
        "#,
        )
        .bind(&stats.ip)
        .bind(stats.port)
        .bind(stats.last_success)
        .bind(stats.last_failure)
        .bind(stats.tries)
        .bind(stats.success_count)
        .bind(stats.avg_rtt)
        .bind(stats.avg_throughput)
        .bind(stats.score)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Fetch top N proxies ordered by score desc.
    pub async fn top(&self, limit: i64) -> sqlx::Result<Vec<ProxyStats>> {
        let rows = sqlx::query_as::<_, ProxyStats>(
            "SELECT ip, port, last_success, last_failure, tries, success_count, avg_rtt, avg_throughput, score FROM proxy_stats ORDER BY score DESC LIMIT ?"
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }
}
