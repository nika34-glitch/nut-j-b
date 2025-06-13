use tokio::{fs::File, io::{AsyncReadExt, BufReader}};
use futures::stream::{self, Stream};
use reqwest::Client;
use std::{io, path::Path};

/// Read proxies from file or URL as stream of lines.
pub async fn read_feed(path: &str) -> io::Result<impl Stream<Item = String>> {
    if path.starts_with("http") {
        let body = Client::new().get(path).send().await.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?.text().await.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let lines = body.lines().map(|s| s.trim().to_string()).filter(|l| !l.is_empty()).collect::<Vec<_>>();
        Ok(stream::iter(lines))
    } else {
        let file = File::open(Path::new(path)).await?;
        let mut reader = BufReader::new(file);
        let mut buf = String::new();
        reader.read_to_string(&mut buf).await?;
        let lines = buf.lines().map(|s| s.trim().to_string()).filter(|l| !l.is_empty()).collect::<Vec<_>>();
        Ok(stream::iter(lines))
    }
}
