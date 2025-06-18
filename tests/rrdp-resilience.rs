#[cfg(feature = "rrdp")]
#[cfg(feature = "repository")]
#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::io;
    use http_body_util::Full;
    use hyper::body::Bytes;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;
    use rpki::rrdp::NotificationFile;

    async fn serve(
        test_bytes: &'static[u8],
        _: Request<hyper::body::Incoming>
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let body = Full::new(Bytes::from_static(test_bytes));

        Ok(Response::builder()
            .header("Content-Encoding", "gzip")
            .body(body)
            .unwrap())
    }

    async fn run(test_bytes: &'static[u8]) -> 
        Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let port = match listener.local_addr() {
            Ok(addr)    => addr.port(),
            _                       => panic!("Could not bind to port")
        };

        let handle = tokio::task::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);

            let _ = http1::Builder::new()
                .serve_connection(io, service_fn(|req| serve(test_bytes, req)))
                .await;
        });

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        let handle2 = tokio::task::spawn_blocking(
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let client = reqwest::blocking::Client::builder()
                .gzip(true)
                .build()?;
            let r = client.get(format!("http://127.0.0.1:{:?}/", port)).send()?;
            
            let reader = io::BufReader::new(r);
            let p = NotificationFile::parse(reader);
            assert!(p.is_err());
            Ok(())
        });

        let _ = handle.await;
        let _ = handle2.await;
        Ok(())
    }

    #[tokio::test]
    async fn test_serial() {
        let bytes = include_bytes!("../test-data/rrdp/bomb-serial.xml.gz");
        assert!(run(bytes).await.is_ok());
    }

    #[tokio::test]
    async fn test_snapshot_uri() {
        let bytes = include_bytes!(
            "../test-data/rrdp/bomb-snapshot-uri.xml.gz"
        );
        assert!(run(bytes).await.is_ok());
    }

    #[tokio::test]
    async fn test_whitespace() {
        let bytes = include_bytes!("../test-data/rrdp/bomb-whitespace.xml.gz");
        assert!(run(bytes).await.is_ok());
    }
}
