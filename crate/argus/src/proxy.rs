use std::{
    net::{Shutdown, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::cert_util;
use anyhow::*;
use async_h1::{client as h1_client, server as h1_server};
use async_native_tls::{TlsAcceptor, TlsConnector, TlsStream};
use async_std::io::{copy, prelude::*, Cursor};
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task;
use async_tls::{client::TlsStream as ClientTlsStream, server::TlsStream as ServerTlsStream};
use futures::{future::BoxFuture, prelude::*};
use http_types::{Method, Request, Response, StatusCode, Url};
use openssl::{
    pkey::{PKey, Private},
    x509::X509,
};
use rustls::{ClientConfig, NoClientAuth, ServerConfig};
pub struct Server {
    pub addr: SocketAddr,
    pub container: cert_util::CAContainer,
    pub edit_request: fn(Request) -> BoxFuture<'static, Result<Request>>,
    pub edit_response: fn((Request, Response)) -> BoxFuture<'static, Result<Response>>,
}

async fn ident_request(input: Request) -> Result<Request> {
    Ok(input)
}
async fn ident_response(req: Request, res: Response) -> Result<Response> {
    Ok(res)
}

impl Server {
    pub fn new(addr: SocketAddr, container: cert_util::CAContainer) -> Self {
        Server {
            addr,
            container,
            edit_request: |r| ident_request(r).boxed(),
            edit_response: |(r, rr)| ident_response(r, rr).boxed(),
        }
    }

    pub async fn start(self) -> Result<()> {
        let listener = TcpListener::bind(&self.addr).await?;
        let server = Arc::new(self);
        loop {
            let (stream, _peer_addr) = listener.accept().await?;
            let s = server.clone();
            task::spawn(async move {
                match handle_conn(s, stream).await {
                    Ok(()) => {}
                    Err(e) => {
                        dbg!(e);
                    }
                }
            });
        }
    }

    pub fn req_handler(&mut self, f: fn(Request) -> BoxFuture<'static, Result<Request>>) {
        self.edit_request = f;
    }

    pub fn res_handler(&mut self, f: fn((Request, Response)) -> BoxFuture<'static, Result<Response>>) {
        self.edit_response = f;
    }
}

pub fn make_server_config(cert: &X509, key: &PKey<Private>) -> Result<ServerConfig> {
    let (cert, mut key) = cert_util::convert_to_rustls(cert, key)?;
    let mut server_config = ServerConfig::new(NoClientAuth::new());
    server_config.set_single_cert(cert, key.remove(0))?;
    Ok(server_config)
}

async fn handle_conn(server: Arc<Server>, client_stream: TcpStream) -> Result<()> {
    let req = read_request(client_stream.clone()).await?;

    match req.method() {
        Method::Connect => {
            let (client_stream, target_stream) =
                handle_handshake(&server.container, req.url(), client_stream).await?;
            handle_finalize(server, client_stream, target_stream).await?;
            return Ok(());
        }
        _ => {
            let addr = req.url().socket_addrs(|| Some(80)).unwrap()[0];
            let target_stream = TcpStream::connect(&addr).await?;
            handle_finalize(server.clone(), client_stream.clone(), target_stream).await?;
            return Ok(());
        }
    }
}

async fn handle_handshake(
    container: &cert_util::CAContainer,
    url: &Url,
    mut client_stream: TcpStream,
) -> Result<(
    async_dup::Arc<async_dup::Mutex<ServerTlsStream<TcpStream>>>,
    async_dup::Arc<async_dup::Mutex<ClientTlsStream<TcpStream>>>,
)> {
    let socket_addr = url.socket_addrs(|| Some(80))?;
    let host_str = url.host_str().unwrap();

    let target_server = TcpStream::connect(socket_addr.as_slice()).await?;
    let target_stream = TlsConnector::new().connect(host_str, target_server).await?;

    target_stream.get_ref().shutdown(Shutdown::Both)?;

    let target_server = TcpStream::connect(socket_addr.as_slice()).await?;
    let mut client_config = ClientConfig::new();
    client_config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    let connector = async_tls::TlsConnector::from(Arc::new(client_config));
    let target_tls_stream = connector.connect(host_str, target_server).await?;

    // to finish CONNECT handshake
    WriteExt::write_all(&mut client_stream, b"HTTP/1.1 200 OK\r\n\r\n").await?;

    let server_config = match target_stream.peer_certificate()? {
        Some(cert) => {
            let cert = openssl::x509::X509::from_der(&cert.to_der()?)?;
            let spoofed = cert_util::spoof_certificate(&cert, container)?;
            make_server_config(&spoofed, &container.key)?
        }
        None => make_server_config(&container.cert, &container.key)?,
    };

    let acceptor = async_tls::TlsAcceptor::from(Arc::new(server_config));
    let client_tls_stream = acceptor.accept(client_stream).await?;

    let (client_stream, target_stream) = (
        async_dup::Arc::new(async_dup::Mutex::new(client_tls_stream)),
        async_dup::Arc::new(async_dup::Mutex::new(target_tls_stream)),
    );

    Ok((client_stream, target_stream))
}

async fn handle_finalize(
    server: Arc<Server>,
    client_stream: impl Read + Write + Clone + Send + Sync + Unpin + 'static,
    target_stream: impl Read + Write + Clone + Send + Sync + Unpin + 'static,
) -> Result<()> {
    async_h1::accept(client_stream.clone(), |req| async {
        let req = (server.edit_request)(req).await?;
        let res = async_h1::connect(target_stream.clone(), req.clone()).await?;
        Ok((server.edit_response)((req, res)).await?)
    })
    .map_err(Error::msg)
    .await?;

    Ok(())
}

async fn read_request(
    client_stream: impl Read + Write + Clone + Send + Sync + Unpin + 'static,
) -> Result<Request> {
    let res = match h1_server::decode(client_stream).await {
        Ok(decorded) => match decorded {
            Some(r) => r,
            None => {
                bail!("")
            }
        },
        Err(e) => {
            dbg!(&e);
            bail!("{}", e)
        }
    };
    Ok(res.0)
}
