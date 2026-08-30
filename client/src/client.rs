/* -------------------------------------------------------------------------- *\
 *                |   █████╗ ██╗   ██╗██████╗  █████╗ ███████╗ |              *
 *                |  ██╔══██╗██║   ██║██╔══██╗██╔══██╗██╔════╝ |              *
 *                |  ███████║██║   ██║██████╔╝███████║█████╗   |              *
 *                |  ██╔══██║██║   ██║██╔══██╗██╔══██║██╔══╝   |              *
 *                |  ██║  ██║╚██████╔╝██║  ██║██║  ██║███████╗ |              *
 *                |  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ |              *
 *                +--------------------------------------------+              *
 *                                                                            *
 *                         Distributed Systems Runtime                        *
 * -------------------------------------------------------------------------- *
 * Copyright 2022 - 2024, the aurae contributors                              *
 * SPDX-License-Identifier: Apache-2.0                                        *
\* -------------------------------------------------------------------------- */

//! An internally scoped rust client specific for Auraed & AuraeScript.
//!
//! Manages authenticating with remote Aurae instances, as well as searching
//! the local filesystem for configuration and authentication material.

use crate::AuraeSocket;
use crate::config::{AuraeConfig, CertMaterial, ClientCertDetails};
use hyper_util::rt::TokioIo;
use std::fmt;
use thiserror::Error;
use tokio::net::{TcpStream, UnixStream};
use tonic::metadata::AsciiMetadataValue;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity, Uri};
use tower::service_fn;

const KNOWN_IGNORED_SOCKET_ADDR: &str = "hxxp://null";
const KNOWN_IGNORED_TLS_SOCKET_ADDR: &str = "https://null";
pub(crate) const VM_CONTROL_TOKEN_HEADER: &str = "x-aurae-vm-control";

type Result<T> = std::result::Result<T, ClientError>;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error(transparent)]
    ConnectionError(#[from] tonic::transport::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Instance of a single client for an Aurae consumer.
#[derive(Clone)]
pub struct Client {
    /// The channel used for gRPC connections before encryption is handled.
    pub(crate) channel: Channel,
    #[allow(unused)]
    client_cert_details: Option<ClientCertDetails>,
    /// Present only on the private host-to-cell VmService path.
    pub(crate) vm_control_token: Option<AsciiMetadataValue>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("channel", &self.channel)
            .field("client_cert_details", &self.client_cert_details)
            .field("has_vm_control_token", &self.vm_control_token.is_some())
            .finish()
    }
}

impl Client {
    pub async fn default() -> Result<Self> {
        Self::new(AuraeConfig::try_default()?).await
    }

    /// Create a new Client.
    ///
    /// Note: A new client is required for every independent execution of this process.
    pub async fn new(
        AuraeConfig { auth, system }: AuraeConfig,
    ) -> Result<Self> {
        let cert_material = auth.to_cert_material().await?;
        let client_cert_details =
            Some(cert_material.get_client_cert_details()?);

        let CertMaterial { server_root_ca_cert, client_cert, client_key } =
            cert_material;

        let tls_config = ClientTlsConfig::new()
            // TODO: get this from the config or the cert information somehow
            .domain_name("server.unsafe.aurae.io")
            .ca_certificate(Certificate::from_pem(server_root_ca_cert))
            .identity(Identity::from_pem(client_cert, client_key));

        let channel =
            Self::connect_chan(system.socket.clone(), Some(tls_config)).await?;
        Ok(Self { channel, client_cert_details, vm_control_token: None })
    }

    /// Create a new Client without TLS, remote server should also expect no TLS.
    ///
    /// Note: A new client is required for every independent execution of this process.
    pub async fn new_no_tls(socket: AuraeSocket) -> Result<Self> {
        let channel = Self::connect_chan(socket, None).await?;
        let client_cert_details = None;
        Ok(Self { channel, client_cert_details, vm_control_token: None })
    }

    /// Create a no-TLS client carrying the capability required by the
    /// VmService of a nested auraed. The token is never included in `Debug`.
    pub async fn new_no_tls_with_vm_control_token(
        socket: AuraeSocket,
        token: &str,
    ) -> Result<Self> {
        let mut client = Self::new_no_tls(socket).await?;
        client.vm_control_token = Some(token.parse().map_err(|e| {
            anyhow::anyhow!("invalid VM control token metadata: {e}")
        })?);
        Ok(client)
    }

    async fn connect_chan(
        socket: AuraeSocket,
        tls_config: Option<ClientTlsConfig>,
    ) -> Result<Channel> {
        let endpoint = match tls_config {
            None => Channel::from_static(KNOWN_IGNORED_SOCKET_ADDR),
            Some(tls_config) => {
                Channel::from_static(KNOWN_IGNORED_TLS_SOCKET_ADDR)
                    .tls_config(tls_config)?
            }
        };

        // If the system socket looks like a SocketAddr, bind to it directly.  Otherwise,
        // connect as a UNIX socket (assume it's a file path).
        let channel = match socket {
            AuraeSocket::Path(path) => {
                endpoint
                    .connect_with_connector(service_fn({
                        move |_: Uri| {
                            let path = path.clone();
                            async move {
                                Ok::<_, std::io::Error>(TokioIo::new(
                                    UnixStream::connect(path).await?,
                                ))
                            }
                        }
                    }))
                    .await
            }
            AuraeSocket::Addr(addr) => {
                endpoint
                    .connect_with_connector(service_fn({
                        move |_: Uri| async move {
                            Ok::<_, std::io::Error>(TokioIo::new(
                                TcpStream::connect(addr).await?,
                            ))
                        }
                    }))
                    .await
            }
        }?;

        Ok(channel)
    }
}
