use arti_client::{StreamPrefs, TorClient, config::TorClientConfigBuilder};
use arti_hyper_connector::TorHttpConnector;
use boring::{
    ssl::{ExtensionType, SslConnector, SslConnectorBuilder, SslCurve, SslMethod, SslVersion},
    x509::{X509, store::X509StoreBuilder},
};
use http::{HeaderMap, HeaderName, HeaderValue, Request};
use http_body_util::{BodyExt, Empty};
use hyper::{
    Priorities, PseudoOrder, SettingsOrder, StreamDependency,
    body::Bytes,
    h2::frame::{Priority, PseudoId, SettingId, StreamId},
};
use hyper_boring::v1::HttpsConnector;
use hyper_util::rt::TokioExecutor;
use tracing::level_filters::LevelFilter;

const TEST_URL: &str = "https://tls.peet.ws/api/all";

macro_rules! join {
    ($sep:expr, $first:expr $(, $rest:expr)*) => {
        concat!($first $(, $sep, $rest)*)
    };
}

/* ============================= Entry ============================= */

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::DEBUG)
        .init();

    let url_string = std::env::args()
        .nth(1)
        .unwrap_or_else(|| TEST_URL.to_string());
    let url = url_string.parse::<hyper::Uri>().unwrap();

    // let mut headers = build_headers(url.host().expect("uri has no host"));

    let mut config_builder = TorClientConfigBuilder::default();

    // Configure the address filters so that we only allow onion addresses to be queried.
    config_builder
        .address_filter()
        .allow_onion_addrs(true)
        .allow_local_addrs(false);

    let config = config_builder.build()?;

    let tor_client = TorClient::create_bootstrapped(config).await?;

    let mut s_prefs = StreamPrefs::new();
    s_prefs.connect_to_onion_services(arti_client::config::BoolOrAuto::Explicit(true));

    let mut tor_connector = TorHttpConnector::new(tor_client);
    tor_connector.set_stream_prefs(s_prefs);

    let ssl = build_ssl_connector().unwrap();

    let mut https_tor = HttpsConnector::with_connector(tor_connector, ssl)
        .expect("Can construct https connection over Arti");

    https_tor.set_callback(|config, _| {
        config.set_verify_hostname(true);
        config.set_use_server_name_indication(true);
        // config.set_verify(SslVerifyMode::NONE);
        // config.set_options(SslOptions::NO_PSK_DHE_KE).unwrap();
        // config.set_options(SslOptions::NO_TICKET).unwrap();
        Ok(())
    });

    let headers_pseudo_order = PseudoOrder::builder()
        .extend([
            PseudoId::Method,
            PseudoId::Path,
            PseudoId::Scheme,
            PseudoId::Authority,
        ])
        .build();

    let settings_order = SettingsOrder::builder()
        .extend([
            SettingId::HeaderTableSize,
            SettingId::EnablePush,
            SettingId::MaxConcurrentStreams,
            SettingId::InitialWindowSize,
            SettingId::MaxFrameSize,
            SettingId::MaxHeaderListSize,
            SettingId::EnableConnectProtocol,
            SettingId::NoRfc7540Priorities,
        ])
        .build();

    let priorities = Priorities::builder()
        .extend([
            Priority::new(
                StreamId::from(3),
                StreamDependency::new(StreamId::zero(), 200, false),
            ),
            Priority::new(
                StreamId::from(5),
                StreamDependency::new(StreamId::zero(), 100, false),
            ),
            Priority::new(
                StreamId::from(7),
                StreamDependency::new(StreamId::zero(), 0, false),
            ),
            Priority::new(
                StreamId::from(9),
                StreamDependency::new(StreamId::from(7), 0, false),
            ),
            Priority::new(
                StreamId::from(11),
                StreamDependency::new(StreamId::from(3), 0, false),
            ),
            Priority::new(
                StreamId::from(13),
                StreamDependency::new(StreamId::zero(), 240, false),
            ),
        ])
        .build();

    let client = hyper_util::client::legacy::Client::builder(TokioExecutor::new())
        .http2_initial_stream_id(15)
        .http2_header_table_size(65536)
        .http2_priorities(Some(priorities))
        .http2_headers_stream_dependency(Some(StreamDependency::new(StreamId::from(13), 41, false)))
        .http2_adaptive_window(false)
        .http2_initial_max_send_streams(100)
        .http2_max_send_buf_size(1024 * 1024)
        .http2_keep_alive_while_idle(false)
        .http2_initial_stream_window_size(131072)
        .http2_max_frame_size(16384)
        .http2_initial_connection_window_size(12517377 + 65535)
        .http2_headers_pseudo_order(Some(headers_pseudo_order))
        .http2_settings_order(Some(settings_order))
        .build::<_, Empty<Bytes>>(https_tor);

    let headers = build_headers(url.authority().expect("uri has no host").as_str());

    let mut req = Request::get(url).body(Empty::<Bytes>::new())?;

    *req.headers_mut() = headers.clone(); // preserve caller copy if needed

    let res = client.request(req).await?;

    let body_bytes = res.into_body().collect().await?.to_bytes();
    let text = std::str::from_utf8(&body_bytes)?;
    tracing::info!("\n{}", text);

    Ok(())
}

/* ============================= Builders (retain original customizations) ============================= */

fn build_ssl_connector() -> anyhow::Result<SslConnectorBuilder> {
    let mut ssl = SslConnector::builder(SslMethod::tls())?;

    ssl.set_key_shares_limit(2);

    ssl.set_curves(&[
        SslCurve::X25519,
        SslCurve::SECP256R1,
        SslCurve::SECP384R1,
        SslCurve::SECP521R1,
        SslCurve::FFDHE2048,
        SslCurve::FFDHE3072,
    ])?;

    ssl.set_cipher_list(join!(
        ":",
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_256_CBC_SHA"
    ))?;

    ssl.set_sigalgs_list(join!(
        ":",
        "ecdsa_secp256r1_sha256",
        "ecdsa_secp384r1_sha384",
        "ecdsa_secp521r1_sha512",
        "rsa_pss_rsae_sha256",
        "rsa_pss_rsae_sha384",
        "rsa_pss_rsae_sha512",
        "rsa_pkcs1_sha256",
        "rsa_pkcs1_sha384",
        "rsa_pkcs1_sha512",
        "ecdsa_sha1",
        "rsa_pkcs1_sha1"
    ))?;

    ssl.set_delegated_credentials(join!(
        ":",
        "ecdsa_secp256r1_sha256",
        "ecdsa_secp384r1_sha384",
        "ecdsa_secp521r1_sha512",
        "ecdsa_sha1"
    ))?;

    ssl.set_alpn_protos(b"\x02h2\x08http/1.1")?;

    ssl.set_min_proto_version(Some(SslVersion::TLS1_1)).unwrap();
    ssl.set_max_proto_version(Some(SslVersion::TLS1_3)).unwrap();

    ssl.set_extension_permutation(&[
        ExtensionType::SERVER_NAME,
        ExtensionType::EXTENDED_MASTER_SECRET,
        ExtensionType::RENEGOTIATE,
        ExtensionType::SUPPORTED_GROUPS,
        ExtensionType::EC_POINT_FORMATS,
        ExtensionType::SESSION_TICKET,
        ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
        ExtensionType::STATUS_REQUEST,
        ExtensionType::DELEGATED_CREDENTIAL,
        ExtensionType::CERTIFICATE_TIMESTAMP,
        ExtensionType::KEY_SHARE,
        ExtensionType::SUPPORTED_VERSIONS,
        ExtensionType::SIGNATURE_ALGORITHMS,
        ExtensionType::PSK_KEY_EXCHANGE_MODES,
        ExtensionType::RECORD_SIZE_LIMIT,
        ExtensionType::CERT_COMPRESSION,
        ExtensionType::ENCRYPTED_CLIENT_HELLO,
    ])?;

    ssl.set_prefer_chacha20(true);
    ssl.set_aes_hw_override(true);

    ssl.set_record_size_limit(0x4001);

    // ssl.set_grease_enabled(false);

    ssl.enable_ocsp_stapling();
    // ssl.enable_signed_cert_timestamps();

    // configure certs
    let mut x509store = X509StoreBuilder::new()?;

    webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .flat_map(|c| X509::from_der(AsRef::<[u8]>::as_ref(&c)))
        .for_each(|x509| x509store.add_cert(x509).unwrap());

    ssl.set_cert_store_builder(x509store);

    Ok(ssl)
}

fn build_headers(host: &str) -> HeaderMap<HeaderValue> {
    let mut headers = HeaderMap::new();

    headers.insert(
        HeaderName::from_static("te"),
        HeaderValue::from_static("trailers"),
    );

    headers.insert(
        "USER-AGENT",
        HeaderValue::from_static(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_17; rv:109.0) Gecko/20000101 Firefox/109.0",
        ),
    );

    headers.insert(
        http::header::ACCEPT,
        HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    );

    headers.insert(
        "ACCEPT-ENCODING",
        HeaderValue::from_static("gzip, deflate, br"),
    );

    headers.insert(
        "ACCEPT-LANGUAGE",
        HeaderValue::from_static("en-US,en;q=0.9"),
    );

    headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
    headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
    headers.insert("sec-fetch-site", HeaderValue::from_static("none"));

    headers.insert(http::header::HOST, HeaderValue::from_str(host).unwrap());
    headers
}
