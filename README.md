# arti-hyper-connector

A lightweight HTTP connector that routes all traffic through an
`arti_client::TorClient`.

Intended to sit *under* a TLS layer (e.g. an `HttpsConnector`). It:
  1. Validates the URI (scheme + host)
  2. Derives host + port (defaults 80 / 443)
  3. Opens a Tor stream via `TorClient::connect_with_prefs`

No DNS resolution happens here: Tor handles hostname/onion resolution.

Error handling:
  - We expose a concrete `ConnectionError` (using `thiserror`) so callers
    can pattern-match failures (unsupported scheme, missing host, Tor error).
  - The error type is `Clone` by wrapping the underlying `arti_client::Error`
    in an `Arc`, similar to approaches used in other connector libraries.

Typical layering:

```rs,ignore
let tor = TorClient::create_bootstrapped(config).await?;
let mut tor_http = TorHttpConnector::new(tor.clone());
let mut prefs = StreamPrefs::new();
prefs.connect_to_onion_services(arti_client::config::BoolOrAuto::Explicit(true));
tor_http.set_stream_prefs(prefs);
// Wrap with TLS layer if desired.
```

We do not expose local/remote socket addresses (they are abstracted by Tor).
