# arti-hyper-connector

A lightweight HTTP connector that routes all traffic through an
`arti_client::TorClient`.

No DNS resolution happens here: Tor handles hostname/onion resolution.

We do not expose local/remote socket addresses (they are abstracted by Tor).
