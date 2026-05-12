# cloudip-db

[![Build CloudIP Data](https://github.com/rezmoss/cloudip-db/actions/workflows/build.yml/badge.svg)](https://github.com/rezmoss/cloudip-db/actions/workflows/build.yml)
[![Latest Release](https://img.shields.io/github/v/release/rezmoss/cloudip-db?label=data%20version)](https://github.com/rezmoss/cloudip-db/releases/latest)
[![Last Updated](https://img.shields.io/github/last-commit/rezmoss/cloudip-db?label=updated)](https://github.com/rezmoss/cloudip-db/commits/main)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**A tiny, daily-updated, MessagePack-encoded database of cloud-provider IP ranges — purpose-built for fast client libraries.**

`cloudip-db` is the compiled, compressed binary form of [rezmoss/cloud-provider-ip-addresses](https://github.com/rezmoss/cloud-provider-ip-addresses). It packs every CIDR block from the major cloud providers into a single ~**743 KB gzipped** [MessagePack](https://msgpack.org/) file that client libraries — like [go-cloudip](https://github.com/rezmoss/go-cloudip) and [js-cloudip](https://github.com/rezmoss/js-cloudip) — can download once and use offline for sub-microsecond IP-to-provider lookups.

> Source data (rich JSON, per provider) → **cloudip-db** (compact binary) → client libraries (Go, JS, …)

## What's inside

| File | Description |
|------|-------------|
| [`data/cloudip.msgpack`](data/cloudip.msgpack) | Uncompressed MessagePack database (~6.5 MB) |
| [`data/cloudip.msgpack.gz`](data/cloudip.msgpack.gz) | Gzipped MessagePack database (~743 KB) — recommended for downloads |
| [`data/version.json`](data/version.json) | Version metadata: build date, range count, SHA-256, sizes |

### Current stats

> See [`data/version.json`](data/version.json) for the live numbers — typically **120,000+ CIDR ranges** across **6 providers**, rebuilt every day.

### Providers covered

- **AWS** (Amazon Web Services)
- **GCP** (Google Cloud Platform)
- **Azure** (Microsoft)
- **Cloudflare**
- **DigitalOcean**
- **Oracle Cloud**

Need more providers (Fastly, GitHub, Linode, bot crawlers, …)? The full firehose with 22+ providers and 12+ output formats lives in the upstream [cloud-provider-ip-addresses](https://github.com/rezmoss/cloud-provider-ip-addresses) repo.

## Why a separate repo?

The upstream [cloud-provider-ip-addresses](https://github.com/rezmoss/cloud-provider-ip-addresses) repo is optimized for **humans and ops tooling**: per-provider JSON/CSV/SQL, ready-to-paste Nginx/Apache/iptables/nftables/UFW/HAProxy/Caddy configs, and a daily changelog.

`cloudip-db` is optimized for **client libraries**:

- **One file, one fetch.** No per-provider HTTP requests, no format negotiation.
- **Compact binary format.** MessagePack with short field names (`p`, `r`, `s`) keeps the gzipped payload under 1 MB.
- **Verifiable.** Every build publishes a SHA-256 in `version.json` so clients can detect corruption or tampering.
- **Versioned releases.** Each daily build is tagged `vYYYY-MM-DD` with a GitHub Release — pin to a version or always grab `latest`.
- **CDN-friendly.** Raw GitHub URLs are immutable per-commit, perfect for caching.

## Download

Latest data (always-current, served from `main`):

```
https://github.com/rezmoss/cloudip-db/raw/main/data/cloudip.msgpack.gz
https://github.com/rezmoss/cloudip-db/raw/main/data/version.json
```

Pinned release (immutable):

```
https://github.com/rezmoss/cloudip-db/releases/download/v2026-05-12/cloudip.msgpack.gz
```

## Schema

The MessagePack file decodes to:

```jsonc
{
  "version":     "2026-05-12",          // ISO date of the build
  "build_time":  1778548431,            // Unix timestamp
  "providers":   ["aws", "gcp", "cloudflare", "azure", "digitalocean", "oracle"],
  "ranges": [
    {
      "cidr": "52.94.76.0/22",          // IPv4 or IPv6 CIDR
      "p":    0,                        // Provider index into `providers`
      "r":    "us-east-1",              // Region (optional)
      "s":    "EC2"                     // Service (optional)
    },
    // …
  ]
}
```

Field names are intentionally short (`p`, `r`, `s`) to minimize on-wire size.

`version.json` has its own small schema:

```json
{
  "version":   "2026-05-12",
  "build_time": 1778548431,
  "sha256":    "b712e66bb16d3da4e9347a67829444343471fedef23882f3e5c182a5e1a92e19",
  "ranges":    121392,
  "size":      6552383,
  "size_gzip": 743009
}
```

Clients typically:
1. Fetch `version.json` to check `version` + `sha256`.
2. Download `cloudip.msgpack.gz` only if changed.
3. Verify SHA-256, decompress, parse, build a trie.

## Use it from your code

### Go — [`go-cloudip`](https://github.com/rezmoss/go-cloudip)

```bash
go get github.com/rezmoss/go-cloudip
```

```go
import "github.com/rezmoss/go-cloudip"

if cloudip.IsAWS("52.94.76.1") {
    // …
}
```

### JavaScript / TypeScript — [`js-cloudip`](https://github.com/rezmoss/js-cloudip)

```bash
npm install js-cloudip
```

```ts
import { isAws, getProvider, lookup } from 'js-cloudip';

await isAws('52.94.76.1');        // true
await getProvider('34.64.0.1');   // "gcp"
```

Both libraries embed a fallback copy of `cloudip-db` for offline / air-gapped use and refresh from this repo in the background.

### Roll your own client

Any MessagePack library will do. Example in Python:

```python
import gzip, urllib.request, msgpack

url = "https://github.com/rezmoss/cloudip-db/raw/main/data/cloudip.msgpack.gz"
with urllib.request.urlopen(url) as r:
    db = msgpack.unpackb(gzip.decompress(r.read()), raw=False)

print(db["version"], len(db["ranges"]), "ranges")
```

## How the build works

[`scripts/build.go`](scripts/build.go) is a small Go program that:

1. Fetches the per-provider JSON files from [cloud-provider-ip-addresses](https://github.com/rezmoss/cloud-provider-ip-addresses).
2. Normalizes them into a single `Range` schema (CIDR + provider index + optional region/service).
3. Sorts ranges deterministically (so daily diffs stay clean).
4. Encodes to MessagePack, gzips, and writes `version.json` with SHA-256 + sizes.

[`.github/workflows/build.yml`](.github/workflows/build.yml) runs this every day at **00:30 UTC** (30 minutes after upstream updates), commits any changes, tags `vYYYY-MM-DD`, and publishes a GitHub Release with the three data files attached.

To rebuild locally:

```bash
cd scripts
go mod download
go run build.go ../data
```

## Update cadence

- **Daily** at 00:30 UTC via GitHub Actions.
- A new tag + release is created only when the data actually changes.
- Clients should poll `version.json` (a few hundred bytes) to decide whether to re-download the full blob.

## Versioning

Tags follow `vYYYY-MM-DD` (the build date). There is no SemVer here — the *schema* is stable, and the *data* changes every day. If the schema ever changes in a breaking way, the change will be announced in a release note and a `schema_version` field will be added.

## Contributing

This repo only contains the build script and generated artifacts. **Open issues and PRs against the upstream data repo:** [rezmoss/cloud-provider-ip-addresses](https://github.com/rezmoss/cloud-provider-ip-addresses).

Bug reports about the build script, schema, or client integration are welcome here.

## Related projects

- [**cloud-provider-ip-addresses**](https://github.com/rezmoss/cloud-provider-ip-addresses) — upstream daily data, 22+ providers, 12+ formats (JSON/CSV/SQL/Nginx/iptables/…)
- [**go-cloudip**](https://github.com/rezmoss/go-cloudip) — Go client, sub-microsecond lookups via Patricia trie
- [**js-cloudip**](https://github.com/rezmoss/js-cloudip) — JS/TS client for Node and the browser

## License

MIT — see [LICENSE](LICENSE). Upstream provider data is published under each provider's own terms; this repo only redistributes publicly available IP-range information.
