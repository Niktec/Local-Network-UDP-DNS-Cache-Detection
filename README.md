# Local Network UDP DNS Cache Detection

A small Windows tool that checks whether your router or network answers plain DNS (UDP port 53) from a local cache instead of forwarding it to the real resolver.

It is a single file: **`CacheCheck.bat`**. Download it and double-click it. No installation needed.

## Preview

| Cache detected | No cache detected |
|---|---|
| <img src="Cache%20detected.png" width="480"> | <img src="No%20cache%20detected.png" width="480"> |

## How it works

The tool measures how fast a public resolver (Cloudflare, Google or Quad9) answers, using several different paths:

| Measurement | What it is |
|---|---|
| **UDP** (baseline) | A normal DNS query to the resolver on port 53, the path a local cache can intercept |
| **Ping (TCP 443)** | Time to open a TCP connection to the resolver |
| **DoT** | A DNS query over TLS (port 853), which a local cache on port 53 cannot answer |
| **UDP random subdomain** | A query for a random name like `u7k2x9q1m4a.example.com`, which can never be in a cache |

If the plain UDP answer is much faster than the references, something nearby is answering it. Each reference votes `cache` or `no cache`:

- Ping and DoT: UDP must be under 70% of the reference time and at least 2 ms faster.
- UDP random subdomain: UDP must be under 45% of the reference time and at least 4 ms faster.

More than half of the votes decide the result: **Cache detected**, **No cache detected** or **Inconclusive**. A reference that fails gives no vote.

## Usage

1. Download `CacheCheck.bat`.
2. Double-click it. A window opens.
3. Pick a resolver, optionally change the domain and the number of queries, and click **Start**.

You can also run it in the console with `CacheCheck.bat -NoGui`.

## Requirements

- Windows 10 or 11 with the built-in Windows PowerShell 5.1
- Network access to the resolver on UDP 53, TCP 443 and TCP 853

## Notes

- The result is a timing-based estimate, not proof. A fast local network or a very close resolver can look similar to a cache.
- Results can vary between runs. Run it a few times if the verdict is close.
