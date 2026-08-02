# Configuration

Configuration is loaded from environment variables (prefixed with `POCMAP_`) and an
optional `.env` file, discovered from the current directory upward. Source of truth:
`src/pocmap/config.py`.

```bash
# Create .env file
cat > .env << 'EOF'
GITHUB_API_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
POCMAP_HTTP_TIMEOUT=30
POCMAP_MAX_RETRIES=3
POCMAP_BACKOFF_FACTOR=1.5
POCMAP_THREAD_POOL_SIZE=10
POCMAP_LOG_LEVEL=INFO
POCMAP_CACHE_ENABLED=true
POCMAP_CACHE_TTL=3600
POCMAP_CACHE_MAX_MB=200
EOF
```

| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_API_TOKEN` | None | GitHub personal access token for higher rate limits |
| `NVD_API_KEY` | None | NVD API key for increased rate limits |
| `POCMAP_HTTP_TIMEOUT` | 30 | HTTP request timeout in seconds |
| `POCMAP_MAX_RETRIES` | 3 | Maximum retry attempts for failed requests |
| `POCMAP_BACKOFF_FACTOR` | 1.5 | Exponential backoff multiplier |
| `POCMAP_THREAD_POOL_SIZE` | 10 | Worker thread count for bulk operations |
| `POCMAP_LOG_LEVEL` | INFO | Logging verbosity (DEBUG, INFO, WARNING, ERROR) |
| `POCMAP_CACHE_ENABLED` | true | Enable the persistent HTTP response cache |
| `POCMAP_CACHE_DIR` | platform user cache | Directory for cached responses (see [Caching](cli.md#caching-offline-mode)) |
| `POCMAP_CACHE_TTL` | 3600 | Seconds a cached entry stays fresh |
| `POCMAP_CACHE_MAX_MB` | 200 | On-disk cache cap (MB) before LRU eviction |
| `POCMAP_OFFLINE` | false | Serve HTTP only from cache; a miss errors instead of hitting the network |
| `POCMAP_ALLOW_FETCH_POC_SOURCE` | false | Opt in to downloading PoC **source code** to disk (see [Verifying PoCs](verifying-pocs.md)) |
| `POCMAP_POC_SOURCE_DIR` | `<cache>/poc-source` | Where fetched PoC source is extracted |
| `POCMAP_POC_SOURCE_MAX_MB` | 100 | Per-repo cap, applied to download **and** extracted size |
| `POCMAP_POC_SOURCE_TOTAL_MAX_MB` | 1000 | Total on-disk cap for fetched sources |

Some settings also accept a `POCMAP_` prefix for API keys — trust `config.py` over
skill docs that use older names.

See also [Caching & offline mode](cli.md#caching-offline-mode) and the
[exit-code contract](cli.md#exit-code-contract).
