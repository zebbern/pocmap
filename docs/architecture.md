# Architecture

```text
+------------------+     +------------------+     +------------------+
|     CLI Layer    |     |   MCP Server     |     |   Python API     |
|   (Typer/Rich)   |     |  (MCP SDK / 22   |     |   (Services)     |
+------------------+     |     Tools)       |     +------------------+
         |               +------------------+             |
         |                         |                      |
         +-------------------------+----------------------+
                                   |
                    +------------------------------+
                    |        Service Layer         |
                    |  CVE / Exploit / Lab / BB /  |
                    |  Recent / Product / Package  |
                    +------------------------------+
                                   |
                    +------------------------------+
                    |     Clients + HTTP utils     |
                    |  (SSRF guard, cache, retry)  |
                    +------------------------------+
```

## Package layout (`src/pocmap/`)

| Path | Role |
|------|------|
| `cli.py` | Typer CLI |
| `mcp/` | MCP implementation (tools, resources, prompts, adapter) |
| `mcp_server.py` | Stable import / `pocmap-mcp` facade over `pocmap.mcp` |
| `services/` | Business logic |
| `clients/` | Upstream HTTP clients |
| `models.py` | Pydantic models + `export_schemas()` |
| `bugbounty/` | Hunter toolkit (Python API + playbook JSON) |
| `utils/` | HTTP, validators, renderers, paths |
| `config.py` | Frozen `Settings` singleton |

Repo-root `mcp_server.py` is a thin launcher that puts `src/` on `sys.path` for
uninstalled clones.
