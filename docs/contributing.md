# Contributing

## Adding new exploit sources (in-tree)

New exploit sources can be registered via the plugin pattern:

1. Create a new client in `src/pocmap/clients/`:
```python
# src/pocmap/clients/my_source_client.py
from pocmap.models import Exploit, ExploitSource

class MySourceClient:
    """Client for My Exploit Source."""

    SOURCE = ExploitSource.OTHER  # or add to enum

    def search(self, cve_id: str) -> list[Exploit]:
        # Implement search logic
        return []
```

2. Integrate into `ExploitService` in `src/pocmap/services/exploit_service.py`:
```python
from pocmap.clients.my_source_client import MySourceClient

class ExploitService:
    def __init__(self):
        self._my_source = MySourceClient()

    def find_exploits(self, cve_id: str) -> list[Exploit]:
        exploits = []
        exploits.extend(self._my_source.search(cve_id))
        # ... existing sources
        return exploits
```

3. Add tests and documentation.

## Third-party exploit sources (no fork)

External packages can add exploit sources **without modifying pocmap** by registering an
entry point in the `pocmap.exploit_sources` group. A source is any object exposing
`search(cve_id: str) -> list[Exploit]` (the `ExploitSourcePlugin` protocol):

```toml
# your package's pyproject.toml
[project.entry-points."pocmap.exploit_sources"]
my-source = "my_pkg.source:MySource"
```

```python
# my_pkg/source.py
from pocmap.models import Exploit, ExploitSource

class MySource:
    source = "my-source"

    def search(self, cve_id: str) -> list[Exploit]:
        return [Exploit(source=ExploitSource.OTHER, url="https://…", title="…")]
```

`pip install` your package and its results appear in `pocmap lookup` and
`ExploitService.find_exploits`. Plugins are **error-isolated**: a failing plugin
degrades to `FetchStatus.ERROR` (via `find_exploits_with_status`) without affecting
built-in sources. Runnable example:
[`examples/example-exploit-source/`](https://github.com/zebbern/pocmap/tree/main/examples/example-exploit-source/).
Entry-point plugins execute third-party code you chose to install — pocmap only calls
`search()` and aggregates results with per-source status isolation.

## Development setup

```bash
git clone https://github.com/zebbern/pocmap.git
cd pocmap
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,docs]"

# Run tests
pytest -v

# Run type checker
mypy src/pocmap

# Run linter
ruff check src/pocmap

# Build docs
python scripts/generate_mcp_docs.py
mkdocs build --strict
```
