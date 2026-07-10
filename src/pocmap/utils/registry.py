"""Generic plugin registry for extensible components.

Provides a type-safe way to register and discover plugins such as
exploit sources, lab platforms, or any other extensible component.

It also defines the :class:`ExploitSourcePlugin` contract that third-party
packages implement to contribute an exploit source (see
:mod:`pocmap.services.exploit_service` for discovery/aggregation).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Generic, Protocol, TypeVar, runtime_checkable

if TYPE_CHECKING:  # avoid a runtime import cycle; annotations are strings here.
    from pocmap.models import Exploit

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Third-party exploit-source plugin contract (PLUGIN-SOURCES)
# ---------------------------------------------------------------------------


@runtime_checkable
class ExploitSourcePlugin(Protocol):
    """Contract a third-party exploit source must satisfy.

    PocMap discovers external sources from the ``importlib.metadata`` entry-point
    group **``pocmap.exploit_sources``**. Each entry point resolves to either:

    * a **class** implementing this protocol (PocMap instantiates it with no
      arguments), or
    * a ready **instance/object** exposing the same surface.

    The only required member is :meth:`search`. A source *label* is derived, in
    order, from a ``source`` attribute (a plain string or an
    :class:`~pocmap.models.ExploitSource` enum), then a ``name`` attribute, and
    finally the entry-point's own name — so a minimal plugin need only implement
    ``search``. Results are contributed to
    :meth:`~pocmap.services.exploit_service.ExploitService.find_exploits` under
    the same per-source health (ERR-RESULT) contract as the built-in sources.

    Example::

        class MySource:
            name = "my-feed"

            def search(self, cve_id: str) -> list[Exploit]:
                return [Exploit(source=ExploitSource.OTHER, url=..., title=...)]

    Security
    --------
    Entry-point plugins execute **third-party code that the user chose to
    install** (via ``pip``). PocMap only *aggregates* their results: it calls the
    declared :meth:`search` and nothing else — it never auto-fetches, imports, or
    executes anything beyond that. A plugin that raises (including a bug in its
    own code) is isolated to a degraded ``ERROR`` status for that one source and
    can never crash the aggregate or the host process; a plugin returning
    non-:class:`~pocmap.models.Exploit` data is defensively discarded. Installing
    a plugin is a trust decision the operator makes, exactly like installing any
    other Python dependency.
    """

    def search(self, cve_id: str) -> list[Exploit]:
        """Return exploits for *cve_id* (an empty list when none are found)."""
        ...


class PluginRegistry(Generic[T]):
    """Generic plugin registry for extensible components.

    Plugins are registered by a unique string name and can be retrieved
    by name or listed. Registration can be used as a decorator.

    Example::

        registry = PluginRegistry[Callable[[str], list[Exploit]]]()

        @registry.register("github")
        def find_github_exploits(cve_id: str) -> list[Exploit]:
            ...

        plugin = registry.get("github")
        names = registry.list()       # ["github", ...]
        all_plugins = registry.all()  # {"github": <function>, ...}
    """

    def __init__(self) -> None:
        self._plugins: dict[str, T] = {}

    def register(self, name: str, plugin: T) -> T:
        """Register a plugin by name.

        Args:
            name: Unique identifier for the plugin.
            plugin: The plugin object to register.

        Returns:
            The registered plugin (for use as a decorator).

        Raises:
            ValueError: If *name* is already registered.
        """
        if name in self._plugins:
            raise ValueError(f"Plugin '{name}' is already registered")
        self._plugins[name] = plugin
        return plugin

    def get(self, name: str) -> T | None:
        """Retrieve a plugin by name.

        Args:
            name: The plugin identifier.

        Returns:
            The registered plugin, or *None* if not found.
        """
        return self._plugins.get(name)

    def list(self) -> list[str]:
        """Return a list of all registered plugin names."""
        return list(self._plugins.keys())

    def all(self) -> dict[str, T]:
        """Return a shallow copy of all registered plugins."""
        return dict(self._plugins)
