"""Generic plugin registry for extensible components.

Provides a type-safe way to register and discover plugins such as
exploit sources, lab platforms, or any other extensible component.
"""

from __future__ import annotations

from typing import Generic, TypeVar

T = TypeVar("T")


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
