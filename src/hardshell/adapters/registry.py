"""Adapter discovery and registration."""

from __future__ import annotations

from importlib.metadata import entry_points

from hardshell.adapters.base import ControlAdapter

ENTRYPOINT_GROUP = "hardshell.adapters"


class AdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, ControlAdapter] = {}

    def register(self, adapter: ControlAdapter) -> None:
        if adapter.adapter_id in self._adapters:
            raise ValueError(f"adapter already registered: {adapter.adapter_id}")
        self._adapters[adapter.adapter_id] = adapter

    def get(self, adapter_id: str) -> ControlAdapter:
        try:
            return self._adapters[adapter_id]
        except KeyError as exc:
            raise KeyError(f"unknown adapter: {adapter_id}") from exc

    def list(self) -> list[ControlAdapter]:
        return list(self._adapters.values())


def discover_adapters() -> AdapterRegistry:
    """Load third-party adapters from the hardshell.adapters entry-point group."""
    registry = AdapterRegistry()
    for entry_point in entry_points(group=ENTRYPOINT_GROUP):
        loaded = entry_point.load()
        adapter = loaded() if callable(loaded) else loaded
        if not isinstance(adapter, ControlAdapter):
            raise TypeError(
                f"entry point {entry_point.name!r} did not return a ControlAdapter"
            )
        registry.register(adapter)
    return registry
