"""Minimal service locator so UI code does not construct services itself."""
from __future__ import annotations

from typing import Any, TypeVar

T = TypeVar("T")


class ServiceRegistry:
    def __init__(self) -> None:
        self._services: dict[type, Any] = {}

    def register(self, cls: type[T], instance: T) -> None:
        self._services[cls] = instance

    def get(self, cls: type[T]) -> T:
        try:
            return self._services[cls]
        except KeyError:
            raise LookupError(f"service not registered: {cls.__name__}") from None
