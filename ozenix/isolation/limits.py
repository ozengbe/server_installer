"""Per-tenant resource limits (cgroup v2 via systemd slices, PHP-FPM, cache)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from typing import Any

from ozenix.core.errors import ValidationError

_BOUNDS: dict[str, tuple[int, int]] = {
    "cpu_quota_percent": (10, 6400),  # 100 = one full core
    "memory_max_mb": (128, 262144),
    "memory_high_mb": (96, 262144),
    "swap_max_mb": (0, 65536),
    "tasks_max": (32, 32768),
    "php_max_children": (1, 512),
    "php_memory_limit_mb": (32, 4096),
    "cache_maxmemory_mb": (8, 65536),
}


@dataclass(frozen=True)
class TenantLimits:
    cpu_quota_percent: int = 100
    memory_max_mb: int = 1024
    memory_high_mb: int = 896
    swap_max_mb: int = 0
    tasks_max: int = 256
    php_max_children: int = 8
    php_memory_limit_mb: int = 256
    cache_maxmemory_mb: int = 64

    def __post_init__(self) -> None:
        for f in fields(self):
            value = getattr(self, f.name)
            low, high = _BOUNDS[f.name]
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise ValidationError(f"{f.name} must be an integer between {low} and {high}")
        if self.memory_high_mb > self.memory_max_mb:
            raise ValidationError("memory_high_mb must not exceed memory_max_mb")
        if self.php_memory_limit_mb >= self.memory_max_mb:
            raise ValidationError("php_memory_limit_mb must be below memory_max_mb")

    def to_dict(self) -> dict[str, int]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TenantLimits:
        unknown = set(data) - set(_BOUNDS)
        if unknown:
            raise ValidationError(f"unknown limit(s): {', '.join(sorted(unknown))}")
        return cls(**data)
