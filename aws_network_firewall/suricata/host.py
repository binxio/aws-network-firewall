from __future__ import annotations

from dataclasses import dataclass
from typing import Union, Optional


@dataclass
class Host:
    """
    Understands a source and/or destination defenition
    """

    address: str = "any"
    port: Optional[int] = None

    def __post_init__(self):
        self.port = "any" if not self.port else self.port

    def __str__(self):
        return f"{self.address} {self.port}"
