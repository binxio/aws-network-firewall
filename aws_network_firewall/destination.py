from __future__ import annotations
from dataclasses import dataclass
from typing import Optional


@dataclass
class Destination:
    """
    Understands a destination
    """

    description: str
    protocol: str
    port: Optional[int]
    endpoint: Optional[str]
    cidr: Optional[str]
    message: Optional[str]
