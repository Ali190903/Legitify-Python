from abc import ABC, abstractmethod
from typing import List, Any
from internal.common.types import Repository, Organization, Member

class Collector(ABC):
    def __init__(self, ctx: Any, client: Any):
        self.ctx = ctx
        self.client = client

    @abstractmethod
    def collect(self) -> List[Any]:
        """Collects entities and returns a list of them."""
        pass

    @abstractmethod
    def get_namespace(self) -> str:
        """Returns the namespace (e.g. 'repository', 'organization', etc.)"""
        pass
