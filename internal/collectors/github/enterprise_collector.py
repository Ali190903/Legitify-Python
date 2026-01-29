from typing import List
from internal.clients.github_client import GitHubClient
from internal.common.types import Enterprise
from internal.collectors.base_collector import Collector

class EnterpriseCollector(Collector):
    def __init__(self, client: GitHubClient, enterprise: str):
        self.client = client
        self.enterprise = enterprise

    def get_namespace(self) -> str:
        return "enterprise"

    def collect(self) -> List[Enterprise]:
        # Collect Enterprise details via GraphQL or REST (usually different endpoint or user role needed)
        # Note: Legitify Go uses GraphQL for enterprise settings.
        # Assuming Client has method get_enterprise(slug)
        raw = self.client.get_enterprise(self.enterprise)
        if not raw:
            return []
            
        return [Enterprise(**raw)]
