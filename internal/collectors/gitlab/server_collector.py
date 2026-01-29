from typing import List
from internal.collectors.base_collector import Collector
from internal.common.types import GitLabServer

class ServerCollector(Collector):
    def get_namespace(self) -> str:
        return "enterprise"

    def collect(self) -> List[GitLabServer]:
        settings = self.client.get_server_settings()
        if not settings:
            return []
        
        # We assume the client endpoint is the server URL
        url = self.client.gl.url
        server_obj = GitLabServer(url=url, **settings)
        return [server_obj]
