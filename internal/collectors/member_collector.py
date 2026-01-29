from typing import List
from internal.clients.github_client import GitHubClient
from internal.common.types import Member

class MemberCollector:
    def __init__(self, client: GitHubClient):
        self.client = client

    def collect(self, org_name: str) -> List[Member]:
        raw_members = self.client.get_members(org_name)
        members = []
        
        for m in raw_members:
            # role is usually "ADMIN" or "MEMBER"
            is_admin = m.get("role") == "ADMIN"
            
            member = Member(
                login=m["login"],
                role=m.get("role", "MEMBER"),
                is_admin=is_admin,
                # last_active is not available via standard GraphQL without Enterprise/SAML
                last_active=-1 
            )
            members.append(member)
            
        return members
