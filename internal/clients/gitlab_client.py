import os
import gitlab
from typing import Optional, List
from internal.common.types import GitLabGroup, GitLabProject, GitLabMember

class GitLabClient:
    def __init__(self, token: str, endpoint: Optional[str] = None):
        if not endpoint:
            endpoint = "https://gitlab.com"
        
        self.gl = gitlab.Gitlab(url=endpoint, private_token=token)
        self.gl.auth()

    def get_groups(self) -> List[GitLabGroup]:
        """Fetches all groups the user has access to."""
        groups = self.gl.groups.list(all=True)
        return [GitLabGroup(**group.attributes) for group in groups]

    def get_projects(self) -> List[GitLabProject]:
        """Fetches all projects."""
        projects = self.gl.projects.list(all=True)
        return [GitLabProject(**project.attributes) for project in projects]

    def get_users(self) -> List[GitLabMember]:
        """Fetches users (requires admin often, or search)."""
        # Note: Listing all users usually requires admin. 
        # For non-admin, this might return limited results or error.
        users = self.gl.users.list(all=True)
        return [GitLabMember(**user.attributes) for user in users]

    def get_server_settings(self):
        """Fetches server settings (requires admin)."""
        try:
            settings = self.gl.settings.get()
            return settings.attributes
        except Exception:
            return {}
