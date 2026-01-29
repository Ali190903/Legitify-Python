from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

class RepositorySecret(BaseModel):
    name: str
    updated_at: str = Field(alias="update_date") # ISO string from REST

class OrganizationSecret(BaseModel):
    name: str
    updated_at: str = Field(alias="update_date")

class Member(BaseModel):
    login: str
    name: Optional[str] = None
    email: Optional[str] = None
    role: str
    is_admin: bool = False
    last_active: int = -1 # timestamp or -1 if unknown

class Hook(BaseModel):
    name: str
    url: str
    id: Any

class BranchProtectionRule(BaseModel):
    allows_deletions: bool = False
    allows_force_pushes: bool = False
    requires_status_checks: bool = False
    requires_strict_status_checks: bool = False
    requires_code_owner_reviews: bool = False
    required_approving_review_count: int = 0
    dismisses_stale_reviews: bool = False
    requires_linear_history: bool = False
    requires_conversation_resolution: bool = False
    requires_commit_signatures: bool = False
    restricts_review_dismissals: bool = False
    restricts_pushes: bool = False

class Ref(BaseModel):
    name: str
    branch_protection_rule: Optional[BranchProtectionRule] = None

class Repository(BaseModel):
    name: str
    id: str
    url: str
    is_private: bool
    is_archived: bool
    pushed_at: Optional[str] = None
    default_branch: Optional[Ref] = None
    
    # Extra data collected
    repo_secrets: List[RepositorySecret] = []
    hooks: List[Hook] = []
    collaborators: List[Any] = [] # List of admins/collaborators
    
    # Advanced Security & Actions
    actions_token_permissions: Dict[str, Any] = Field(default_factory=dict)
    rules_set: List[Any] = Field(default_factory=list)
    vulnerability_alerts_enabled: Optional[bool] = None
    security_and_analysis: Dict[str, Any] = Field(default_factory=dict)
    scorecard: Dict[str, Any] = Field(default_factory=dict)
    dependency_graph_manifests: Dict[str, Any] = Field(default_factory=dict)

    # Permissions
    
    # Permissions
    no_branch_protection_permission: bool = False

    no_branch_protection_permission: bool = False

    model_config = ConfigDict(populate_by_name=True)

class Organization(BaseModel):
    login: str
    name: Optional[str] = None
    description: Optional[str] = None
    url: Optional[str] = None
    two_factor_requirement_enabled: bool = Field(default=False, alias="requiresTwoFactorAuthentication")
    members_can_create_public_repositories: bool = Field(default=False, alias="membersCanCreatePublicRepositories")
    default_repository_permission: Optional[str] = Field(default=None, alias="defaultRepositoryPermission")
    saml_enabled: bool = False

    # Collections
    repositories: List[Repository] = []
    members: List[Member] = []
    organization_secrets: List[OrganizationSecret] = []
    hooks: List[Hook] = []
    
    # Actions & Runners
    actions: Optional['OrganizationActions'] = None
    runner_groups: List['RunnerGroup'] = []

    model_config = ConfigDict(populate_by_name=True)

class OrganizationActions(BaseModel):
    actions_permissions: Dict[str, Any] = Field(default_factory=dict)
    token_permissions: Dict[str, Any] = Field(default_factory=dict)

class RunnerGroup(BaseModel):
    id: int
    name: str
    visibility: str
    allows_public_repositories: bool
    default: bool
    runners_url: str
    inherited: bool
    selected_repositories_url: Optional[str] = None
    workflow_restrictions_read_only: bool = False
    restricted_to_workflows: bool = False
    selected_workflows: List[str] = []

