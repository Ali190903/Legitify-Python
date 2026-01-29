from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

# ==========================================
# GitHub Entities
# ==========================================

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
    events: List[str] = []
    active: bool = True
    content_type: str = ""

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

class AnalysisAndSecurityPolicies(BaseModel):
    # Field definitions based on what GitHub Enterprise returns for code security policies
    # Using generic dict for now as strict typing might be overkill without exact schema
    model_config = ConfigDict(extra='allow')

class Enterprise(BaseModel):
    members_can_change_repository_visibility: str = Field(alias="members_can_change_repository_visibility")
    repositories_forking_policy: str = Field(alias="repositories_forking_policy")
    external_collaborators_invite_policy: str = Field(alias="external_collaborators_invite_policy")
    two_factor_required_setting: str = Field(alias="two_factor_required_setting")
    saml_enabled: bool = Field(alias="saml_enabled")
    name: str = Field(alias="name")
    url: str = Field(alias="url")
    id: int = Field(alias="id")
    user_role: str = "" # Set by collector
    members_can_create_public_repositories: bool = Field(alias="members_can_create_public_repositories")
    default_repository_permission_settings: str = Field(alias="default_repository_permission_settings")
    member_can_delete_repository: str = Field(alias="member_can_delete_repository")
    notification_delivery_restriction_enabled: str = Field(alias="notification_delivery_restriction_enabled")
    code_analysis_and_security_policies: Optional[Dict[str, Any]] = Field(default=None, alias="code_analysis_and_security_policies")

    model_config = ConfigDict(populate_by_name=True)

    def violation_entity_type(self) -> str:
        return "enterprise"

    def canonical_link(self) -> str:
        return self.url

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
    no_branch_protection_permission: bool = False

    model_config = ConfigDict(populate_by_name=True)

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

class OrganizationActions(BaseModel):
    actions_permissions: Dict[str, Any] = Field(default_factory=dict)
    token_permissions: Dict[str, Any] = Field(default_factory=dict)

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
    actions: Optional[OrganizationActions] = None
    runner_groups: List[RunnerGroup] = []

    model_config = ConfigDict(populate_by_name=True)


# ==========================================
# GitLab Entities
# ==========================================

class GitLabMember(BaseModel):
    id: int
    username: str
    name: str
    web_url: str
    state: str
    access_level: int
    
    model_config = ConfigDict(extra='allow')

    def violation_entity_type(self) -> str:
        return "member"
    
    def canonical_link(self) -> str:
        return self.web_url

class GitLabGroup(BaseModel):
    id: int
    name: str
    full_name: str
    web_url: str
    description: Optional[str] = None
    visibility: str
    
    # Collected Fields
    hooks: List[Dict[str, Any]] = []

    model_config = ConfigDict(extra='allow')

    def violation_entity_type(self) -> str:
        return "organization"

    def canonical_link(self) -> str:
        return self.web_url

class GitLabProject(BaseModel):
    id: int
    name: str
    web_url: str
    visibility: str
    default_branch: Optional[str] = None
    
    # Collected Fields
    members: List[GitLabMember] = []
    protected_branches: List[Dict[str, Any]] = []
    webhooks: List[Dict[str, Any]] = []
    push_rules: Optional[Dict[str, Any]] = None
    approval_configuration: Optional[Dict[str, Any]] = None
    approval_rules: List[Dict[str, Any]] = []
    minimum_required_approvals: int = 0

    model_config = ConfigDict(extra='allow')

    def violation_entity_type(self) -> str:
        return "repository"

    def canonical_link(self) -> str:
        return self.web_url

class GitLabServer(BaseModel):
    url: str
    # Settings fields would be numerous, so we allow extra
    # Common settings that might be checked:
    signup_enabled: bool = False
    password_authentication_enabled_for_web: bool = False
    password_authentication_enabled_for_git: bool = False
    
    model_config = ConfigDict(extra='allow')

    def violation_entity_type(self) -> str:
        return "enterprise"

    def canonical_link(self) -> str:
        return self.url
