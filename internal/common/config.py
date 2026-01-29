import os
from dataclasses import dataclass
from typing import Optional, List

@dataclass
class Config:
    orgs: List[str]
    repos: List[str]
    token: str
    output_format: str
    output_scheme: str
    policies_path: str
    namespaces: List[str]
    scorecard: str
    failed_only: bool
    scm_type: str
    ignore_policies_file: Optional[str] = None
    enterprise_url: Optional[str] = None

class ConfigManager:
    _instance = None

    def __init__(self):
        self.config = Config(
            orgs=[],
            repos=[],
            token="",
            output_format="human",
            output_scheme="default",
            policies_path="./policies",
            namespaces=[],
            scorecard="no",
            failed_only=False,
            scm_type="github"
        )

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = ConfigManager()
        return cls._instance

    def load_from_env(self):
        """Loads configuration from environment variables."""
        self.config.token = os.environ.get("SCM_TOKEN", "") or os.environ.get("GITHUB_TOKEN", "")
        # Add other env vars if needed, e.g. LEGITIFY_OUTPUT_FORMAT
        
    def set_args(self, args: dict):
        """Overrides configuration with command line arguments."""
        if args.get("org"):
            self.config.orgs = list(args.get("org"))
        if args.get("repo"):
            self.config.repos = list(args.get("repo"))
        if args.get("token"):
            self.config.token = args.get("token")
        if args.get("output_format"):
            self.config.output_format = args.get("output_format")
        if args.get("output_scheme"):
            self.config.output_scheme = args.get("output_scheme")
        if args.get("policies_path"):
            self.config.policies_path = args.get("policies_path")
        if args.get("namespace"):
            self.config.namespaces = list(args.get("namespace"))
        if args.get("scorecard"):
            self.config.scorecard = args.get("scorecard")
        if args.get("failed_only") is not None:
            self.config.failed_only = args.get("failed_only")
        if args.get("scm"):
            self.config.scm_type = args.get("scm")
        if args.get("ignore_policies_file"):
            self.config.ignore_policies_file = args.get("ignore_policies_file")
        if args.get("enterprise"):
            # Enterprise collector usually takes slugs, but client might need URL?
            # Go analyze args: enterprise (slugs).
            pass

    def get_config(self) -> Config:
        return self.config
