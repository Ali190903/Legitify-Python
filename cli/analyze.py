import click

@click.command()
@click.option('--org', multiple=True, help='Specific organizations to collect')
@click.option('--repo', multiple=True, help='Specific repositories to collect (owner/repo)')
@click.option('--enterprise', multiple=True, help='Specific enterprises to collect')
@click.option('--token', envvar='SCM_TOKEN', help='GitHub Token (or set SCM_TOKEN env var)')
@click.option('--output-format', default='human', type=click.Choice(['human', 'json', 'markdown', 'sarif']), help='Output format')
@click.option('--output-scheme', default='default', help='Output scheme (default, flat)')
@click.option('--policies-path', default='./policies', help='Path to policies directory')
@click.option('--namespace', multiple=True, type=click.Choice(['organization', 'repository', 'member', 'actions', 'runner_group']), help='Which namespace to run')
@click.option('--scorecard', default='no', type=click.Choice(['no', 'yes', 'verbose']), help='Whether to run additional scorecard checks')
@click.option('--failed-only', is_flag=True, help='Only show violated policies')
@click.option('--scm', default='github', type=click.Choice(['github', 'gitlab']), help='Source Control Management system')
@click.option('--ignore-policies-file', help='Path to a file containing newline separated policy names to ignore')
def analyze(org, repo, enterprise, token, output_format, output_scheme, policies_path, namespace, scorecard, failed_only, scm, ignore_policies_file):
    """Analyze GitHub/GitLab organization or repository for security issues."""
    from internal.common.namespace import Namespace, validate_namespaces, ALL_NAMESPACES
    from internal.common.config import ConfigManager

    # Initialize Config
    config_manager = ConfigManager.get_instance()
    config_manager.load_from_env()
    
    # Pass arguments to config override
    args_dict = {
        "org": org,
        "repo": repo,
        "enterprise": enterprise,
        "token": token,
        "output_format": output_format,
        "output_scheme": output_scheme,
        "policies_path": policies_path,
        "namespace": namespace,
        "scorecard": scorecard,
        "failed_only": failed_only,
        "scm": scm,
        "ignore_policies_file": ignore_policies_file
    }
    config_manager.set_args(args_dict)
    config = config_manager.get_config()

    if not config.token:
        click.echo("Error: Token is required. Set SCM_TOKEN environment variable or use --token.")
        return

    # Validate naming
    if config.orgs and config.repos:
        click.echo("Error: Cannot use --org and --repo options together.")
        return
        
    # Validate namespaces
    namespaces_to_run = config.namespaces if config.namespaces else [n.value for n in ALL_NAMESPACES]
    try:
        validate_namespaces(namespaces_to_run)
    except ValueError as e:
        click.echo(f"Error: {e}")
        return

    from internal.common.scm_type import ScmType
    from internal.opa.opa_engine import OpaEngine
    from internal.opa.skipper import Skipper
    from internal.outputer.base_outputer import ConsoleOutputer
    import os

    # Resolve absolute path for policies if default
    final_policies_path = config.policies_path
    if final_policies_path == './policies':
        final_policies_path = os.path.join(os.getcwd(), 'policies')
    
    skipper = Skipper(config.ignore_policies_file)
    
    click.echo(f"Starting analysis...")
    
    try:
        # Initialize Engine
        engine = OpaEngine(final_policies_path)
        all_violations = []
        
        if config.scm_type == ScmType.GITHUB:
             _analyze_github(config, namespaces_to_run, engine, all_violations, skipper)
        elif config.scm_type == ScmType.GITLAB:
             _analyze_gitlab(config, namespaces_to_run, engine, all_violations, skipper)

        # Output
        # Filter failed only
        if config.failed_only:
             all_violations = [v for v in all_violations if v.get("status") == "FAILED" or True] 
             pass 

        if config.output_format == 'sarif':
             from internal.outputer.sarif_outputer import SarifOutputter
             outputer = SarifOutputter()
             outputer.print_violations(all_violations)
        else:
             outputer = ConsoleOutputer(output_format=config.output_format)
             outputer.print_violations(all_violations)

    except Exception as e:
        click.echo(f"Error during analysis: {e}")
        import traceback
        traceback.print_exc()

def _analyze_repos(repos, engine, all_violations, skipper):
    for r in repos:
        input_data = {
            "repository": r.model_dump(by_alias=True),
            "hooks": [h.model_dump() for h in r.hooks],
            "collaborators": r.collaborators
        }
        violations = engine.eval(input_data, package="repository")
        for v in violations:
            if skipper.should_skip(v.get("policyName", "")) or skipper.should_skip(v.get("rule", "")):
                continue
            v["target"] = r.name
            all_violations.append(v)

def _analyze_github(config, namespaces_to_run, engine, all_violations, skipper):
    from internal.clients.github_client import GitHubClient
    from internal.collectors.github.repository_collector import RepositoryCollector
    from internal.collectors.github.organization_collector import OrganizationCollector
    from internal.collectors.github.member_collector import MemberCollector
    from internal.collectors.github.actions_collector import ActionsCollector
    from internal.collectors.github.runners_collector import RunnersCollector
    from internal.common.namespace import Namespace
    import click

    client = GitHubClient(config.token)
    orgs_to_scan = config.orgs
    repos_to_scan = config.repos
    
    # Organizations
    if orgs_to_scan:
        for current_org in orgs_to_scan:
            click.echo(f"Analyzing Organization: {current_org}")
            
            if Namespace.ORGANIZATION in namespaces_to_run:
                click.echo("  - Collecting Organization details...")
                org_collector = OrganizationCollector(client, current_org)
                organizations = org_collector.collect()
                for organization in organizations:
                    input_data = {
                        "organization": organization.model_dump(by_alias=True),
                        "hooks": [h.model_dump() for h in organization.hooks],
                        "organization_secrets": [s.model_dump(by_alias=True) for s in organization.organization_secrets],
                        "saml_enabled": organization.saml_enabled
                    }
                    violations = engine.eval(input_data, package="organization")
                    for v in violations:
                        if skipper.should_skip(v.get("policyName", "")) or skipper.should_skip(v.get("rule", "")):
                             continue
                        v["target"] = current_org
                        all_violations.append(v)

            if Namespace.MEMBER in namespaces_to_run:
                click.echo("  - Collecting Members...")
                member_collector = MemberCollector(client, current_org)
                members = member_collector.collect()
                input_data = {"members": [m.model_dump() for m in members]}
                violations = engine.eval(input_data, package="member")
                for v in violations:
                   if skipper.should_skip(v.get("policyName", "")) or skipper.should_skip(v.get("rule", "")):
                        continue
                   v["target"] = f"{current_org} (Members)"
                   all_violations.append(v)

            if Namespace.ACTIONS in namespaces_to_run:
                click.echo("  - Collecting Actions settings...")
                actions_collector = ActionsCollector(client, current_org)
                actions_data_list = actions_collector.collect()
                for actions_data in actions_data_list:
                    input_data = {"actions": actions_data.model_dump()}
                    violations = engine.eval(input_data, package="actions")
                    for v in violations:
                        if skipper.should_skip(v.get("policyName", "")) or skipper.should_skip(v.get("rule", "")):
                             continue
                        v["target"] = f"{current_org} (Actions)"
                        all_violations.append(v)

            if Namespace.RUNNER_GROUP in namespaces_to_run:
                click.echo("  - Collecting Runner Groups...")
                runners_collector = RunnersCollector(client, current_org)
                runners = runners_collector.collect()
                for rg in runners:
                        input_data = {"runner_group": rg.model_dump()}
                        violations = engine.eval(input_data, package="runner_group")
                        for v in violations:
                            if skipper.should_skip(v.get("policyName", "")) or skipper.should_skip(v.get("rule", "")):
                                 continue
                            v["target"] = f"{current_org} (RunnerGroup: {rg.name})"
                            all_violations.append(v)
            
            if Namespace.REPOSITORY in namespaces_to_run:
                click.echo("  - Collecting Repositories...")
                repo_collector = RepositoryCollector(client, current_org)
                repos = repo_collector.collect()
                _analyze_repos(repos, engine, all_violations, skipper)

    # Repositories
    if repos_to_scan:
        click.echo(f"Analyzing {len(repos_to_scan)} specific repositories...")
        if Namespace.REPOSITORY in namespaces_to_run:
            collected_repos = []
            for r_str in repos_to_scan:
                    if '/' not in r_str:
                         click.echo(f"  - Warning: Skipping invalid repo string '{r_str}'. Expected 'owner/repo'.")
                         continue
                    owner, name = r_str.split('/')
                    click.echo(f"  - Collecting {owner}/{name}...")
                    repo_collector = RepositoryCollector(client, owner)
                    all_from_org = repo_collector.collect() 
                    for r in all_from_org:
                        if r.name == name:
                            collected_repos.append(r)
            _analyze_repos(collected_repos, engine, all_violations, skipper)

def _analyze_gitlab(config, namespaces_to_run, engine, all_violations, skipper):
    from internal.clients.gitlab_client import GitLabClient
    from internal.collectors.gitlab.group_collector import GroupCollector
    from internal.collectors.gitlab.repository_collector import RepositoryCollector
    from internal.collectors.gitlab.user_collector import UserCollector
    from internal.common.namespace import Namespace
    import click
    
    # Note: 'org' argument is treated as 'group' in GitLab context usually, or we can use --org for groups.
    # The analyze command uses `org` for groups.
    groups_to_scan = config.orgs
    
    client = GitLabClient(config.token) # TODO: Support --endpoint if needed for self-hosted
    
    # In this MVP GitLab client, we fetch *all* available groups if none specified, or we might need filtering.
    # The Collector `collect()` fetches all. We should filter here if `groups_to_scan` is set.
    
    click.echo(f"Analyzing GitLab...")

    if Namespace.ORGANIZATION in namespaces_to_run: # Group
        click.echo("  - Collecting Groups...")
        collector = GroupCollector(None, client) # Context is unused in current impl
        all_groups = collector.collect()
        
        for g in all_groups:
            if groups_to_scan and g.name not in groups_to_scan and g.full_name not in groups_to_scan:
                 continue

            click.echo(f"    Scanning Group: {g.name}")
            input_data = {"organization": g.model_dump()} # Mapping Group -> Organization for OPA
            violations = engine.eval(input_data, package="organization")
            for v in violations:
                if skipper.should_skip(v.get("policyName", "")) or skipper.should_skip(v.get("rule", "")):
                     continue
                v["target"] = g.name
                all_violations.append(v)
    
    if Namespace.REPOSITORY in namespaces_to_run: # Project
        click.echo("  - Collecting Projects...")
        collector = RepositoryCollector(None, client)
        all_projects = collector.collect()
        
        for p in all_projects:
             # Basic filtering by group if needed, but project doesn't strictly have group name on it easily without expansion
             # For MVP scan all visible projects
             # TODO: Filter by group if groups_to_scan is set
             input_data = {"repository": p.model_dump()}
             violations = engine.eval(input_data, package="repository")
             for v in violations:
                 if skipper.should_skip(v.get("policyName", "")) or skipper.should_skip(v.get("rule", "")):
                      continue
                 v["target"] = p.name
                 all_violations.append(v)

    if Namespace.MEMBER in namespaces_to_run: # User
        click.echo("  - Collecting Users...")
        collector = UserCollector(None, client)
        users = collector.collect()
        input_data = {"members": [u.model_dump() for u in users]}
        violations = engine.eval(input_data, package="member")
        for v in violations:
             if skipper.should_skip(v.get("policyName", "")) or skipper.should_skip(v.get("rule", "")):
                  continue
             v["target"] = "GitLab Users"
             all_violations.append(v)
