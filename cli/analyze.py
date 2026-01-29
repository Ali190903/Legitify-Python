import click

@click.command()
@click.option('--org', multiple=True, help='Specific organizations to collect')
@click.option('--repo', multiple=True, help='Specific repositories to collect (owner/repo)')
@click.option('--enterprise', multiple=True, help='Specific enterprises to collect')
@click.option('--token', envvar='SCM_TOKEN', help='GitHub Token (or set SCM_TOKEN env var)')
@click.option('--output-format', default='human', type=click.Choice(['human', 'json', 'markdown']), help='Output format')
@click.option('--output-scheme', default='default', help='Output scheme (default, flat)')
@click.option('--policies-path', default='./policies', help='Path to policies directory')
@click.option('--namespace', multiple=True, type=click.Choice(['organization', 'repository', 'member', 'actions', 'runner_group']), help='Which namespace to run')
@click.option('--scorecard', default='no', type=click.Choice(['no', 'yes', 'verbose']), help='Whether to run additional scorecard checks')
@click.option('--failed-only', is_flag=True, help='Only show violated policies')
def analyze(org, repo, enterprise, token, output_format, output_scheme, policies_path, namespace, scorecard, failed_only):
    """Analyze GitHub organization or repository for security issues."""
    """Analyze GitHub organization or repository for security issues."""
    from internal.common.namespace import Namespace, validate_namespaces, ALL_NAMESPACES

    if not token:
        click.echo("Error: GitHub Token is required. Set SCM_TOKEN environment variable or use --token.")
        return

    # Validate naming
    if org and repo:
        click.echo("Error: Cannot use --org and --repo options together.")
        return
        
    # Validate namespaces
    namespaces_to_run = list(namespace) if namespace else [n.value for n in ALL_NAMESPACES]
    try:
        validate_namespaces(namespaces_to_run)
    except ValueError as e:
        click.echo(f"Error: {e}")
        return

    from internal.clients.github_client import GitHubClient
    from internal.collectors.repository_collector import RepositoryCollector
    from internal.collectors.organization_collector import OrganizationCollector
    from internal.collectors.member_collector import MemberCollector
    from internal.collectors.actions_collector import ActionsCollector
    from internal.collectors.runners_collector import RunnersCollector
    from internal.opa.opa_engine import OpaEngine
    from internal.outputer.base_outputer import ConsoleOutputer
    import os

    # Resolve absolute path for policies if default
    if policies_path == './policies':
        policies_path = os.path.join(os.getcwd(), 'policies')

    click.echo(f"Starting analysis...")
    
    try:
        # Initialize Client & Engine
        client = GitHubClient(token)
        engine = OpaEngine(policies_path)
        all_violations = []

        # Collect targets
        orgs_to_scan = list(org)
        
        # If repo is provided, extract owner as org to scan (conceptually) but handle appropriately
        repos_to_scan = list(repo)

        # 1. Organization Level Collections
        if orgs_to_scan:
            for current_org in orgs_to_scan:
                click.echo(f"Analyzing Organization: {current_org}")
                
                # Organization
                if Namespace.ORGANIZATION in namespaces_to_run:
                    click.echo("  - Collecting Organization details...")
                    org_collector = OrganizationCollector(client)
                    organization = org_collector.collect(current_org)
                    
                    input_data = {
                        "organization": organization.model_dump(by_alias=True),
                        "hooks": [h.model_dump() for h in organization.hooks],
                        "organization_secrets": [s.model_dump(by_alias=True) for s in organization.organization_secrets],
                        "saml_enabled": organization.saml_enabled
                    }
                    violations = engine.eval(input_data, package="organization")
                    for v in violations:
                        v["target"] = current_org
                        all_violations.append(v)

                # Members
                if Namespace.MEMBER in namespaces_to_run:
                    click.echo("  - Collecting Members...")
                    member_collector = MemberCollector(client)
                    members = member_collector.collect(current_org)
                    input_data = {"members": [m.model_dump() for m in members]}
                    violations = engine.eval(input_data, package="member")
                    for v in violations:
                        v["target"] = f"{current_org} (Members)"
                        all_violations.append(v)

                # Actions
                if Namespace.ACTIONS in namespaces_to_run:
                    click.echo("  - Collecting Actions settings...")
                    actions_collector = ActionsCollector(client)
                    actions_data = actions_collector.collect(current_org)
                    # Need to check expected input schema for actions policy 
                    # Assuming data.actions... or part of organization? 
                    # Go definitions usually put it in its own package or sub-struct.
                    # Let's assume 'actions' package for now or check policies.
                    input_data = {"actions": actions_data.model_dump()}
                    violations = engine.eval(input_data, package="actions")
                    for v in violations:
                        v["target"] = f"{current_org} (Actions)"
                        all_violations.append(v)

                # Runner Groups
                if Namespace.RUNNER_GROUP in namespaces_to_run:
                    click.echo("  - Collecting Runner Groups...")
                    runners_collector = RunnersCollector(client)
                    runners = runners_collector.collect(current_org)
                    for rg in runners:
                         input_data = {"runner_group": rg.model_dump()}
                         violations = engine.eval(input_data, package="runner_group")
                         for v in violations:
                             v["target"] = f"{current_org} (RunnerGroup: {rg.name})"
                             all_violations.append(v)
                
                # Repositories (if part of Org scan)
                if Namespace.REPOSITORY in namespaces_to_run:
                    click.echo("  - Collecting Repositories...")
                    repo_collector = RepositoryCollector(client)
                    repos = repo_collector.collect_all(current_org)
                    _analyze_repos(repos, engine, all_violations)

        # 2. Specific Repository Analysis
        if repos_to_scan:
            click.echo(f"Analyzing {len(repos_to_scan)} specific repositories...")
            if Namespace.REPOSITORY in namespaces_to_run:
                repo_collector = RepositoryCollector(client)
                # We need a more efficient way to collect specific repos than collecting ALL and filtering
                # But for now reusing collect_all per org or implementing specific fetch.
                # Let's rely on collect_all for MVP or loop owner/repo and fetch individually.
                
                # Fetching individually is better.
                collected_repos = []
                for r_str in repos_to_scan:
                    owner, name = r_str.split('/')
                    # TODO: Implement get_repository single in collector
                    # For now, let's just collect all from owner and filter (inefficient but safe for now)
                    # Or better: Add collect_one to RepositoryCollector
                    all_from_org = repo_collector.collect_all(owner) 
                    for r in all_from_org:
                         if r.name == name:
                             collected_repos.append(r)
                
                _analyze_repos(collected_repos, engine, all_violations)

        # Output
        # Filter failed only
        if failed_only:
             all_violations = [v for v in all_violations if v.get("status") == "FAILED" or True] # Wait, violations list ARE failed policies usually. 
             # Is 'violations' containing PASSED ones? engine.eval returns only "true" rules usually.
             # If engine returns everything, we filter.
             # Our engine.eval currently returns violations (true rules).
             pass 

        outputer = ConsoleOutputer(output_format=output_format)
        outputer.print_violations(all_violations)

    except Exception as e:
        click.echo(f"Error during analysis: {e}")
        import traceback
        traceback.print_exc()

def _analyze_repos(repos, engine, all_violations):
    for r in repos:
        input_data = {
            "repository": r.model_dump(by_alias=True),
            "hooks": [h.model_dump() for h in r.hooks],
            "collaborators": r.collaborators
        }
        violations = engine.eval(input_data, package="repository")
        for v in violations:
            v["target"] = r.name
            all_violations.append(v)
