import click

@click.command()
@click.option('--org', required=True, help='Organization to analyze')
@click.option('--repo', help='Specific repository to analyze (owner/repo)')
@click.option('--token', envvar='SCM_TOKEN', help='GitHub Token (or set SCM_TOKEN env var)')
@click.option('--output-format', default='human', type=click.Choice(['human', 'json']), help='Output format')
@click.option('--policies-path', default='./policies', help='Path to policies directory')
def analyze(org, repo, token, output_format, policies_path):
    """Analyze GitHub organization or repository for security issues."""
    if not token:
        click.echo("Error: GitHub Token is required. Set SCM_TOKEN environment variable or use --token.")
        return

    from internal.clients.github_client import GitHubClient
    from internal.collectors.repository_collector import RepositoryCollector
    from internal.collectors.organization_collector import OrganizationCollector
    from internal.collectors.member_collector import MemberCollector
    from internal.opa.opa_engine import OpaEngine
    from internal.outputer.base_outputer import ConsoleOutputer
    import os

    # Resolve absolute path for policies if default
    if policies_path == './policies':
        # Assuming run from root
        policies_path = os.path.join(os.getcwd(), 'policies')

    click.echo(f"Starting analysis for org={org}...")
    
    try:
        # 1. Initialize Client
        client = GitHubClient(token)
        engine = OpaEngine(policies_path)
        all_violations = []

        # --- Organization Analysis ---
        if not repo: # Only analyze org level if not specific repo
            click.echo("Analyzing Organization configuration...")
            org_collector = OrganizationCollector(client)
            organization = org_collector.collect(org)
            
            input_data = {
                "organization": organization.model_dump(by_alias=True),
                "hooks": [h.model_dump() for h in organization.hooks],
                "organization_secrets": [s.model_dump(by_alias=True) for s in organization.organization_secrets]
            }
            # Add other flags like saml_enabled at root level for policy
            input_data["saml_enabled"] = organization.saml_enabled

            violations = engine.eval(input_data, package="organization")
            for v in violations:
                v["target"] = org
                all_violations.append(v)
            
            # --- Member Analysis ---
            click.echo("Analyzing Members...")
            member_collector = MemberCollector(client)
            members = member_collector.collect(org)
            
            input_data_members = {
                "members": [m.model_dump() for m in members]
            }
            
            violations_members = engine.eval(input_data_members, package="member")
            for v in violations_members:
                v["target"] = org + " (Members)"
                all_violations.append(v)

        # --- Repository Analysis ---
        click.echo("Analyzing Repositories...")
        repo_collector = RepositoryCollector(client)
        repos = repo_collector.collect_all(org)
        
        # Filter if specific repo requested
        if repo:
            repos = [r for r in repos if r.name == repo or f"{org}/{r.name}" == repo]

        click.echo(f"Collected {len(repos)} repositories to analyze.")

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
        
        # 4. Output Results
        outputer = ConsoleOutputer(output_format=output_format)
        outputer.print_violations(all_violations)

    except Exception as e:
        click.echo(f"Error during analysis: {e}")
        import traceback
        traceback.print_exc()
