import click
from internal.common.scm_type import ScmType
from internal.clients.github_client import GitHubClient
from internal.clients.gitlab_client import GitLabClient

@click.command('list-orgs')
@click.option('--token', envvar='SCM_TOKEN', help='SCM Token')
@click.option('--scm', default='github', type=click.Choice(['github', 'gitlab']), help='Source Control Management system')
def list_orgs(token, scm):
    """List organizations/groups associated with the token."""
    if not token:
        click.echo("Error: Token is required.")
        return

    try:
        if scm == ScmType.GITHUB:
            client = GitHubClient(token)
            # GitHub doesn't have a simple "list my orgs" in the client yet explicitly public,
            # but we can assume get_organizations or similar exists or we use GraphQL.
            # Checking GitHubClient... 
            # If not present, we should implement it. 
            # For now, let's try assuming a method or using one.
            # Actually, `get_organization_details` fetches one.
            # We need a method to list authenticated user's orgs.
            # Let's check GitHubClient in next step. For now, writing placeholder logic that calls client.
            orgs = client.get_user_organizations() 
            click.echo(f"Organizations ({len(orgs)}):")
            for org in orgs:
                click.echo(f"- {org}")
                
        elif scm == ScmType.GITLAB:
            client = GitLabClient(token)
            groups = client.get_groups()
            click.echo(f"GitLab Groups ({len(groups)}):")
            for g in groups:
                 click.echo(f"- {g.full_name} (path: {g.name})")

    except Exception as e:
        click.echo(f"Error listing organizations: {e}")
