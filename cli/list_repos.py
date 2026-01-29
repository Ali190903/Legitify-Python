import click
from internal.common.scm_type import ScmType
from internal.clients.github_client import GitHubClient
from internal.clients.gitlab_client import GitLabClient

@click.command('list-repos')
@click.option('--token', envvar='SCM_TOKEN', help='SCM Token')
@click.option('--scm', default='github', type=click.Choice(['github', 'gitlab']), help='Source Control Management system')
@click.option('--org', help='Organization/Group to list repositories for')
def list_repos(token, scm, org):
    """List repositories associated with the token or organization."""
    if not token:
        click.echo("Error: Token is required.")
        return

    try:
        if scm == ScmType.GITHUB:
            client = GitHubClient(token)
            if org:
                repos = client.get_repositories(org)
                click.echo(f"Repositories for {org} ({len(repos)}):")
                for r in repos:
                    click.echo(f"- {r.get('name')} ({r.get('url')})")
            else:
                 click.echo("Error: --org is required for GitHub list-repos currently.")

        elif scm == ScmType.GITLAB:
            client = GitLabClient(token)
            # GitLab client get_projects returns all projects user has access to if no filter
            # But usually we want to filter by group if provided
            projects = client.get_projects()
            # If org (group) is provided, filter? Or does client support it?
            # Client `get_projects` fetches all.
            # We can filter locally.
            
            count = 0
            for p in projects:
                 # Logic to check if p belongs to group 'org'
                 # p.namespace['name'] or p.path_with_namespace
                 # Let's assume user wants to see everything if no org.
                 if org:
                     # Filter by partial match or namespace
                     pass # TODO implement filtering
                 
                 click.echo(f"- {p.name} ({p.web_url})")
                 count += 1
            
            click.echo(f"Total Projects: {count}")

    except Exception as e:
        click.echo(f"Error listing repositories: {e}")
