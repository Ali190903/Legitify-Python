import click
import os
import sys

# Ensure the current directory is in the python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from cli.analyze import analyze

@click.group()
def cli():
    """Legitify - Security Posture Analysis Tool (Python Version)"""
    pass

cli.add_command(analyze)

from cli.list_orgs import list_orgs
from cli.list_repos import list_repos
cli.add_command(list_orgs)
cli.add_command(list_repos)

if __name__ == '__main__':
    cli()
