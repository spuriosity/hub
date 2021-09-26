import click


@click.group()
def config():
    pass


@config.command()
def editor():
    click.echo('Starting editor configuration')

