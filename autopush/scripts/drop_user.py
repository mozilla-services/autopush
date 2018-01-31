import time

import click

from autopush.db import (
    get_router_table,
    Router,
)
from autopush.metrics import SinkMetrics


@click.command()
@click.option('--router_table_name', help="Name of the router table.")
@click.option('--months-ago', default=2, help="Months ago to remove.")
@click.option('--batch_size', default=25,
              help="Deletes to run before pausing.")
@click.option('--pause_time', default=1,
              help="Seconds to pause between batches.")
def drop_users(router_table_name, months_ago, batch_size, pause_time):
    router_table = get_router_table(router_table_name)
    router = Router(router_table, SinkMetrics())
    click.echo("Deleting users with a last_connect %s months ago."
               % months_ago)

    count = 0
    for deletes in router.drop_old_users(months_ago):
        click.echo("")
        count += deletes
        if count >= batch_size:
            click.echo("Deleted %s user records, pausing for %s seconds."
                       % pause_time)
            time.sleep(pause_time)
            count = 0
    click.echo("Finished old user purge.")


if __name__ == '__main__':  # pragma: nocover
    drop_users()
