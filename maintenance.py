"""Maintenance scripts

These scripts are isolated from ``main.py`` to reduce the package dependencies
when running under AWS Lambda.

This module avoids non-stdlib imports to work cleanly in AWS Lambda. Using the
functions in the db module would be cleaner but autopush uses boto2, while
AWS Lambda uses Boto 3. The db module also has additional imports requiring
substantially more packages.

The IAM execution context should have a policy similar to the following to
ensure it can read/write DynamoDB properly:

..

    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                "Resource": "arn:aws:logs:*:*:*"
            },
            {
                "Sid": "ListAndCreateAndDescribeAllTables",
                "Effect": "Allow",
                "Action": [
                    "dynamodb:ListTables",
                    "dynamodb:DescribeTable",
                    "dynamodb:CreateTable",
                    "dynamodb:UpdateTable"
                ],
                "Resource": "arn:aws:dynamodb:*:*:table/*"
            }
        ]
    }

"""
import datetime

import boto3

# Change when deploying under Lambda
MESSAGE_TABLE_PREFIX = "message"
REGION = "us-east-1"

dynamodb = boto3.resource('dynamodb', region_name=REGION)
client = boto3.client('dynamodb', region_name=REGION)


def get_month(delta=0):
    """Basic helper function to get a datetime.date object iterations months
    ahead/behind of now."""
    new = last = datetime.date.today()
    # Move until we hit a new month, this avoids having to manually
    # check year changes as we push forward or backward since the Python
    # timedelta math handles it for us
    for _ in range(abs(delta)):
        while new.month == last.month:
            if delta < 0:
                new -= datetime.timedelta(days=14)
            else:
                new += datetime.timedelta(days=14)
        last = new
    return new


def make_rotating_tablename(prefix, delta=0):
    """Creates a tablename for table rotation based on a prefix with a given
    month delta."""
    date = get_month(delta=delta)
    return "{}_{:04d}_{:02d}".format(prefix, date.year, date.month)


def table_maintenance(event, context):
    """AWS Lambda function for ensuring the appropriate message table is
    available for the next month

    This function will create a table for the month, and copy the read/write
    units provisioned over to it.

    If the next table's month already exists, this script will check and ensure
    the read/write units match this months.

    """
    # Get the current provisioned limits for this months table
    cur_mth_tbl = dynamodb.Table(make_rotating_tablename(MESSAGE_TABLE_PREFIX))
    limits = cur_mth_tbl.provisioned_throughput
    read_units = limits["ReadCapacityUnits"]
    write_units = limits["WriteCapacityUnits"]

    # Determine if we are making the table or just verifying limits
    nxt_mth_tblname = make_rotating_tablename(MESSAGE_TABLE_PREFIX, delta=1)
    existing_tables = client.list_tables()["TableNames"]
    if nxt_mth_tblname in existing_tables:
        # Verify table units
        nxt_mth_tbl = dynamodb.Table(nxt_mth_tblname)
        nxt_limits = nxt_mth_tbl.provisioned_throughput
        if nxt_limits["ReadCapacityUnits"] != read_units or \
           nxt_limits["WriteCapacityUnits"] != write_units:
            nxt_mth_tbl.update(ProvisionedThroughput={
                "ReadCapacityUnits": read_units,
                "WriteCapacityUnits": write_units
            })
    else:
        # Create the new table
        client.create_table(
            AttributeDefinitions=[
                {"AttributeName": "uaid", "AttributeType": "S"},
                {"AttributeName": "chidmessageid", "AttributeType": "S"}
            ],
            TableName=nxt_mth_tblname,
            KeySchema=[
                {"AttributeName": "uaid", "KeyType": "HASH"},
                {"AttributeName": "chidmessageid", "KeyType": "RANGE"}
            ],
            ProvisionedThroughput={
                "ReadCapacityUnits": read_units,
                "WriteCapacityUnits": write_units
            }
        )
