"""Manage DNAC backups
 
Example:
    Run the manage_backup command with no arguments to list all backups.
    ```
    python manage_backups.py
    ```
 
    Delete backups 'older than'. If no value is passed after --older, it deletes
    backups older than 2 years. Example shows deleting backups older than 1 year.
    ```bash
    python manage_backups.py --older 31556952
    ```
 
    Delete backup by ID. Example shows deletion of a backup with
    ID '70a0a277-8ff6-48b3-8a7b-832eef048c5a'.
    ```bash
    python manage_backups.py --delete 70a0a277-8ff6-48b3-8a7b-832eef048c5a
    ```
 
    Dryrun the command. Shows what the command will do without consequences.
    Shows all backups that would be deleted (1.5 years or older).
    ```bash
    python manage_backups.py --older 47335428 --dryrun
    ```
 
    Add -v argument to get verbose debug logging.
    ```
    python manage_backups.py -v
    ```
 
Author: Harbourheading
Creation date: 2025-07-29
"""

import base64
import json
import logging
import os
import requests
from argparse import ArgumentParser
from time import time, strftime, localtime

DNAC_FQDN: str = os.getenv("DNAC_FQDN") or ""
DNAC_USER: str = os.getenv("DNAC_USER") or ""
DNAC_PASS: str = os.getenv("DNAC_PASS") or ""

logger = logging.getLogger(__name__)


def format_time(secs) -> str:
    """Formats seconds into readable (24H) time
 
    :param secs: Seconds to format
    :return: Timestamp
    """
    fmt = "%Y-%m-%d %H:%M:%S"
    timestr = strftime(fmt, localtime(secs))
    return timestr


def make_request_to_dnac(method: str, endpoint: str, headers: dict) -> dict:
    """Makes request to DNAC.
 
    :param method: Request method, GET, DELETE, POST etc
    :param endpoint: API endpoint, e.g. '/dna/system/api/v1/auth/token'
    :param headers: Request headers
    :return: (Success, data)
    """

    url = "https://" + DNAC_FQDN + endpoint

    if not endpoint.startswith("/"):
        logger.warning("Endpoint is missing a '/' prefix. Targeted URL will be %s", url)

    try:
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            timeout=300
        )
    except Exception as e:
        raise Exception("Request to DNAC failed.") from e

    if response.ok:
        logger.debug("Request successful!")

        data = json.loads(response.content)

        return data
    else:
        logger.error(
            "Request failed! See message below for more info!\n",
            response.content
        )

        raise RuntimeError("DNAC contained unsuccessful status code. Response: %s", response)

def get_authentication_token(username: str, password: str) -> str:
    """Fetches API token from basic auth.
 
    :param username: DNAC username credential
    :param password: DNAC password credential
    :return: API token
    """

    endpoint = "/dna/system/api/v1/auth/token"

    raw_basic_auth = username + ":" + password

    auth = base64.b64encode(raw_basic_auth.encode('UTF-8')).decode('ASCII')

    headers = {
        "Accept": "application/json",
        "Authorization": "Basic " + auth,
        "Content-Type": "application/json"
    }

    logger.info("Authenticating to DNAC...")

    response = make_request_to_dnac(
        method="POST", endpoint=endpoint, headers=headers
    )

    token = response["Token"]
    return token


def show_backups(headers) -> None:
    """Lists all DNAC backups.
 
    :param headers: Request header containing token
    """

    logger.debug("Fetching all backups...")

    response: dict = make_request_to_dnac(method="GET", endpoint="/api/system/v1/maglev/backup", headers=headers)

    backups = response.get('response', [])
    backups.sort(key=lambda b: b['start_timestamp'], reverse=True)

    logger.info(
        "{:40s}{:40s}{:35s}{}".format("Backup-id", "name", "timestamp", "time")
    )

    for backup in backups:
        formatted = format_time(backup['start_timestamp'])

        logger.info("{:40s}{:40s}{:35s}{}".format(
            backup['backup_id'],
            backup.get('description', 'N/A'),
            str(backup['start_timestamp']),
            formatted
        ))


def delete(args, headers, backup_id) -> None:
    """Deletes backup from provided 'backup_id'.
 
    :param args: Passed arguments. Used to set dryrun for example
    :param backup_id: ID of backup to delete
    :param headers: Request header containing token
    """

    # No GET method exists, so delete is skipped altogether
    if args.dryrun:
        return

    response = make_request_to_dnac(method="DELETE", endpoint=f"/api/system/v1/maglev/backup/{backup_id}", headers=headers)

    logger.info(response)


def purge(args, headers, older_than) -> None:
    """Deletes all DNAC backups older than specified.
 
    :param args: Passed arguments. Used to set dryrun for example
    :param headers: Request header containing token
    :param older_than: In seconds, delete backups older than this amount
    """

    now = time()

    logger.debug("Purging backups...")

    response: dict = make_request_to_dnac(method="GET", endpoint="/api/system/v1/maglev/backup", headers=headers)

    backups = response.get('response', [])
    backups.sort(key=lambda b: b['start_timestamp'], reverse=True)

    for backup in backups:

        backup_time = backup['start_timestamp']

        if backup_time + older_than < now:
            formatted = format_time(backup['start_timestamp'])

            backup_id = backup['backup_id']

            logger.debug('deleting %s, %s',backup_id, formatted)

            delete(args, headers, backup_id)


def main() -> None:

    if not DNAC_FQDN:
        raise ValueError("Invalid input for required environment variable DNAC_FQDN. Is the environment variable being passed correctly?")

    if not DNAC_USER:
        raise ValueError("Invalid input for required environment variable DNAC_USER. Is the environment variable being passed correctly?")

    if not DNAC_PASS:
        raise ValueError("Invalid input for required environment variable DNAC_PASS. Is the environment variable being passed correctly?")

    parser = ArgumentParser(description='Select options.')

    parser.add_argument(
        '-v',
        action='store_true',
        help="verbose"
    )

    parser.add_argument(
        '--delete',
        type=str,
        metavar='backup_id',
        help='backup id to delete'
    )

    parser.add_argument(
        '--older',
        type=int,
        nargs='?',
        const=63113904,
        metavar='older_than_seconds',
        help='delete backups older than x seconds, default 2 years'
    )

    parser.add_argument(
        '--dryrun',
        action='store_true',
        help='Say what the action would do; a test run with no consequences'
    )

    args = parser.parse_args()

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    if args.v:
        logger.setLevel(logging.DEBUG)

        logger.debug("Debug logging enabled")

    token = get_authentication_token(username=DNAC_USER, password=DNAC_PASS)

    headers = {
        "x-auth-token": token,
        "Content-Type": "application/json"
    }

    if args.delete:
        logger.debug('deleting %s',args.delete)
        delete(args, headers, args.delete)
    elif args.older:
        purge(args, headers, args.older)
    else:
        show_backups(headers)


if __name__ == "__main__":
    main()