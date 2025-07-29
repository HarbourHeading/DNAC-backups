# DNAC Manage backups
This python CLI tool will show or delete older automation backups on Cisco DNA Center.<br>
This tool can show the current backups, delete a specific backup by id<br>
or delete all backups older than a certain time (the default is 2 years).

## Listing the backups
Run the manage_backup command with no arguments to list backups.

```bash
python manage_backups.py 
```
Output:
```
Backup-id                               name                          timestamp                     time
70a0a277-8ff6-48b3-8a7b-832eef048c5a    test-backup                   1666243182.6503744            2022-10-20 16:19:42
```

## Deleting old backups
By default, backups older than 2 year are deleted. To delete a backup more recently,<br>
use the `--older <secs>` argument. For example, older than 1 year, you can use `--older 31556952`

```bash
python manage_backups.py --older 31556952
```

## Deleting a specific backup
Provide a backup id and just that backup will be deleted.

```bash
python manage_backups.py --delete 70a0a277-8ff6-48b3-8a7b-832eef048c5a
```
*Note: This API call returns the exact same message, even if a backup by the supplied ID does not exist.*

## Dryrun the command
Dryrun the command. Shows what the command will do without consequences. Shows all backups that would be deleted (1.5 years or older).
```bash
python manage_backups.py --older 47335428 --dryrun
```

## Enable debug logs
Add -v argument to get verbose debug logging.
```
python manage_backups.py -v
```