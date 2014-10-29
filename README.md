# modsecparser
--------------

## mod_security audit log parser

This is a CLI tool which parses 
[mod_security](https://www.modsecurity.org/) 
[concurrent audit logs](https://github.com/SpiderLabs/ModSecurity/wiki/ModSecurity-2-Data-Formats#Concurrent_Audit_Log_Format)
and writes them into a Postgres database. It is designed to be run from `cron(1)` in a schedule that fits your workload.

## Modus operandi

`modsecparser` will read the concurrent audit log index file and try to open and parse each concurrent audit log transaction file.
Each transaction will then be inserted in the database.

After reaching the end of the index file, `modsecparser` will remove all parsed transaction files as well as
remove stale transaction files and empty directories in the 
[SecAuditLogStorageDir](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual#SecAuditLogStorageDir)

On subsequent runs, it will seek to the last position in the audit log index file and continue operation from there.

## Getting started

See the [sample configuration](docs/modsecparser-example.yml) for configuration details and the `modsecparser --help` output for runtime options.

You can use `flock(1)` to prevent concurrent runs when using a cronjob:

`*/2 * * * * /usr/bin/flock -n /var/run/modsecparser /usr/bin/modsecparser`

Output will be logged to `/var/log/modsecparser.log` by default.

## Requirements

 * Ruby >= 1.9.1
 * pg >= 0.13.2
