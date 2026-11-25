# Backup and recovery

UnWeb uses a single SQLite database for reports, owner-scoped history, target grants, audit events, and browser-job state. Production also uses a persistent Redis volume for rate-limit and browser-dispatch state.

## SQLite backup

The API image includes an online-backup utility. It can run while the API is serving traffic and verifies the copied database with `PRAGMA integrity_check`.

```bash
sudo install -d -o 10001 -g 10001 -m 0700 backups
docker compose --env-file .env -f docker-compose.production.yml exec -T api \
  python -m app.maintenance backup \
  "/backups/unweb-$(date -u +%Y%m%dT%H%M%SZ).sqlite3"
```

Copy completed backups to protected off-host storage. Do not treat the local bind mount as the only backup.

## Restore

Stop every SQLite writer before restoring:

```bash
docker compose --env-file .env -f docker-compose.production.yml stop api browser-worker
docker compose --env-file .env -f docker-compose.production.yml run --rm --no-deps api \
  python -m app.maintenance restore /backups/your-backup.sqlite3 \
  --overwrite --confirm-restore
docker compose --env-file .env -f docker-compose.production.yml up -d api browser-worker frontend
```

Restore requires explicit confirmation and overwrite flags. The utility checkpoints the old WAL, verifies the source and destination, and installs the restored database atomically. Test restores in an isolated environment before relying on them.

## Redis recovery

Redis persistence is configured with AOF on the `redis_data` volume. Back up that volume according to the host's storage policy if preserving rate-limit and queued-dispatch state matters. SQLite remains the source of truth for report/job records; after Redis loss, inspect queued jobs and worker heartbeat before allowing new browser jobs.

## Recovery acceptance

A release deployment is not recovery-ready until operators have:

- a scheduled off-host SQLite backup;
- a tested restore command and documented RPO/RTO;
- a protected Redis volume or a documented decision to rebuild dispatch state;
- an isolated restore drill with integrity and owner-isolation checks;
- rollback images and a rollback procedure.
