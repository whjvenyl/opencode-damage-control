# Command Patterns

[Back to README](../README.md)

**108 patterns** -- 46 hard-blocked, 62 require confirmation.

Each pattern has an **action**:

| Action | Behavior |
|--------|----------|
| `block` | Hard block. Tool never executes. Error surfaced to the AI agent. |
| `ask` | User sees confirmation dialog with once/always/reject options. |

---

## Blocked Patterns (action: block)

These are hard-blocked. The tool never executes.

### System Destruction

| Pattern | Description |
|---------|-------------|
| `rm -rf /` | Recursive delete from root |
| Fork bombs | `:() { :` and `fork()` |
| `> /dev/sd*` | Direct device write |
| `dd ... of=/dev/` | dd writing to device |
| `mkfs.*` | Format filesystem |
| `kill -9 -1` | Kill all processes |
| `killall -9` | Kill all processes |
| `pkill -9` | pkill with SIGKILL |
| `shutdown` / `reboot` / `init 0` | System shutdown/reboot/halt |
| `format c:` | Windows format |
| `sudo rm` | sudo rm |

### SQL (no WHERE clause)

| Pattern | Description |
|---------|-------------|
| `DROP TABLE` | SQL DROP TABLE |
| `DROP DATABASE` | SQL DROP DATABASE |
| `DELETE FROM ... ;` | DELETE without WHERE clause |
| `DELETE * FROM` | DELETE * (will delete ALL rows) |
| `TRUNCATE TABLE` | SQL TRUNCATE TABLE |

### Git (irreversible)

| Pattern | Description |
|---------|-------------|
| `git push --force` | Force push (blocks `--force` but NOT `--force-with-lease`) |
| `git push -f` | Force push shorthand |
| `git stash clear` | Deletes ALL stashes |
| `git filter-branch` | Rewrites entire history |
| `git reflog expire` | Destroys recovery mechanism |
| `git gc --prune=now` | Can lose dangling commits |

### Shell

| Pattern | Description |
|---------|-------------|
| `curl ... \| sh` | Pipe to shell |
| `wget ... \| sh` | Pipe to shell |

### Docker / Containers

| Pattern | Description |
|---------|-------------|
| `docker rm -f $(docker ps)` | Force removes all running containers |
| `kubectl delete all --all` | Deletes all K8s resources |
| `kubectl delete --all --all-namespaces` | Deletes across all namespaces |

### Infrastructure

| Pattern | Description |
|---------|-------------|
| `terraform destroy` | Destroys all infrastructure |
| `pulumi destroy` | Destroys all resources |
| `aws s3 rm --recursive` | Deletes all S3 objects |
| `aws s3 rb --force` | Force removes S3 bucket |
| `gcloud projects delete` | Deletes entire GCP project |
| `firebase projects:delete` | Deletes Firebase project |
| `firebase firestore:delete --all-collections` | Wipes all Firestore data |

### Databases / Services

| Pattern | Description |
|---------|-------------|
| `redis-cli FLUSHALL` | Wipes ALL Redis data |
| `dropdb` | PostgreSQL drop database |
| `mysqladmin drop` | MySQL drop database |
| `mongosh ... dropDatabase` | MongoDB drop database |
| `mongo ... dropDatabase` | MongoDB drop database (legacy shell) |
| `npm unpublish` | Removes package from registry |
| `gh repo delete` | Deletes GitHub repository |

---

## Confirmed Patterns (action: ask)

These prompt the user for confirmation. The user can approve once, approve always, or reject.

### File Operations

| Pattern | Description |
|---------|-------------|
| `rm -rf` / `rm -f` / `rm -R` | rm with recursive or force flags |
| `rm --recursive` / `rm --force` | rm with long flag variants |
| `rmdir --ignore-fail-on-non-empty` | rmdir ignore-fail |

### Git (recoverable but risky)

| Pattern | Description |
|---------|-------------|
| `git reset --hard` | Hard reset (suggest --soft or stash) |
| `git clean -fd` | Clean with force/directory flags |
| `git checkout -- .` | Discard all uncommitted changes |
| `git restore .` | Discard all uncommitted changes |
| `git stash drop` | Permanently delete a stash |
| `git branch -D` | Force delete branch (even if unmerged) |
| `git push --delete` | Delete remote branch |
| `git push origin :branch` | Delete remote branch (refspec syntax) |

### SQL (targeted)

| Pattern | Description |
|---------|-------------|
| `DELETE FROM ... WHERE` | SQL DELETE with WHERE clause |

### Permissions

| Pattern | Description |
|---------|-------------|
| `chmod 777` / `chmod -R 777` | World-writable permissions |
| `chown -R` | Recursive ownership change |

### Cloud / Infrastructure

| Pattern | Description |
|---------|-------------|
| `aws ec2 terminate-instances` | Terminate EC2 instances |
| `aws rds delete-db-instance` | Delete RDS instance |
| `aws cloudformation delete-stack` | Delete CloudFormation stack |
| `aws dynamodb delete-table` | Delete DynamoDB table |
| `aws eks delete-cluster` | Delete EKS cluster |
| `aws lambda delete-function` | Delete Lambda function |
| `aws iam delete-role` / `delete-user` | Delete IAM role or user |
| `gcloud compute instances delete` | Delete GCE instances |
| `gcloud sql instances delete` | Delete Cloud SQL instances |
| `gcloud container clusters delete` | Delete GKE clusters |
| `gcloud storage rm -r` | Recursive cloud storage delete |
| `gcloud functions delete` | Delete Cloud Function |
| `gcloud iam service-accounts delete` | Delete service account |

### Docker / Kubernetes

| Pattern | Description |
|---------|-------------|
| `docker system prune -a` | Remove all unused Docker data |
| `docker rmi -f` | Force remove Docker images |
| `docker volume rm` / `docker volume prune` | Remove Docker volumes |
| `kubectl delete namespace` | Delete K8s namespace |
| `helm uninstall` | Uninstall Helm release |

### Databases

| Pattern | Description |
|---------|-------------|
| `redis-cli FLUSHDB` | Wipe Redis database |
| `firebase database:remove` | Remove Firebase Realtime Database data |

### Hosting / Deployment

| Pattern | Description |
|---------|-------------|
| `vercel remove --yes` / `vercel projects rm` | Remove Vercel deployment or project |
| `vercel env rm --yes` | Remove Vercel environment variable |
| `netlify sites:delete` / `netlify functions:delete` | Delete Netlify site or function |
| `heroku apps:destroy` / `heroku pg:reset` | Destroy Heroku app or reset Postgres |
| `fly apps destroy` / `fly destroy` | Destroy Fly.io app |
| `wrangler delete` | Delete Cloudflare Worker |
| `wrangler r2 bucket delete` | Delete R2 bucket |
| `wrangler kv:namespace delete` | Delete KV namespace |
| `wrangler d1 delete` / `wrangler queues delete` | Delete D1 database or Queue |
| `firebase hosting:disable` / `firebase functions:delete` | Disable Firebase hosting or delete function |
| `serverless remove` / `sls remove` | Remove Serverless Framework stack |
| `sam delete` | Delete SAM application |
| `doctl compute droplet delete` / `doctl databases delete` | Delete DigitalOcean resources |
| `supabase db reset` | Reset Supabase database |

### Other

| Pattern | Description |
|---------|-------------|
| `history -c` | Clear shell history |
