# Udap.Pki.Cli

A CLI tool for managing UDAP PKI Certificate Revocation Lists (CRLs). Packaged as a Docker image with the Google Cloud CLI for uploading CRLs to GCP storage. Can run as a Cloud Run Job on a weekly schedule.

## Docker

### Build

From the repository root:

```bash
docker build -t udap-pki-cli -f examples/Udap.Pki.Cli/Dockerfile .
```

### Interactive Use

```bash
docker run -it --name udap-pki-cli -v udap-pki-gcloud:/root/.config/gcloud --entrypoint /bin/bash udap-pki-cli
```

This starts an interactive bash shell inside the container. The named volume `udap-pki-gcloud` persists your `gcloud` authentication between container runs.

### Resume a Stopped Container

```bash
docker start -ai udap-pki-cli
```

### Remove and Recreate

```bash
docker rm udap-pki-cli
docker run -it --name udap-pki-cli -v udap-pki-gcloud:/root/.config/gcloud --entrypoint /bin/bash udap-pki-cli
```

## CLI Usage

Inside the container:

```bash
# Authenticate with Google Cloud (first time only, persisted in the volume)
gcloud auth login --no-launch-browser
gcloud auth application-default login --no-launch-browser
gcloud config set project udap-idp

# Update CA CRL in production
./Udap.Pki.Cli crl-update --type CA --prod

# Update SubCA CRL in production
./Udap.Pki.Cli crl-update --type SubCA --prod

# Update both CA and SubCA CRLs in one run
./Udap.Pki.Cli crl-update-all --prod

# Test mode (writes to local disk instead of GCP)
./Udap.Pki.Cli crl-update --type CA

# Set custom CRL validity period (default: 7 days)
./Udap.Pki.Cli crl-update --type CA --days 30 --prod

# Non-interactive with password
./Udap.Pki.Cli crl-update-all --prod --password "your-password"
```

### Commands

| Command          | Description                                       |
|------------------|---------------------------------------------------|
| `crl-update`     | Generate and publish an updated CRL               |
| `crl-update-all` | Update both CA and SubCA CRLs in one run          |

### Options

| Option          | Description                                                          |
|-----------------|----------------------------------------------------------------------|
| `-t, --type`    | CRL type: `CA` or `SubCA` (required for `crl-update`)               |
| `--days`        | Days until CRL next update (default: 7)                              |
| `--prod`        | Production mode; uploads to GCP. Omit for test.                      |
| `--password`    | CA P12 password. Can also be set via `CA_P12_PASSWORD` env var.      |

In production mode, after uploading the CRL to the public bucket, the tool automatically invalidates the Cloud CDN cache for the updated CRL path. The URL map name is configured in `appsettings.json` under `PublicCertStore.CdnUrlMapName`.

## Cloud Run Job Deployment

The Docker image defaults to running `crl-update-all --prod`. Deploy as a Cloud Run Job for scheduled weekly CRL updates.

### One-Time GCP Setup

```bash
# 1. Create a service account
gcloud iam service-accounts create udap-crl-updater \
  --display-name="UDAP CRL Updater"

# 2. Grant storage access to both buckets
gcloud storage buckets add-iam-policy-binding gs://cert_store_private \
  --member="serviceAccount:udap-crl-updater@udap-idp.iam.gserviceaccount.com" \
  --role="roles/storage.objectAdmin"

gcloud storage buckets add-iam-policy-binding gs://crl.fhircerts.net \
  --member="serviceAccount:udap-crl-updater@udap-idp.iam.gserviceaccount.com" \
  --role="roles/storage.objectAdmin"

# 3. Grant CDN cache invalidation permission
gcloud projects add-iam-policy-binding udap-idp \
  --member="serviceAccount:udap-crl-updater@udap-idp.iam.gserviceaccount.com" \
  --role="roles/compute.loadBalancerAdmin"

# 4. Grant Secret Manager access
gcloud projects add-iam-policy-binding udap-idp \
  --member="serviceAccount:udap-crl-updater@udap-idp.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

# 5. Grant Cloud Run invoker (for Cloud Scheduler to trigger the job)
gcloud projects add-iam-policy-binding udap-idp \
  --member="serviceAccount:udap-crl-updater@udap-idp.iam.gserviceaccount.com" \
  --role="roles/run.invoker"

# 6. Store the CA P12 password in Secret Manager
echo -n "YOUR_PASSWORD" | gcloud secrets create ca-p12-password --data-file=-

# 7. Create a Cloud Build trigger (connect repo, set trigger on tag push,
#    point to examples/Udap.Pki.Cli/cloudbuild.yaml)

# 8. Schedule weekly execution with Cloud Scheduler
gcloud scheduler jobs create http udap-crl-weekly \
  --location=us-west1 \
  --schedule="0 6 * * 1" \
  --uri="https://us-west1-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/udap-idp/jobs/udap-crl-update:run" \
  --http-method=POST \
  --oauth-service-account-email=udap-crl-updater@udap-idp.iam.gserviceaccount.com
```

### Deploy the Cloud Run Job

From the repository root, submit via Cloud Build:

```bash
gcloud builds submit --config examples/Udap.Pki.Cli/cloudbuild.yaml --substitutions=TAG_NAME="0.0.1"
```

Subsequent deployments can also be automated via a Cloud Build trigger on tag push (step 7 above).

### Manual Execution

```bash
gcloud run jobs execute udap-crl-update --region us-west1
```
