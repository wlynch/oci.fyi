# oci.fyi

Inspect signature and attestation information for OCI images!

This is heavily inspired/influenced by [oci.dag.dev](https://oci.dag.dev) 🫶

## Releasing

```sh
$ KO_DOCKER_REPO="us-central1-docker.pkg.dev/oci-fyi/oci-fyi" gcloud run deploy oci-fyi --region=us-central1 --image $(ko build -B .)
```
