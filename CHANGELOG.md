# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [semantic versioning](https://semver.org/). Syncloom is a public preview until 1.0.

## [0.1.0] - 2026-11-02

First public preview.

### Added
- REST API and gRPC change feed (gRPC-Web for browsers) on axum and tonic.
- Accounts with mandatory second factor: any number of authenticator apps and security keys, recovery codes, admin 2FA reset. OIDC sign-in.
- Encrypted files with versions and trash, key/value namespaces with compare-and-set, shares, public links, quotas and an admin API.
- Retention jobs, Postgres metadata, blobs on a filesystem volume or an S3-compatible store.
- Docker image; the repository holds 32 integration tests.

### Known limits
- The S3 backend has not been tested against a real S3 store.
- Revoking a share does not rotate keys.
