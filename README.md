# syncloom-server

The Syncloom server (Rust, axum and tonic): accounts with mandatory two-step sign-in (authenticator apps and security keys), OpenID Connect, encrypted file and key/value storage, versions and trash, sharing and public links, admin, and the change feed over REST, gRPC and gRPC-Web. The server only ever sees ciphertext.

Part of [Syncloom](https://github.com/Syncloom), a self-hosted, end-to-end encrypted file sync and key/value store. Status: **public preview (0.1)**.

```bash
docker run -d --name syncloom-pg -e POSTGRES_PASSWORD=syncloom -e POSTGRES_DB=syncloom -p 55432:5432 postgres:17-alpine
cargo test                       # integration tests against that Postgres
```
To run a full stack, use [syncloom-deploy](https://github.com/Syncloom/syncloom-deploy). Needs `../syncloom-core`.

## Working with the other repositories

The Syncloom repositories reference each other by relative path. Clone the ones you need **side by side in one folder**, for example `syncloom-core`, `syncloom-server` and `syncloom-web` next to each other.

## License

Apache License 2.0, see [LICENSE](LICENSE).
