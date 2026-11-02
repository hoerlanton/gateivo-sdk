# Contributing

Gateivo is an experimental SDK. A small reproduction of an integration problem is particularly useful feedback.

Use a supported Node.js version and the committed lockfile:

```sh
npm ci
npm run check
npm run demo
```

`check` includes the packaged clean-consumer verification. Run `npm run verify:consumer` separately when only the packaging boundary needs checking.

The authenticated WorkOS example requires Node.js 24. After building, run `npm run test:workos` and `npm run verify:workos` for its focused tests and isolated signed-provider acceptance. These are separate CI steps on Node.js 24; the generic SDK retains Node.js 22.6 support. They do not use a live WorkOS account or log in to Claude.

The packaged Express connection and PostgreSQL store also support Node.js 22.6. Run `npm run verify:workos:postgres` on both supported runtimes with `GATEIVO_REFERENCE_TEST_DATABASE_URL` pointing to an explicitly disposable loopback database named `gateivo_reference_test`. The verifier rejects hosted destinations and other database names. It installs the actual archive in a separate app and checks durable consent, restart/concurrency behavior and old-generation rejection using signed synthetic provider responses. CI supplies a disposable PostgreSQL service for both runtime jobs.

Changes to exported behavior should include a relevant test. Keep application-specific adapters, deployment credentials and customer data out of this repository. Use fictional accounts and records in reproductions.

The source-only HTTP-backend example has its own boundary tests and local MCP
exercise. After building, run `node --test examples/http-backend/*.test.mjs` and
`node examples/http-backend/demo.mjs` on both supported runtimes. Its upstream
server and approvals are fictional; these checks do not establish Laravel or
hosted OAuth compatibility. No PHP runtime or external API is contacted.

For a proposed feature, describe the app workflow, what you tried and the missing capability. Please open an issue before a substantial API redesign so we can discuss compatibility and scope.

Report security vulnerabilities through [SECURITY.md](SECURITY.md).

## Preparing a preview archive

Registry publishing stays disabled. A public GitHub preview must have an agreed licence, a matching `LICENSE` file and matching licence metadata in `package.json` and `package-lock.json`.

1. Finish source, documentation and dependency changes, then run `npm ci`.
2. Run `npm run check` and `npm run demo` on Node.js 22.6.0 and Node.js 24. Each check installs and tests an actual archive outside the checkout.
3. Run the Node 24 reference tests and isolated SQLite check, and run `npm run verify:workos:postgres` on both runtimes using the disposable local database. Run `npm run pack:preview`, then `npm run verify:release`. The guard compares the archive against the current distribution files and requires both SDK consumer reports and both PostgreSQL connection reports to match its integrity and current example files.
4. Review the clean source tree and CI result before creating a GitHub prerelease. Attach only the verified archive, checksum and release notes. Do not upload test credentials or local operational records.

Build and verify again after source changes. The release guard checks distribution contents and receipts; it does not prove that the current source was compiled. Generated archives and local verification reports belong in the ignored `artifacts/` directory.
