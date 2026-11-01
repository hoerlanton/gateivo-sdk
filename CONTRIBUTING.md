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

Changes to exported behavior should include a relevant test. Keep application-specific adapters, deployment credentials and customer data out of this repository. Use fictional accounts and records in reproductions.

For a proposed feature, describe the app workflow, what you tried and the missing capability. Please open an issue before a substantial API redesign so we can discuss compatibility and scope.

Report security vulnerabilities through [SECURITY.md](SECURITY.md).

## Preparing a preview archive

Registry publishing stays disabled. A public GitHub preview must have an agreed licence, a matching `LICENSE` file and matching licence metadata in `package.json` and `package-lock.json`.

1. Finish source, documentation and dependency changes, then run `npm ci`.
2. Run `npm run check` and `npm run demo` on Node.js 22.6.0 and Node.js 24. Each check installs and tests an actual archive outside the checkout.
3. Run `npm run pack:preview`, then `npm run verify:release`. The guard compares the archive against the current distribution files and requires both consumer reports to match its integrity and the current example files.
4. Review the clean source tree and CI result before creating a GitHub prerelease. Attach only the verified archive, checksum and release notes. Do not upload test credentials or local operational records.

Build and verify again after source changes. The release guard checks distribution contents and receipts; it does not prove that the current source was compiled. Generated archives and local verification reports belong in the ignored `artifacts/` directory.
