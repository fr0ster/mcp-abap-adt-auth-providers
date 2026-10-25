# mcp-abap-adt-auth-providers

The repository of two packages, each with its README and CHANGELOG in its directory:

- [`packages/auth-providers`](packages/auth-providers/README.md) — `@mcp-abap-adt/auth-providers`,
  every `IAuthProvider` for SAP ABAP ADT;
- [`packages/auth-spnego-gssapi`](packages/auth-spnego-gssapi/README.md) —
  `@mcp-abap-adt/auth-spnego-gssapi`, a negotiate token source for `SpnegoAuthProvider` over the
  system's GSS-API, through the native `kerberos` binding.

Neither depends on the other. This root is private and holds only the tools that build, check and
publish the packages of the repository.

The packages are not npm workspaces: each installs its own dependencies from the registry, with
install scripts off. The one native build is `kerberos` in `packages/auth-spnego-gssapi`
(`npm rebuild kerberos --build-from-source` there, allowed by its `allowScripts`); without it that
package's tests replace the binding, and its load test is skipped.

```bash
npm ci --ignore-scripts          # the root's tools
npm run install:packages         # each package's dependencies
npm run build                    # every package, in publishOrder
npm run check                    # build, type-check, lint, tests, shape check, packed tarballs, publish path
npm run release:publish          # publishes the packages whose version is not on the registry (the owner runs it)
```

Releases are tagged `<package directory>-v<version>`, for example `auth-providers-v7.0.0` or
`auth-spnego-gssapi-v0.1.0`.
