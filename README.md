# mcp-abap-adt-auth-providers

The repository of `@mcp-abap-adt/auth-providers`, every `IAuthProvider` for SAP ABAP ADT.

The package lives in [`packages/auth-providers`](packages/auth-providers/README.md); its README,
CHANGELOG and docs are there. This root is private and holds only the tools that build, check and
publish the packages of the repository.

The packages are not npm workspaces: each installs its own dependencies from the registry.

```bash
npm ci --ignore-scripts          # the root's tools
npm run install:packages         # each package's dependencies
npm run build                    # every package, in publishOrder
npm run check                    # build, type-check, lint, tests, shape check, packed tarballs, publish path
npm run release:publish          # publishes the packages whose version is not on the registry (the owner runs it)
```

Releases are tagged `<package directory>-v<version>`, for example `auth-providers-v7.0.0`.
