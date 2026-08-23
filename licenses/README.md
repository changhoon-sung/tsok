# Dependency licenses

`tsok.md` lists the union of dependencies linked into the four release
targets: Linux and macOS on `amd64` and `arm64`.

The report is generated with
[`google/go-licenses`](https://github.com/google/go-licenses) v2.0.1. Update it
after dependency or release-target changes by running:

```console
scripts/generate-licenses.sh
```

CI regenerates the report and fails if the committed copy is stale. Review new
or changed dependencies and their license classifications before accepting the
generated diff.
