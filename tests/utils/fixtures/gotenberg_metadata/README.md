# Gotenberg metadata fixtures

These are source reconstructions, not production captures. `version.txt` contains
the exact plain-text compiled server release (`8.30.1`, no newline), and `root.html`
is the literal root response from `pkg/modules/api/api.go` at tag v8.30.1, commit
`9bf12e7cb99f1ad70aee2e142fcba4750c3788fa`.

Source attribution: the release workflow passes its tag to
`.github/actions/build-test-push/build.sh`, which removes `v` and sets the Docker
`GOTENBERG_VERSION` build argument. `build/Dockerfile` injects `cmd.Version` through
Go linker flags. `cmd/gotenberg.go` assigns it to `gotenberg.Version`, returned
unchanged by `GET /version`. `test/integration/features/version.feature` confirms
plain-text metadata and 401 when optional API Basic Auth is enabled.

The same version/root pair was checked at v8.20.0
(`7ca1d118a1e167fea8f4cfe1cf51d696b190bfd3`), v8.25.0
(`43354cafb19a1da43801a35489ef91052008d0f3`), v8.30.0
(`a80191a2881184a3529696ebf9cdcd82a0008442`), v8.31.0
(`db51f9026d13357aecc23e3c99ba6937ac09fbfc`) and v8.32.0
(`fe1b0020b8f211575559e6cf7e5ef6cc5a0545ca`). v8.10.0 has version metadata but no
matching root banner; v8.0.0 lacks the version route. Such formats are unsupported.

The helper accepts only this exact product banner, a canonical stable numeric
version and an absent-route 404. It does not inspect the debug endpoint or infer
module versions, enabled conversions, configured filters, authentication state or
exploitability. Custom root paths and modified/snapshot/prerelease builds are
inconclusive. Self-reported metadata cannot identify an unmarked fork/backport.
