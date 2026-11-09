# Packaging of a single module

The example core module (`crates/core-api/examples/module_api.rs`) is the template: every module reuses this layout (spec sections 2 and 3, hardening in section 12).

## Install (one command)

```sh
sudo apt install ./ostyr-example-module.deb
```

The package creates the `ostyr-module` system user, a `0700` state directory `/var/lib/ostyr-example-module`, a random 32-byte store key and a TLS certificate under `/etc/ostyr/example-module/` signed by a throwaway local CA (`ca.crt` is the client trust anchor, the CA key is deleted; replace `tls.crt` and `tls.key` with your own, the service reloads on change), then enables and starts `ostyr-example-module.service`. The module listens on `https://0.0.0.0:8443`. `apt purge` removes the state, the secrets and the user.

Installed tools: `ostyr-auth-tool` (accounts, run as the service user) and `xdrctl` (CLI client).

First administrator (run as the service user so the store keeps its owner):

```sh
echo 'bootstrap admin a-long-passphrase' | sudo -u ostyr-module ostyr-auth-tool \
    /var/lib/ostyr-example-module/accounts.json /var/lib/ostyr-example-module/audit-cli.log \
    /etc/ostyr/example-module/store.key /etc/ostyr/example-module/compromised.txt
```

The tool keeps its own audit log (`audit-cli.log`): the running service holds the chain head of `audit.log`, so a second writer would break that chain. The output carries the TOTP secret to enrol in an authenticator. Then `xdrctl --server https://localhost:8443 --ca-file /etc/ostyr/example-module/ca.crt login --username admin --totp-code <code>` and `xdrctl ... whoami`.

## Build

`packaging/build.sh` (needs `cargo-deb` and `cargo-cyclonedx`, both installed with `cargo install --locked`) writes to `target/packaging/`:

- `ostyr-example-module.deb`, with the three CycloneDX 1.5 SBOMs (`core-api`, `core-auth`, `xdrctl`) under `/usr/share/doc/ostyr-example-module/sbom/`;
- `image/`, the container build context.

## Container image

`packaging/Dockerfile`: `gcr.io/distroless/cc-debian13:nonroot`, user `65532`, the module binary only. Run it with a read-only root filesystem, no capabilities and a writable volume for the state:

```sh
docker run --read-only --cap-drop ALL --security-opt no-new-privileges -p 8443:8443 \
    -v ostyr-config:/etc/ostyr:ro -v ostyr-state:/var/lib/ostyr ostyr-example-module
```

The image is built and run inside a lab VM (`packaging/tests/image-lab.sh`), never on a development host.

## Tests

- `packaging/tests/static-test.sh`: `hadolint`, `systemd-analyze verify` and `security`, unit directives, `sh -n` and `shellcheck` on the maintainer scripts.
- `packaging/tests/postinst-test.sh`: runs the maintainer script in a scratch tree (modes, owners, idempotence, key kept on upgrade).
- `packaging/tests/deb-test.sh <deb>`: package metadata, contents and modes.
- `packaging/tests/deb-lab.sh <task-id>`: the live install proof on a booted `ubuntu-single` lab (timed install, service, user, security score, `xdrctl whoami`, purge).
- `packaging/tests/image-lab.sh <task-id>`: image build and run in a booted `ubuntu-single` lab.

## Measured install time

`apt-get install ./ostyr-example-module.deb` on a fresh `ubuntu-single` lab VM (TCG emulation, no KVM, 2 vCPU): 54 s, 77 s and 106 s in three runs, against the 10 minute limit. The time includes the unit start and the certificate generation.
