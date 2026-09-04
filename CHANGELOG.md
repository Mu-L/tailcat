# tailcat changelog

## v0.6.0 (2026-09-04)

- Application-layer UDP support: servers can serve and forward UDP
  flows, clients can dial UDP ports, and `tailcat socks` supports
  SOCKS5 UDP ASSOCIATE. Idle incoming UDP flows close after a
  configurable timeout, two minutes by default. (@sksingh2005)
- SSH public key authentication: `tailcat serve ssh` takes
  `--ssh-authorized-keys` with literal keys, key files, or
  `user@github` to fetch a GitHub user's keys.
- tailcat addresses now include a WireGuard pre-shared key by default;
  `--psk=false` opts out, and servers warn when serving without one.
- `tailcat forward` can forward through exit-node servers to arbitrary
  IP:port targets, and a local port of 0 picks a free one. (@Audi-dask)
- `--derpmap-url` defaults from the `TAILCAT_DERPMAP_URL` environment
  variable.
- Served processes receive the authenticated peer's node key in
  `TAILCAT_PEER_KEY`, in the same `nodekey:...` form `--allow` takes.
  (@seffs)
- `tailcat genkey --embed-derp-map` no longer panics when no fixed
  region is set, and unknown `--region` values report an error naming
  the missing region. (@gmkbenjamin; reported by @chanchiwai-ray)
- Proxied TCP connections finish their teardown instead of losing data
  queued at close.
- Connection setup resends pings lost by busy relays instead of
  waiting out whole timeouts, and SOCKS dials get a longer budget than
  a single WireGuard handshake.
- Packaging: the Nix flake builds in CI with Go built from source and
  an automatically refreshed vendor hash; conda-forge installation is
  documented (@pavelzw); the test suite is hermetic and several times
  faster, for reliable distro package builds.

## v0.5.0 (2026-09-02)

- New `tailcat forward` subcommand: listen on a local TCP port and
  forward each connection to a tailcat server. (@Audi-dask)
- The connection string is now called a "tailcat address" everywhere;
  the old flag spellings remain as hidden aliases.
- Write-only file shares are actually write-only: drop boxes no longer
  leak whether a file already exists, and the new `:wo+` mode allows
  overwrites.
- Mistyped addresses no longer fall through to DNS lookups.
- Hardened validation of arguments passed to ssh and scp child
  processes.
- Added SECURITY.md.
- Windows: the SSH server looks for pwsh.exe. (@gcurtis)

## v0.4.0 (2026-08-31)

- File transfer: servers share a directory with
  `tailcat serve --files=DIR` (read-only, read-write, or write-only
  drop box modes) over the SSH SFTP subsystem, and new `cp`, `recv`,
  and `ls` subcommands use it.
- New `serve` subcommand as the long-form way to run servers.
- The CLI was rewritten with declarative subcommands: fuller help with
  examples on every subcommand, and requested help prints to stdout.
- SSH support on Windows, and CI now tests macOS and Windows; the
  integration tests were made Windows-portable. (@FenjuFu)
- Official release binaries build with a trimmed feature set for
  smaller size; the tag list is documented in build-tags.md.
- Addresses with null DERP regions or nodes are rejected, and the meow
  packet encoding gained tests. (@CharmingGroot)
- `genkey --client --key=default` is rejected as a likely mix-up, and
  `--version` keeps working as an unadvertised alias.
- The Nix flake's vendor hash stays fresh automatically.
- Documented Homebrew installation for macOS.

## v0.3.0 (2026-08-30)

- Node and disco keys are now separate, matching Tailscale's split
  between identity and path discovery.
- Local dev DERP mode is usable end to end and tested hermetically.
- Clients drain the final ACK before exiting, so the last bytes of a
  transfer are not lost at close.
- Documented the Arch Linux package. (@BarbUk)

## v0.2.0 (2026-08-30)

- Addresses with malformed public keys are rejected with a clear
  error instead of failing later. (@keyurbodar)
- Fixed a close panic in the browser (Wasm) build.
- Documented the prebuilt binaries and container image.

## v0.1.0 (2026-08-30)

First tagged release. Highlights:

- Release process: static Linux binaries, deb and rpm packages,
  Windows zips, checksums, and container images on ghcr.io.
- Browser demo published to GitHub Pages, with the demo reusable by
  other servers.
- A Nix flake.
- DERP maps are cached on disk with ETag revalidation, plus a
  process-wide in-memory cache.
- `ping` reports the network path and gained `--until-direct`; peers
  advertise their endpoints on important events so direct paths form
  reliably.
- `genkey --fixed-region` bakes a region choice into a key.
- The Go library's zero value `Server` and `Client` are usable
  directly.
- Closing a `Server` closes its active connections and backend
  resources. (@0xcadams)
- SOCKS mode runs without a child command, takes a custom listen
  address (@tw4452852), and uses the configured client key.
- The ssh ProxyCommand forwards a custom DERP map (@zukka77) and uses
  a short deterministic ControlPath (@korjavin).
- README fixes. (@CooperSheroy)

## derpcat becomes its own Go module (2026-03-07)

- Left the tailscale.com fork: commit
  [68ac83e73](https://github.com/tailscale/tailcat/commit/68ac83e73)
  ("derpcat: use tailscale.com as a library instead of forking") made
  derpcat its own Go module, depending on tailscale.com as a regular
  library. Renamed to tailcat in
  [e6b242f14](https://github.com/tailscale/tailcat/commit/e6b242f14)
  (2026-07-17). (@bradfitz)

## derpcat (2023-09-14)

- First worked, as "derpcat" inside a fork of the tailscale.com repo,
  in commit
  [911915fbb](https://github.com/tailscale/tailcat/commit/911915fbb)
  ("derpcat: it's alive!"), written on UA 605 PDX-ORD without buying
  the wifi. (@bradfitz)
