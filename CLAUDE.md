# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run

```bash
nix build              # build via flake (preferred)
go build -o result     # direct Go build (version will be "dev")
```

Nix formatting: `nix fmt` (uses alejandra)

No test suite exists.

## Architecture

Network-unlock implements a protocol for remotely unlocking LUKS-encrypted disks at boot time using secret sharing (Na XOR Nb). Two peers split a key into two shares: one stored on the server, one on the client's boot partition. At boot, the initrd client retrieves the server's share over mTLS and reconstructs the LUKS key.

### Four subcommands (defined in `main.go`, implemented in `cmd/`)

- **serve** - Long-running server exposing two HTTP endpoints: plain HTTP `/register/` on the internal network (trusted), and mTLS `/unlock` on the external network. In-memory store with TTL-based expiry.
- **prepare** - Pre-reboot client step: generates ephemeral TLS cert, splits a random secret into two shares, registers one share with the server, enrolls XOR of both shares as a LUKS key, writes credentials to `/boot/unlock/`.
- **unlock** - Initrd client: reads credentials from boot partition, retrieves the server's share over mTLS, XORs with local share, writes the reconstructed key to a FIFO for systemd-cryptsetup. Sends sd_notify when ready.
- **cleanup** - Removes the ephemeral LUKS key slot after successful boot.

### `lib/` - core logic

- `server.go` - HTTP handlers for register and unlock; in-memory `map[Fingerprint]*Entry` with mutex; `IP_FREEBIND` socket option for early binding before network is fully up.
- `client.go` - HTTP clients for register (plain) and unlock (mTLS with peer cert pinning).
- `crypto.go` - ECDSA P-256 certificate generation, PEM encoding.
- `luks.go` - Wrappers around `cryptsetup luksAddKey`/`luksKillSlot`; resolves dm-crypt mapper device to backing block device via sysfs.

### `modules/` - NixOS integration

- `server.nix` - systemd service with `DynamicUser`, `cap_net_raw` for freebind.
- `client.nix` - prepare service (runs cleanup on start, prepare on stop), initrd unlock service wired into `systemd-cryptsetup@`. Requires systemd-networkd in initrd.

### Custom CLI type

`cmd/ip_flag.go` implements `IPFlag` as a custom `urfave/cli` generic flag type for `net.IP` parsing.
