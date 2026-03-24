# Network Unlock: Remote LUKS disk decryption over mTLS
```mermaid
sequenceDiagram
    participant Server
    participant Client
    Note over Client,Server: TRUSTED INTERNAL NETWORK
    Note over Server: Generate TLS CA
    Note over Client: Generate ephemeral<br>TLS KEY and CERT<br> with internal<br>and external IPs<br>in subjectAltName
    Note over Client: Generate Na and Nb,<br>enroll Na XOR Nb<br>on LUKS key slot
    Client->>Server: Register(hash(CERT), Na)
    Note over Server: Store sourceIP,<br>hash(CERT)<br>and Na with TTL
    Server-->>Client: CA
    create participant Boot@{ "type" : "database" } as Boot Partition
    Client->>Boot: Nb, CERT,<br> KEY, CA
    Note over Client: REBOOT
    Note over Client,Server: PUBLIC NETWORK
    destroy Boot
    Boot-->>Client: Nb, CERT,<br>  KEY, CA
    Client->>Server: Unlock() over mTLS<br>(require client cert without verifying)
    Note over Server: If within TTL, compare cert<br>against hash(CERT), and<br>stored and new sourceIPs<br>against subjectAltName
    Server-->>Client: Na
    Note over Client: Unlock disk with<br>Na XOR Nb
```

## Threat Model

- Internal network is trusted, nodes are not. However, a compromised network unlock server won't collude with a network attacker.
- Attacker has full access to the public network.
- Attacker has eventual access to the disk and can recover any deleted file.

Any full disk encryption unlocking scheme of a remote machine without a TPM, e.g. SSH-ing into a dropbear initramfs, is vulnerable to the same attacker: someone who can read your unencrypted /boot partition and sit on your network. Against dropbear, they extract the SSH host key from the initramfs, impersonate your server, and capture the passphrase you type.

This protocol doesn't strive to be stronger than that, it accepts the same threat model. An attacker with disk access + network access within the TTL window can steal the ephemeral TLS cert + key from /boot, connect to the server, and retrieve Na. The protocol just removes the human from the loop while being no worse than typing a password over SSH.
