# Host-reserved UID range — Maât 0.14

Configuration: `/etc/maat/uid_range.dab`.

The parser accepts the following **restricted, side-effect-free Dabsic subset**:

```dabsic
[UIDRange
    First = 1000000000
    Last = 2099999999
]
```

It is **not yet linked against the full Dabsic parser**. Unknown variables,
additional blocks, non-decimal integers, missing fields, duplicates and
unsafe files are rejected. Only root-owned regular files without group/other
write permission are accepted; symbolic links are rejected. The broker
refuses startup on parse failure or if the configured range excludes any
previously issued UID stored in the SQLite ledger.

The default range offers 1,100,000,000 unique connection UIDs and stays
below the signed 32-bit UID maximum (2,147,483,647). At 1 million **new SSH
connections per day** this is about three years, *not* infinite capacity.
A never-reused UID is a lifetime resource; at truly massive load the
allocation strategy will need a carefully verified safe recycling / namespace
strategy. These are NOT HTTP request UIDs if several requests reuse SSH.

Host administrator MUST reserve this entire range globally, excluding it
from manual accounts, LDAP/NSS, systemd DynamicUser, subordinate UID pools
(`/etc/subuid`), containers, user namespaces and other privileged services.
Linux has no global kernel reservation for numeric UIDs; a config file cannot
guarantee exclusivity against another privileged service. **Fail-closed
checking of every NSS mapping before each allocation is defense in depth,
not host-wide reservation**. Do not deploy without auditing all local UID
allocators and namespace mappings.

WARNING: after allocation, do not narrow or move the range to exclude any
UID already recorded in `maat_ephemeral_uids`. The repository rejects it.
A prior 0.13 database using 1800000000..1899999999 remains within the
new default range and continues monotonically from its historical maximum.

Testing: `maat-check-config /etc/maat/uid_range.dab` validates ownership,
regular-file type, permissions and syntax. Install does not enable services.
