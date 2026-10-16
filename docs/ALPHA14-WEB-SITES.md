# Maât alpha14 — first PHP site scaffold (experimental)

`tools/maat-site create demo --root /var/www/maat` requires that the parent
`/var/www/maat` **already exists**. It creates `demo/public`,
`demo/private` and `demo/apache-private.conf.example`, refusing existing sites.
It never installs services, modifies Apache configuration, assigns UIDs, or
changes `/etc/maat` or `/var/lib/maat`.

First test without privileges:

```
mkdir -p /tmp/maat-sites
./tools/maat-site create demo --root /tmp/maat-sites
python3 tests/maat_site_test.py
```

On a disposable system, explicitly create a root you control before invoking
`sudo tools/maat-site create demo`. Prefer deploying with the same ownership
strategy as the existing private Apache instance. **Do not use a publicly
listening Apache instance for Maât SSH ingress.** `MaatIngress` is server-wide
and the generated Apache snippet is only a *reviewable fragment*, not a
running configuration. Match it to the proven SSH bridge, broker, native
`mod_maat` and PHP 8.1 `maat.so` deployment already under test.

The app reads only request-local `$_AUTH` provided by the native extension.
`identity_verified` is intentionally false for SSH key auth. It neither
accepts HTTP bearer identity nor claims a BBS identity. BBS verification
remains a separate experimental capability and is deliberately not exposed
as a PHP grant in alpha14. The private folder must not be Web-accessible.

No shell access, new system account, public port, site enablement, or registry
root/peer changes are performed by this tool.
