# Maât alpha15: site checks and isolated Apache staging

`maat-site check` validates the site skeleton and permissions. `maat-site deploy` writes an **isolated**, localhost-only Apache configuration. It does **not** install a systemd unit, start Apache, change `/etc/apache2`, alter ports 80/443, configure the broker or SSH, or enable BBS access in PHP.

Keep ordinary Debian Apache (`apache2.service`, `/var/www/html`, ports 80/443) separate. `MaatIngress On` applies to the dedicated Maât instance and must not be inserted into a normal web listener. Only the validated SSH bridge/broker may reach `127.0.0.1:18082`.

Example, after creating `/var/www/maat/demo` (and correcting its ownership/permissions carefully):

```sh
./tools/maat-site check demo --root /var/www/maat
sudo install -d -m 0750 -o www-data -g www-data /run/maat-demo
sudo install -d -m 0700 -o root -g root /etc/maat
sudo ./tools/maat-site deploy demo --root /var/www/maat \
  --output /etc/maat/apache-demo.conf --port 18082 \
  --maat-module "$PWD/modules/mod_maat/.libs/mod_maat.so" \
  --php-module /usr/lib/apache2/modules/libphp8.1.so \
  --runtime /run/maat-demo
sudo apache2 -t -f /etc/maat/apache-demo.conf
```

This is a **configuration staging only**. Never copy it to `sites-enabled`, call `a2ensite` for it, or restart ordinary `apache2.service`. PHP ABI and module versions must match your actual host. The example path `libphp8.1.so` is not a universal default. The local broker, SSH forced command and PHP module still need to be configured and tested before bringing the private listener online.

Run `./tests/e2e_native_apache_direct.sh` on an explicitly disposable isolated environment first to exercise the existing genuine SSH -> broker -> private Apache -> PHP `$_AUTH` path; it is not run by `maat-site deploy`.

The deployment configuration has no public interface and no daemon activation. Do not consider it production-ready: in particular runtime directory lifecycle, ownership isolation, client-proof authorization, dependency verification, and credentials provisioning require operational review.
