PHP_ARG_ENABLE([maat], [whether to enable Maât], [AS_HELP_STRING([--enable-maat], [Enable native Maât SSH authentication])], [no])
if test "$PHP_MAAT" != "no"; then
  PHP_NEW_EXTENSION([maat], [maat.c], [$ext_shared])
fi

PHP_ARG_ENABLE([maat-apache-abi], [enable native Apache/PHP 8.1 request context],
  [AS_HELP_STRING([--enable-maat-apache-abi], [Link Maât to Apache request context; PHP 8.1 only])], [yes])
dnl PHP_ARG_ENABLE may return "yes, shared" for shared extensions. An exact
dnl comparison with "yes" silently produced a module without Apache support.
dnl Maât no longer supports an anonymous-only fallback extension.
case "$PHP_MAAT_APACHE_ABI" in
  yes*)
    AC_DEFINE([MAAT_APACHE_REQUEST_ABI], [1], [Use Apache 2.4 / php-apache2handler PHP 8.1 ABI])
    PHP_ADD_LIBRARY([dl], [1], [MAAT_SHARED_LIBADD])
    PHP_SUBST([MAAT_SHARED_LIBADD])
    ;;
  *)
    AC_MSG_ERROR([Maât requires --enable-maat-apache-abi (PHP 8.1 Apache handler)])
    ;;
esac
