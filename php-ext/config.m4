PHP_ARG_ENABLE([maat], [whether to enable Maât], [AS_HELP_STRING([--enable-maat], [Enable native Maât SSH authentication])], [no])
if test "$PHP_MAAT" != "no"; then
  PHP_NEW_EXTENSION([maat], [maat.c], [$ext_shared])
fi
