#! /bin/sh

# Clean All
if [ "$1" = "clean" ]; then
  make clean
  rm -f aclocal.m4 compile configure install-sh \
        depcomp ltmain.sh config.guess config.sub \
        `find . -name Makefile.in` compile `find . -name Makefile`
  rm -rf autom4te.cache
  rm -rf src/.deps
  exit
fi

set -x

cat /etc/os-release
dpkg -l | grep -E "(m4|autoconf|automake|gettext)"
aclocal --verbose -W all
autoreconf -i --verbose
automake --gnu --add-missing --verbose
autoconf --verbose

case "$OSTYPE" in
  darwin*)
    LDFLAGS=${LDFLAGS=-lintl}
    export LDFLAGS
    ;;
  linux*)
    echo "LINUX"
    ;;
  bsd*)
    echo "BSD"
    ;;
  *)
    echo "unknown: $OSTYPE"
    ;;
esac

./configure "$@"
