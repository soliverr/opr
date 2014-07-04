#! /bin/sh

aclocal
autoheader
#libtoolize --force --copy
libtoolize --ltdl
#automake --foreign --add-missing --copy
automake --foreign --add-missing
autoconf
cp libltdl/config/* .