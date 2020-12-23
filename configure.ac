# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2018 Fraunhofer SIT
# Copyright (c) 2019 Canonical Ltd.
# All rights reserved.
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 or 3 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

AC_PREREQ([2.68])

AC_INIT([tpm2-initramfs-tool],
        [0.2.2],
        [https://github.com/timchen119/tpm2-initramfs-tools/issues],
        [],
        [https://github.com/timchen119/tpm2-initramfs-tools])
dnl Avoid setting CFLAGS to anything by default; we use AC_CFLAGS below for this.
: ${CFLAGS=""}

dnl Let's be FHS-conform by default.
if test "$prefix" = '/usr'; then
    test "$sysconfdir" = '${prefix}/etc' && sysconfdir="/etc"
    test "$sharedstatedir" = '${prefix}/com' && sharedstatedir="/var"
    test "$localstatedir" = '${prefix}/var' && localstatedir="/var"
fi

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/tpm2-initramfs-tool.c])
AC_CONFIG_AUX_DIR([build-aux])

AC_USE_SYSTEM_EXTENSIONS

# propagate configure arguments to distcheck
AC_SUBST([DISTCHECK_CONFIGURE_FLAGS],[$ac_configure_args])

AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE([foreign subdir-objects -Wall -Wno-portability])
#Backward compatible setting of "silent-rules"
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])]) 
AM_MAINTAINER_MODE([enable])

AC_PROG_CC
AC_PROG_CC_C99
AM_PROG_CC_C_O
# Use static libary
AC_PROG_RANLIB

AC_GNU_SOURCE

PKG_INSTALLDIR()

AC_CONFIG_FILES([Makefile dist/tpm2-initramfs-tool.pc])

AX_ADD_COMPILER_FLAG([-std=c99])
AX_ADD_COMPILER_FLAG([-Wall])
AX_ADD_COMPILER_FLAG([-Wextra])
AX_ADD_COMPILER_FLAG([-Wformat-security])
AX_ADD_COMPILER_FLAG([-Werror])
AX_ADD_COMPILER_FLAG([-fstack-protector-all])
AX_ADD_COMPILER_FLAG([-fpic])
AX_ADD_COMPILER_FLAG([-fPIC])

# work around GCC bug #53119
#   https://gcc.gnu.org/bugzilla/show_bug.cgi?id=53119
AX_ADD_COMPILER_FLAG([-Wno-missing-braces])

AX_ADD_LINK_FLAG([-Wl,--no-undefined])
AX_ADD_LINK_FLAG([-Wl,-z,noexecstack])
AX_ADD_LINK_FLAG([-Wl,-z,now])
AX_ADD_LINK_FLAG([-Wl,-z,relro])

AX_CODE_COVERAGE
m4_ifdef([_AX_CODE_COVERAGE_RULES],
         [AM_CONDITIONAL(AUTOCONF_CODE_COVERAGE_2019_01_06, [true])],
         [AM_CONDITIONAL(AUTOCONF_CODE_COVERAGE_2019_01_06, [false])])
AX_ADD_AM_MACRO_STATIC([])

AC_ARG_ENABLE([debug],
            [AS_HELP_STRING([--enable-debug],
                            [build with debug output])],,
            [enable_debug=no])
AS_IF([test "x$enable_debug" != "xno"],
      AC_DEFINE_UNQUOTED([DEBUG], [1], ["Debug output enabled"]))

PKG_PROG_PKG_CONFIG([0.25])
PKG_CHECK_MODULES([TSS2_ESYS],[tss2-esys])

AC_OUTPUT

AC_MSG_RESULT([
$PACKAGE_NAME $VERSION
])
    
