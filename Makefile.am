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

INCLUDE_DIRS    = -I$(srcdir)/include
ACLOCAL_AMFLAGS = -I m4 --install
AM_CFLAGS       = $(INCLUDE_DIRS) $(EXTRA_CFLAGS) $(TSS2_ESYS_CFLAGS) $(CODE_COVERAGE_CFLAGS)
AM_LDFLAGS      = $(EXTRA_LDFLAGS) $(CODE_COVERAGE_LDFLAGS)
AM_LDADD        = $(TSS2_ESYS_LIBS) -ldl

### Add ax_* rules ###
# ax_code_coverage
if AUTOCONF_CODE_COVERAGE_2019_01_06
include $(top_srcdir)/aminclude_static.am
clean-local: code-coverage-clean
distclean-local: code-coverage-dist-clean
else
@CODE_COVERAGE_RULES@
endif

noinst_LIBRARIES = libtpm2-initramfs-tool.a
noinst_HEADERS = include/tpm2-initramfs-tool.h
libtpm2_initramfs_tool_a_SOURCES = src/libtpm2-initramfs-tool.c

pkgconfig_DATA = dist/tpm2-initramfs-tool.pc

bin_PROGRAMS = tpm2-initramfs-tool

tpm2_initramfs_tool_SOURCES = src/tpm2-initramfs-tool.c
tpm2_initramfs_tool_LDADD = libtpm2-initramfs-tool.a $(AM_LDADD)
tpm2_initramfs_tool_LDFLAGS = $(AM_LDFLAGS)

### Tests ###
TESTS =

TESTS += $(TESTS_SHELL)

TESTS_SHELL = test/test-tpm2-initramfs-tool.sh
EXTRA_DIST = $(TESTS_SHELL)
TEST_EXTENSIONS = .sh

check_PROGRAMS = test-tpm2-initramfs-tool-base32enc
test_tpm2_initramfs_tool_base32enc_SOURCES = test/test-tpm2-initramfs-tool-base32enc.c
test_tpm2_initramfs_tool_base32enc_LDADD = libtpm2-initramfs-tool.a $(AM_LDADD)
TESTS += $(check_PROGRAMS)

EXTRA_DIST += \
    CHANGELOG.md \
    LICENSE \
    README.md

AUTHORS:
	$(AM_V_GEN)git log --format='%aN <%aE>' | \
			grep -v 'users.noreply.github.com' | sort -u > $@
EXTRA_DIST += AUTHORS
CLEANFILES = AUTHORS
