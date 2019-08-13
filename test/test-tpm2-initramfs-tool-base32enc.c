/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright © 2019 Canonical Ltd.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 or 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Authored by: Tim Chen <tim.chen119@canonical.com>
 *
 */

#include "tpm2-initramfs-tool.h"
#include <assert.h>

int main()
{
    char *base32key = NULL;
    const unsigned char teststring[] = {0xfe, 0x58, 0x12, 0x53, 0x75, 0x69};

    base32key = base32enc(teststring, 6);
    assert(strcmp(base32key,"7ZMBEU3VNE======") == 0);
    free(base32key);
}
