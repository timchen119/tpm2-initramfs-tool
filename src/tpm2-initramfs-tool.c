/* SPDX-License-Identifier: GPL-2.0-or-later */
/*******************************************************************************
 * Copyright 2018, Fraunhofer SIT
 * Copyright 2018, Jonas Witschel
 * All rights reserved.
 *******************************************************************************/
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

#include "include/tpm2-initramfs-tool.h"

/** Main function
 *
 * @param argc The argument count.
 * @param argv The arguments.
 * @retval 0 on success
 * @retval 1 on failure
 */
int main(int argc, char **argv)
{
    if (parse_opts(argc, argv) != 0) {
        goto err;
    }

    int rc;

    TSS2_TCTI_CONTEXT *tcti_context;
    if (tcti_init(opt.tcti, &tcti_context) != 0) {
        goto err;
    }

    switch (opt.cmd) {
    case CMD_SEAL:

        rc = pcr_seal(opt.data, opt.pcrs, opt.banks, opt.persistent,
                      tcti_context);
        if (rc != 0) {
            goto err;
        }
        break;

    case CMD_UNSEAL:

        rc = pcr_unseal(opt.pcrs, opt.banks, opt.persistent, tcti_context);
        if (rc != 0) {
            goto err;
        }
        break;

    default:
        goto err;
    }

    tcti_finalize();
    return 0;

err:
    tcti_finalize();
    return 1;
}
