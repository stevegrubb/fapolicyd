/*
 * cli-privilege.h - privilege requirements for fapolicyd-cli commands
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#ifndef CLI_PRIVILEGE_HEADER
#define CLI_PRIVILEGE_HEADER

enum cli_privilege_requirement {
	CLI_PRIVILEGE_ROOT,
	CLI_PRIVILEGE_ROOT_OR_GROUP,
};

/*
 * cli_require_privilege - check the caller against a command requirement.
 * @requirement: whether root alone or root/group membership is accepted.
 * Returns 0 when permitted and 1 after printing a tailored error otherwise.
 */
int cli_require_privilege(enum cli_privilege_requirement requirement);

#endif
