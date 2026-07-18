/*
 * cli-privilege.c - privilege checks for fapolicyd-cli commands
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#include "config.h"
#include <errno.h>
#include <grp.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "cli-privilege.h"

#define FAPOLICYD_CONFIG_DIR "/etc/fapolicyd"

struct cli_credentials {
	uid_t euid;
	gid_t egid;
	gid_t allowed_gid;
	const gid_t *groups;
	int group_count;
};

/*
 * privilege_satisfied - evaluate a captured identity against a requirement.
 * @requirement: privilege policy selected by the command.
 * @credentials: effective IDs and supplementary groups to inspect.
 * Returns true when the identity meets the selected requirement.
 */
static bool privilege_satisfied(enum cli_privilege_requirement requirement,
				const struct cli_credentials *credentials)
{
	if (credentials->euid == 0)
		return true;
	if (requirement == CLI_PRIVILEGE_ROOT)
		return false;
	if (credentials->egid == credentials->allowed_gid)
		return true;

	for (int i = 0; i < credentials->group_count; i++)
		if (credentials->groups[i] == credentials->allowed_gid)
			return true;

	return false;
}

/*
 * cli_require_privilege - check the caller against a command requirement.
 * @requirement: whether root alone or root/group membership is accepted.
 * Returns 0 when permitted and 1 after printing a tailored error otherwise.
 */
int cli_require_privilege(enum cli_privilege_requirement requirement)
{
	struct cli_credentials credentials = {
		.euid = geteuid(),
		.egid = getegid(),
		.allowed_gid = (gid_t)-1,
		.groups = NULL,
		.group_count = 0,
	};
	struct group *group;
	struct stat config_dir;
	gid_t *groups = NULL;
	int group_count;

	if (credentials.euid == 0)
		return 0;
	if (requirement == CLI_PRIVILEGE_ROOT)
		goto denied;

	/*
	 * The config directory remains available when the runtime directory and
	 * FIFO disappear, so its group is the stable administrative identity.
	 */
	if (stat(FAPOLICYD_CONFIG_DIR, &config_dir)) {
		fprintf(stderr, "Cannot inspect %s: %s\n",
			FAPOLICYD_CONFIG_DIR, strerror(errno));
		goto denied;
	}
	credentials.allowed_gid = config_dir.st_gid;

	group_count = getgroups(0, NULL);
	if (group_count < 0) {
		fprintf(stderr, "Cannot inspect supplementary groups: %s\n",
			strerror(errno));
		goto denied;
	}
	if (group_count > 0) {
		groups = malloc((size_t)group_count * sizeof(*groups));
		if (groups == NULL) {
			fprintf(stderr,
				"Cannot allocate supplementary group list\n");
			goto denied;
		}
		group_count = getgroups(group_count, groups);
		if (group_count < 0) {
			fprintf(stderr,
				"Cannot inspect supplementary groups: %s\n",
				strerror(errno));
			free(groups);
			goto denied;
		}
		credentials.groups = groups;
		credentials.group_count = group_count;
	}

	if (privilege_satisfied(requirement, &credentials)) {
		free(groups);
		return 0;
	}
	free(groups);

denied:
	if (requirement == CLI_PRIVILEGE_ROOT)
		fprintf(stderr,
			"Error: this command requires root privileges.\n");
	else {
		group = credentials.allowed_gid == (gid_t)-1 ? NULL :
			getgrgid(credentials.allowed_gid);
		if (group)
			fprintf(stderr,
				"Error: this command requires root privileges or "
				"membership in the %s group.\n", group->gr_name);
		else if (credentials.allowed_gid != (gid_t)-1)
			fprintf(stderr,
				"Error: this command requires root privileges or "
				"membership in group ID %" PRIuMAX ".\n",
				(uintmax_t)credentials.allowed_gid);
		else
			fprintf(stderr,
				"Error: this command requires root privileges or "
				"membership in the group that owns %s.\n",
				FAPOLICYD_CONFIG_DIR);
		if (group)
			endgrent();
	}
	return 1;
}
