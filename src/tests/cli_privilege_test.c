/*
 * cli_privilege_test.c - verify fapolicyd-cli privilege policies
 */

#include "config.h"

#include <error.h>
#include <stdbool.h>
#include <stdlib.h>

#include "../cli/cli-privilege.c"

/*
 * expect_privilege - compare a synthetic identity with the expected result.
 * @label: test case name used in failures.
 * @requirement: privilege policy to evaluate.
 * @credentials: synthetic caller identity.
 * @expected: expected policy result.
 * Returns nothing; exits on failure.
 */
static void expect_privilege(const char *label,
		enum cli_privilege_requirement requirement,
		const struct cli_credentials *credentials, bool expected)
{
	bool actual = privilege_satisfied(requirement, credentials);

	if (actual != expected)
		error(1, 0, "%s: expected %d got %d", label, expected,
			actual);
}

int main(void)
{
	const gid_t supplementary[] = { 10, 20, 30 };
	struct cli_credentials credentials = {
		.euid = 0,
		.egid = 1000,
		.allowed_gid = 20,
		.groups = supplementary,
		.group_count = 3,
	};

	expect_privilege("root satisfies root-only",
		CLI_PRIVILEGE_ROOT, &credentials, true);
	expect_privilege("root satisfies group policy",
		CLI_PRIVILEGE_ROOT_OR_GROUP, &credentials, true);

	credentials.euid = 1000;
	expect_privilege("non-root rejected by root-only",
		CLI_PRIVILEGE_ROOT, &credentials, false);
	expect_privilege("supplementary group accepted",
		CLI_PRIVILEGE_ROOT_OR_GROUP, &credentials, true);

	credentials.egid = 20;
	credentials.allowed_gid = 40;
	expect_privilege("unrelated groups rejected",
		CLI_PRIVILEGE_ROOT_OR_GROUP, &credentials, false);

	credentials.allowed_gid = 20;
	credentials.groups = NULL;
	credentials.group_count = 0;
	expect_privilege("effective group accepted",
		CLI_PRIVILEGE_ROOT_OR_GROUP, &credentials, true);

	return EXIT_SUCCESS;
}
