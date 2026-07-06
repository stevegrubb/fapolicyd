/*
 * deb_filter_test.c - verify debdb applies the trust-source filter
 */

#include "config.h"

#include <error.h>
#include <stdlib.h>

#include "fapolicyd-backend.h"
#include "filter.h"
#include "md5-backend.h"

#define BAD_MD5 "00000000000000000000000000000000"
#define FILTER_CONF TEST_BASE "/src/tests/fixtures/filter-minimal.conf"

extern md5_backend_result_t deb_backend_add_file_for_tests(const char *path,
		const char *hash, struct _hash_record **hashtable);

#define CHECK(expr, code, msg) \
	do { \
		if (!(expr)) \
			error(code, 0, "%s", msg); \
	} while (0)

/*
 * main - confirm debdb filter decisions happen before MD5 backend work.
 *
 * The test leaves deb_backend.memfd invalid. An allowed path must therefore
 * reach add_file_to_backend_by_md5() and fail fatally, while a denied path
 * must be skipped before the MD5 helper can validate the backend destination.
 * Returns 0 on success. Exits with error() on test failure.
 */
int main(void)
{
	struct _hash_record *hashtable = NULL;
	md5_backend_result_t rc;

	CHECK(filter_init() == 0, 1, "[ERROR:1] filter_init failed");
	CHECK(filter_load_file(FILTER_CONF) == 0, 2,
	      "[ERROR:2] filter_load_file failed");

	deb_backend.memfd = -1;
	deb_backend.entries = -1;

	rc = deb_backend_add_file_for_tests("/var/log/messages", BAD_MD5,
					    &hashtable);
	CHECK(rc == MD5_BACKEND_SKIPPED, 3,
	      "[ERROR:3] denied path was not skipped before hashing");
	CHECK(hashtable == NULL, 4,
	      "[ERROR:4] denied path added duplicate tracking state");

	rc = deb_backend_add_file_for_tests("/etc/hosts", BAD_MD5, &hashtable);
	CHECK(rc == MD5_BACKEND_FATAL, 5,
	      "[ERROR:5] allowed path did not reach MD5 backend");
	CHECK(hashtable == NULL, 6,
	      "[ERROR:6] fatal allowed path added duplicate tracking state");

	filter_destroy();
	return 0;
}
