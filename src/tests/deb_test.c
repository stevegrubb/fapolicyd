/*
 * deb_test.c - verify deb backend loader failure handling
 */

#include "config.h"

#include <errno.h>
#include <error.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "backend-manager.h"
#include "fapolicyd-backend.h"

extern backend deb_backend;

#define CHILD_WAIT_MS 2000
#define LOADER_TEST_TIMEOUT_MS 100
#define LOADER_TEST_MAX_WAIT_MS 1000

#define CHECK(expr, code, msg) \
	do { \
		if (!(expr)) \
			error(code, 0, "%s", msg); \
	} while (0)

/*
 * monotonic_ms - return monotonic milliseconds for timeout validation.
 * Returns -1 when the monotonic clock is unavailable.
 */
static int64_t monotonic_ms(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return -1;
	return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

/*
 * wait_for_parent_close - act as a loader that never sends a snapshot.
 * Returns after the parent closes fd 3 or after a test safety timeout.
 */
static int wait_for_parent_close(void)
{
	struct pollfd pfd = { .fd = 3, .events = POLLIN };
	int rc;

	do {
		rc = poll(&pfd, 1, CHILD_WAIT_MS);
	} while (rc < 0 && errno == EINTR);
	return rc > 0 ? 0 : 1;
}

/*
 * true_path - find a harmless helper that exits without sending an fd.
 * Returns an executable path, or NULL when none is available.
 */
static const char *true_path(void)
{
	if (access("/bin/true", X_OK) == 0)
		return "/bin/true";
	if (access("/usr/bin/true", X_OK) == 0)
		return "/usr/bin/true";
	return NULL;
}

/*
 * main - run deb loader IPC failure coverage.
 * Returns 0 on success. Exits with error() on test failure.
 */
int main(void)
{
	const char *path = true_path();
	char self_path[PATH_MAX];
	conf_t cfg;
	backend_entry *entry;
	int64_t elapsed;
	int64_t start;
	ssize_t len;
	int rc;

	if (getenv("FAPO_SOCK_FD") != NULL)
		return wait_for_parent_close();

	if (path == NULL)
		return 77;

	memset(&cfg, 0, sizeof(cfg));
	cfg.trust = "debdb";

	CHECK(backend_init(&cfg) == 0, 1, "[ERROR:1] debdb init failed");
	entry = backend_get_first();
	CHECK(entry != NULL, 2, "[ERROR:2] debdb backend not registered");
	CHECK(strcmp(entry->backend->name, cfg.trust) == 0, 3,
	      "[ERROR:3] debdb backend name mismatch");

	deb_backend.memfd = -1;
	deb_backend.entries = -1;

	rc = deb_backend_load_from_path_for_tests(&cfg, path,
						 LOADER_TEST_MAX_WAIT_MS);
	CHECK(rc != 0, 4, "[ERROR:4] deb IPC failure returned success");
	CHECK(deb_backend.memfd == -1, 5,
	      "[ERROR:5] failed deb load published a memfd");
	CHECK(deb_backend.entries == -1, 6,
	      "[ERROR:6] failed deb load published entries");

	len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
	CHECK(len > 0, 7, "[ERROR:7] cannot resolve deb test executable");
	self_path[len] = '\0';
	start = monotonic_ms();
	CHECK(start >= 0, 8, "[ERROR:8] cannot read monotonic clock");
	rc = deb_backend_load_from_path_for_tests(&cfg, self_path,
						 LOADER_TEST_TIMEOUT_MS);
	elapsed = monotonic_ms() - start;
	CHECK(rc != 0, 9, "[ERROR:9] stalled deb loader returned success");
	CHECK(elapsed >= 0 && elapsed < LOADER_TEST_MAX_WAIT_MS, 10,
	      "[ERROR:10] stalled deb loader wait was not bounded");
	CHECK(deb_backend.memfd == -1, 11,
	      "[ERROR:11] stalled deb load published a memfd");
	CHECK(deb_backend.entries == -1, 12,
	      "[ERROR:12] stalled deb load published entries");

	backend_close();
	return 0;
}
