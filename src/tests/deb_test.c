/*
 * deb_test.c - verify deb backend loader failure handling
 */

#include "config.h"

#include <error.h>
#include <string.h>
#include <unistd.h>

#include "backend-manager.h"
#include "fapolicyd-backend.h"

extern backend deb_backend;

#define CHECK(expr, code, msg) \
	do { \
		if (!(expr)) \
			error(code, 0, "%s", msg); \
	} while (0)

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
	conf_t cfg;
	backend_entry *entry;
	int rc;

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

	rc = deb_backend_load_from_path_for_tests(&cfg, path);
	CHECK(rc != 0, 4, "[ERROR:4] deb IPC failure returned success");
	CHECK(deb_backend.memfd == -1, 5,
	      "[ERROR:5] failed deb load published a memfd");
	CHECK(deb_backend.entries == -1, 6,
	      "[ERROR:6] failed deb load published entries");

	backend_close();
	return 0;
}
