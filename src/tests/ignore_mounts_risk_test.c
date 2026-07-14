/*
 * ignore_mounts_risk_test.c - verify ignored-mount risk categories
 */

#define _GNU_SOURCE

#include <error.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

bool verbose;

#include "../cli/ignore-mounts.c"

struct risk_case {
	const char *label;
	const char *path;
	mode_t mode;
	const char *mime;
	const avl_tree_t *languages;
	unsigned int expected;
};

struct dir_case {
	const char *label;
	const char *path;
	unsigned int expected;
};

/*
 * expect_risk - verify that a file path and MIME produce expected risks.
 * @test: test case describing the path, MIME, language set, and expectation.
 * Returns nothing.
 */
static void expect_risk(const struct risk_case *test)
{
	struct stat sb;
	unsigned int got;

	memset(&sb, 0, sizeof(sb));
	sb.st_mode = S_IFREG | test->mode;

	got = classify_file_risks(test->path, &sb, test->mime,
				  test->languages);
	if (got != test->expected)
		error(1, 0, "%s: expected 0x%x got 0x%x", test->label,
		      test->expected, got);
}

/*
 * expect_dir_risk - verify that a directory path produces expected risks.
 * @test: test case describing the directory path and expectation.
 * Returns nothing.
 */
static void expect_dir_risk(const struct dir_case *test)
{
	unsigned int got = classify_dir_risks(test->path);

	if (got != test->expected)
		error(1, 0, "%s: expected 0x%x got 0x%x", test->label,
		      test->expected, got);
}

/*
 * test_language_mime_loading - load a base language set and package addition.
 *
 * The ignored-mount scanner must use the same effective %languages values as
 * the daemon policy, including duplicate-safe += MIME additions.
 * Returns nothing. Exits on test failure.
 */
static void test_language_mime_loading(void)
{
	char path[] = "/tmp/fapolicyd-language-rules.XXXXXX";
	avl_tree_t languages;
	FILE *fp;
	int fd;

	fd = mkstemp(path);
	if (fd == -1)
		error(1, errno, "mkstemp failed");
	fp = fdopen(fd, "w");
	if (fp == NULL) {
		close(fd);
		unlink(path);
		error(1, errno, "fdopen failed");
	}
	if (fputs("%languages=text/x-python\n"
		  "%languages+=application/x-vendor-script,text/x-python\n",
		  fp) == EOF) {
		fclose(fp);
		unlink(path);
		error(1, errno, "write language rules failed");
	}
	if (fclose(fp) == EOF) {
		unlink(path);
		error(1, errno, "write language rules failed");
	}

	avl_init(&languages, compare_language_entry);
	if (load_language_mimes_from_file(&languages, path)) {
		unlink(path);
		error(1, 0, "language rule extensions did not load");
	}
	if (!mime_is_language(&languages, "text/x-python") ||
	    !mime_is_language(&languages, "application/x-vendor-script")) {
		free_language_mimes(&languages);
		unlink(path);
		error(1, 0, "loaded language MIME set was incomplete");
	}

	free_language_mimes(&languages);
	if (unlink(path))
		error(1, errno, "unlink failed");
}

/*
 * nftw() supplies no valid stat buffer when it reports FTW_NS. The callback
 * must report the incomplete scan without dereferencing that buffer.
 */
static void test_unstatable_walk_entry(void)
{
	if (inspect_mount_entry("/unstatable", NULL, FTW_NS, NULL) !=
	    FTW_CONTINUE)
		error(1, 0, "FTW_NS callback stopped the walk");
	if (scan_state.had_error == 0)
		error(1, 0, "FTW_NS callback did not report a scan error");
	scan_state.had_error = 0;
}

/*
 * A pathname can change after nftw() stats it. The reopen helper must retain
 * only the exact regular object seen by the walk, without following a link or
 * blocking on a replacement FIFO.
 */
static void test_walked_open_rejects_replacements(void)
{
	char path[] = "/tmp/fapolicyd-walked-open.XXXXXX";
	char replacement_path[] = "/tmp/fapolicyd-walked-replace.XXXXXX";
	char link_path[sizeof(path) + 8];
	char pipe_path[sizeof(path) + 8];
	struct stat walked, opened;
	int fd, reopened;

	fd = mkstemp(path);
	if (fd == -1)
		error(1, errno, "mkstemp failed");
	if (fstat(fd, &walked))
		error(1, errno, "fstat failed");
	if (close(fd))
		error(1, errno, "close failed");

	reopened = open_verified_regular_file(path, &walked, &opened);
	if (reopened == -1)
		error(1, errno, "regular file reopen failed");
	if (opened.st_dev != walked.st_dev || opened.st_ino != walked.st_ino)
		error(1, 0, "regular file reopen changed identity");
	if (close(reopened))
		error(1, errno, "reopened file close failed");

	fd = mkstemp(replacement_path);
	if (fd == -1)
		error(1, errno, "replacement mkstemp failed");
	if (close(fd))
		error(1, errno, "replacement close failed");
	if (rename(replacement_path, path))
		error(1, errno, "replacement rename failed");
	errno = 0;
	reopened = open_verified_regular_file(path, &walked, &opened);
	if (reopened != -1 || errno != ESTALE)
		error(1, errno, "replacement regular file was accepted");
	if (lstat(path, &walked))
		error(1, errno, "lstat replacement failed");

	snprintf(link_path, sizeof(link_path), "%s.link", path);
	if (symlink(path, link_path))
		error(1, errno, "symlink failed");
	reopened = open_verified_regular_file(link_path, &walked, &opened);
	if (reopened != -1)
		error(1, 0, "replacement symlink was accepted");
	if (unlink(link_path))
		error(1, errno, "unlink symlink failed");

	snprintf(pipe_path, sizeof(pipe_path), "%s.fifo", path);
	if (mkfifo(pipe_path, 0600))
		error(1, errno, "mkfifo failed");
	if (lstat(pipe_path, &walked))
		error(1, errno, "lstat fifo failed");
	alarm(2);
	reopened = open_verified_regular_file(pipe_path, &walked, &opened);
	alarm(0);
	if (reopened != -1 || errno != ESTALE)
		error(1, errno, "replacement FIFO was accepted");
	if (unlink(pipe_path))
		error(1, errno, "unlink fifo failed");
	if (unlink(path))
		error(1, errno, "unlink regular file failed");
}

int main(void)
{
	avl_tree_t languages;
	struct risk_case risk_cases[] = {
		{
			"executable mode", "/mnt/bin/tool", 0755,
			"text/plain", NULL,
			RISK_BIT(RISK_EXECUTABLE_REGULAR)
		},
		{
			"elf shared", "/mnt/lib/libdemo.so", 0644,
			"application/x-sharedlib", NULL,
			RISK_BIT(RISK_ELF_SHARED)
		},
		{
			"archive extension", "/mnt/cache/app.JAR", 0644,
			"application/octet-stream", NULL,
			RISK_BIT(RISK_ARCHIVE)
		},
		{
			"archive mime", "/mnt/cache/blob", 0644,
			"application/zip", NULL,
			RISK_BIT(RISK_ARCHIVE)
		},
		{
			"bytecode cache", "/mnt/pkg/__pycache__/m.pyc", 0644,
			"application/octet-stream", NULL,
			RISK_BIT(RISK_BYTECODE)
		},
		{
			"python bytecode mime", "/mnt/pkg/module", 0644,
			"application/x-bytecode.python", NULL,
			RISK_BIT(RISK_BYTECODE)
		},
		{
			"elisp bytecode mime", "/mnt/pkg/module", 0644,
			"application/x-elc", NULL,
			RISK_BIT(RISK_BYTECODE)
		},
		{
			"zstd archive mime", "/mnt/cache/blob", 0644,
			"application/zstd", NULL,
			RISK_BIT(RISK_ARCHIVE)
		},
		{
			"language mime", "/mnt/scripts/task.py", 0644,
			"text/x-python", &languages,
			RISK_BIT(RISK_LANGUAGE)
		},
		{
			"combined risks", "/mnt/pkg/app.zip", 0755,
			"application/x-executable", NULL,
			RISK_BIT(RISK_EXECUTABLE_REGULAR) |
			RISK_BIT(RISK_ELF_SHARED) |
			RISK_BIT(RISK_ARCHIVE)
		},
		{ NULL, NULL, 0, NULL, NULL, 0 }
	};
	struct dir_case dir_cases[] = {
		{
			"pycache dir", "/mnt/pkg/__pycache__",
			RISK_BIT(RISK_BYTECODE)
		},
		{
			"runtime dir", "/mnt/pkg/site-packages",
			RISK_BIT(RISK_PLUGIN_RUNTIME_DIR)
		},
		{ "ordinary dir", "/mnt/data/reports", 0 },
		{ NULL, NULL, 0 }
	};

	avl_init(&languages, compare_language_entry);
	if (insert_language_mime(&languages, "text/x-python"))
		error(1, 0, "failed to add language MIME");
	test_language_mime_loading();
	test_unstatable_walk_entry();
	test_walked_open_rejects_replacements();

	for (unsigned int i = 0; risk_cases[i].label; i++)
		expect_risk(&risk_cases[i]);
	for (unsigned int i = 0; dir_cases[i].label; i++)
		expect_dir_risk(&dir_cases[i]);

	free_language_mimes(&languages);
	return 0;
}
