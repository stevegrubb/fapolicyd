//
// fanotify_mime_type.c - Gather MIME type usage via fanotify permission events
//

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../src/library/file.h"

#define FANOTIFY_EVENT_BUF 8192
#define TOP_MIME_LIMIT 100

struct mime_entry {
	char *mime;
	unsigned long count;
	struct mime_entry *next;
};

static struct mime_entry *mime_head;
static volatile sig_atomic_t running = 1;

/*
 * handle_signal - set a flag so the main loop can exit gracefully.
 * @sig: signal that was caught.
 */
static void handle_signal(int sig __attribute__ ((unused)))
{
	running = 0;
}

/*
 * add_mime_entry - add or update the counter for a MIME string.
 * @mime: MIME type string to account for.
 */
static void add_mime_entry(const char *mime)
{
	struct mime_entry *cur;

	for (cur = mime_head; cur; cur = cur->next) {
		if (strcmp(cur->mime, mime) == 0) {
			cur->count++;
			return;
		}
	}

	cur = calloc(1, sizeof(*cur));
	if (cur == NULL)
		return;

	cur->mime = strdup(mime);
	if (cur->mime == NULL) {
		free(cur);
		return;
	}

	cur->count = 1;
	cur->next = mime_head;
	mime_head = cur;
}

/*
 * free_mime_entries - release memory used by the MIME list.
 */
static void free_mime_entries(void)
{
	struct mime_entry *cur, *next;

	for (cur = mime_head; cur; cur = next) {
		next = cur->next;
		free(cur->mime);
		free(cur);
	}
	mime_head = NULL;
}

/*
 * count_mime_entries - count the elements in the MIME list.
 *
 * Returns the number of tracked MIME entries.
 */
static size_t count_mime_entries(void)
{
	struct mime_entry *cur;
	size_t count = 0;

	for (cur = mime_head; cur; cur = cur->next)
		count++;

	return count;
}

/*
 * compare_mime_entries - qsort comparison helper for MIME entries.
 * @a: first list entry.
 * @b: second list entry.
 *
 * Returns a < 0 when @b should sort before @a.
 */
static int compare_mime_entries(const void *a, const void *b)
{
	const struct mime_entry *const *ma = a;
	const struct mime_entry *const *mb = b;

	if ((*mb)->count > (*ma)->count)
		return 1;
	if ((*mb)->count < (*ma)->count)
		return -1;

	return strcmp((*ma)->mime, (*mb)->mime);
}

/*
 * print_sorted_mimes - sort and print the most common MIME types.
 */
static void print_sorted_mimes(void)
{
	struct mime_entry **sorted;
	struct mime_entry *cur;
	size_t total;
	size_t idx;

	total = count_mime_entries();
	if (total == 0)
		return;

	sorted = calloc(total, sizeof(*sorted));
	if (sorted == NULL)
		return;

	for (idx = 0, cur = mime_head; cur; cur = cur->next, idx++)
		sorted[idx] = cur;

	qsort(sorted, total, sizeof(*sorted), compare_mime_entries);

	if (total > TOP_MIME_LIMIT)
		total = TOP_MIME_LIMIT;

	for (idx = 0; idx < total; idx++)
		printf("%s	%lu\n", sorted[idx]->mime, sorted[idx]->count);

	free(sorted);
}

/*
 * allow_event - respond to the kernel with an allow decision.
 * @notify_fd: fanotify file descriptor.
 * @file_fd: file descriptor from fanotify metadata.
 */
static void allow_event(int notify_fd, int file_fd)
{
	struct fanotify_response response = {
		.fd = file_fd,
		.response = FAN_ALLOW,
	};

	if (write(notify_fd, &response, sizeof(response)) < 0)
		perror("write fanotify response");
}

/*
 * record_file_mime - look up the MIME type for the fanotify file.
 * @metadata: current fanotify event metadata.
 *
 * Returns 0 on success and -1 on error.
 */
static int record_file_mime(const struct fanotify_event_metadata *metadata)
{
	struct stat sb;
	struct file_info info;
	char path[PATH_MAX + 1];
	char mime_buf[128];
	char *mime;

	if (metadata->fd < 0)
		return -1;

	memset(&info, 0, sizeof(info));
	if (fstat(metadata->fd, &sb) == 0) {
		info.device = sb.st_dev;
		info.inode = sb.st_ino;
		info.mode = sb.st_mode;
		info.size = sb.st_size;
		info.time = sb.st_mtim;
	}

	if (get_file_from_fd(metadata->fd, metadata->pid,
				sizeof(path), path) == NULL)
		strncpy(path, "?", sizeof(path));

	mime = get_file_type_from_fd(metadata->fd, &info, path,
				 sizeof(mime_buf), mime_buf);
	if (mime == NULL)
		return -1;

	add_mime_entry(mime);
	return 0;
}

/*
 * process_event - handle a single fanotify event.
 * @notify_fd: fanotify file descriptor.
 * @metadata: fanotify metadata describing the event.
 */
static void process_event(int notify_fd,
		const struct fanotify_event_metadata *metadata)
{
	if (metadata->mask & FAN_Q_OVERFLOW)
		return;

	record_file_mime(metadata);
	allow_event(notify_fd, metadata->fd);
	close(metadata->fd);
}

/*
 * event_loop - wait for fanotify permission events until asked to stop.
 * @notify_fd: fanotify file descriptor.
 */
static void event_loop(int notify_fd)
{
	char buffer[FANOTIFY_EVENT_BUF];
	size_t len;
	const struct fanotify_event_metadata *metadata;

	while (running) {
		len = read(notify_fd, buffer, sizeof(buffer));
		if (len < 0) {
			if (errno == EINTR)
				continue;
			perror("read fanotify");
			break;
		}

		metadata = (const struct fanotify_event_metadata *)buffer;
		while (FAN_EVENT_OK(metadata, len)) {
			if (metadata->vers != FANOTIFY_METADATA_VERSION) {
				fprintf(stderr,
					"fanotify metadata version mismatch\n");
				running = 0;
				break;
			}

			process_event(notify_fd, metadata);
			metadata = FAN_EVENT_NEXT(metadata, len);
		}
	}
}

/*
 * setup_fanotify - initialize fanotify for permission events.
 *
 * Returns a fanotify file descriptor or -1 on failure.
 */
static int setup_fanotify(void)
{
	int notify_fd;

	notify_fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT,
				O_RDONLY | O_LARGEFILE | O_CLOEXEC);
	if (notify_fd < 0) {
		perror("fanotify_init");
		return -1;
	}

	if (fanotify_mark(notify_fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
			 FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM,
			 AT_FDCWD, "/") < 0) {
		perror("fanotify_mark");
		close(notify_fd);
		return -1;
	}

	return notify_fd;
}

/*
 * teardown_fanotify - remove marks and close the fanotify descriptor.
 * @notify_fd: fanotify file descriptor.
 */
static void teardown_fanotify(int notify_fd)
{
	if (notify_fd >= 0)
		fanotify_mark(notify_fd, FAN_MARK_FLUSH, 0, AT_FDCWD, "/");

	close(notify_fd);
}

/*
 * main - run the fanotify MIME type survey.
 */
int main(void)
{
	struct sigaction sa;
	int notify_fd;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handle_signal;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	file_init();

	notify_fd = setup_fanotify();
	if (notify_fd < 0) {
		file_close();
		return 1;
	}

	event_loop(notify_fd);

	teardown_fanotify(notify_fd);
	file_close();

	print_sorted_mimes();
	free_mime_entries();

	return 0;
}
