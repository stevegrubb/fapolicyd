/*
 * backend-manager.c - backend management
 * Copyright (c) 2020,2022 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING. If not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor
 * Boston, MA 02110-1335, USA.
 *
 * Authors:
 *   Radovan Sroka <rsroka@redhat.com>
 */

#include "config.h"
#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>	// close
#include "conf.h"
#include "message.h"
#include "backend-manager.h"
#include "fapolicyd-backend.h"

extern backend file_backend;
#ifdef USE_RPM
extern backend rpm_backend;
#endif
#ifdef USE_DEB
extern backend deb_backend;
#endif

static backend* compiled[] =
{
	&file_backend,
#ifdef USE_RPM
	&rpm_backend,
#endif
#ifdef USE_DEB
	&deb_backend,
#endif
	NULL,
};

static backend_entry* backends = NULL;
extern atomic_bool stop;
static int backend_push(const char *name)
{
	long index = -1;
	for (long i = 0 ; compiled[i] != NULL; i++) {
		if (strcmp(name, compiled[i]->name) == 0) {
			index = i;
			break;
		}
	}

	if (index == -1) {
		msg(LOG_ERR, "%s backend not supported, aborting!", name);
		return 1;
	} else {
		backend_entry *tmp = (backend_entry *)
				malloc(sizeof(backend_entry));

		if (!tmp) {
			msg(LOG_ERR, "cannot allocate %s backend", name);
			return 2;
		}

		tmp->backend = compiled[index];
		tmp->next = NULL;

		if (!backends)
			backends = tmp;
		else {
			// Find the last entry
			backend_entry *cur = backends;
			while (cur->next)
				cur = cur->next;
			cur->next = tmp;
		}
		msg(LOG_DEBUG, "backend %s registered", name);
	}
	return 0;
}


static int backend_destroy(void)
{
	backend_entry *be = backend_get_first();
	backend_entry *tmp = NULL;

	while (be != NULL) {
		tmp = be;
		be = be->next;
		free(tmp);
	}
	backends = NULL;
	return 0;
}


static int backend_create(const char *trust_list)
{
	char *ptr, *saved, *tmp = strdup(trust_list);

	if (!tmp)
		return 1;

	ptr = strtok_r(tmp, ",", &saved);
	while (ptr) {
		if (backend_push(ptr)) {
			free(tmp);
			return 1;
		}
		ptr = strtok_r(NULL, ",", &saved);
	}
	free(tmp);
	return 0;
}


/*
 * backend_wait_for_loader - wait for a package loader socket event.
 * @fd: loader socket descriptor.
 * @timeout_ms: maximum time to wait in milliseconds.
 *
 * Returns 0 when the socket is ready and -1 on timeout, shutdown, or error.
 */
int backend_wait_for_loader(int fd, int timeout_ms)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	int remaining = timeout_ms;

	while (!stop && remaining > 0) {
		int interval = remaining > BACKEND_LOADER_POLL_MS ?
			BACKEND_LOADER_POLL_MS : remaining;
		int rc = poll(&pfd, 1, interval);

		if (rc > 0)
			return 0;
		if (rc < 0 && errno != EINTR)
			return -1;
		remaining -= interval;
	}

	errno = stop ? ECANCELED : ETIMEDOUT;
	return -1;
}


int backend_init(const conf_t *conf)
{
#if defined(USE_RPM) || defined(USE_DEB)
	struct sigaction action = { .sa_handler = SIG_IGN };

	/*
	 * A sealed memfd is a package loader's success commit. Process exit can
	 * wedge after that commit, while the bounded socket wait handles an
	 * earlier storage stall. Ignore SIGCHLD so neither path blocks reaping.
	 * Do not restore waitpid() without bounded child supervision.
	 */
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGCHLD, &action, NULL)) {
		msg(LOG_ERR, "Cannot configure package loader child reaping (%s)",
		    strerror(errno));
		return 1;
	}
#endif

	if (backend_create(conf->trust))
		return 1;

	for (backend_entry *be = backend_get_first();
			be != NULL;
			be = be->next) {
		if (be->backend->init())
			return 2;
	}
	return 0;
}


int backend_load(const conf_t *conf)
{
	for (backend_entry *be = backend_get_first();
			be != NULL; be = be->next) {
		if (be->backend->load(conf))
			return 1;
	}
	return 0;
}

void backend_close(void)
{
	for (backend_entry *be = backend_get_first();
			be != NULL; be = be->next) {
		// If we have a memfd, close it
		if (be->backend->memfd != -1) {
			close(be->backend->memfd);
			be->backend->memfd = -1;
			be->backend->entries = -1;
		}

		// allow the backend to release any resources
		be->backend->close();
	}
	backend_destroy();
}

backend_entry* backend_get_first(void)
{
	return backends;
}
