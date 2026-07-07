/*
 * fapolicyd-deb-loader.c - Debian loader tool for fapolicyd
 * Copyright (c) 2026 Red Hat Inc.
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
 * Free Software Foundation Inc., 51 Franklin Street, Fifth Floor
 * Boston, MA 02110-1335, USA.
 */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/types.h>
#include <unistd.h>

#include "conf.h"
#include "fapolicyd-backend.h"
#include "message.h"

atomic_bool stop = 0;		// Library needs this
unsigned int debug_mode = 0;	// Library needs this
conf_t config;			// Library needs this

int do_deb_init_backend(void);
int do_deb_load_list(const conf_t *conf, int memfd);
int do_deb_destroy_backend(void);

extern backend deb_backend;

// fd 3 is installed by the daemon-side backend before exec.
int sock_fd = 3;

int main(int argc, char * const argv[])
{
	set_message_mode(MSG_SYSLOG, DBG_NO);
	openlog("fapolicyd-deb-loader", LOG_PID, LOG_DAEMON);

	int memfd = memfd_create("deb_snapshot", MFD_CLOEXEC|MFD_ALLOW_SEALING);
	if (memfd < 0) {
		msg(LOG_ERR, "memfd_create failed");
		return 1;
	}

	if (do_deb_init_backend()) {
		msg(LOG_ERR, "Failed to initialize deb loader backend");
		close(memfd);
		return 1;
	}

	if (do_deb_load_list(&config, memfd)) {
		msg(LOG_ERR, "Failed to populate deb backend snapshot");
		do_deb_destroy_backend();
		close(memfd);
		return 1;
	}

	msg(LOG_INFO, "Loaded files %ld", deb_backend.entries);

	/* Seal the snapshot so readers see a stable view. */
	if (fcntl(memfd, F_ADD_SEALS, F_SEAL_SHRINK |
		  F_SEAL_GROW | F_SEAL_WRITE) == -1)
		// Not a fatal error
		msg(LOG_WARNING, "Failed to seal deb backend memfd (%s)",
		    strerror(errno));
	lseek(memfd, 0, SEEK_SET);

	// Send the snapshot fd to the daemon.
	struct msghdr _msg = {0};
	struct iovec iov = { .iov_base = (char[1]){0}, .iov_len = 1 };
	union { struct cmsghdr align; char buf[CMSG_SPACE(sizeof(int))]; } cmsgbuf;

	_msg.msg_iov = &iov;
	_msg.msg_iovlen = 1;
	_msg.msg_control = cmsgbuf.buf;
	_msg.msg_controllen = sizeof cmsgbuf.buf;

	struct cmsghdr *c = CMSG_FIRSTHDR(&_msg);

	c->cmsg_level = SOL_SOCKET;
	c->cmsg_type = SCM_RIGHTS;
	c->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(c), &memfd, sizeof(int));

	if (sendmsg(sock_fd, &_msg, 0) < 0) {
		char err_buff[256];
		msg(LOG_ERR, "sendmsg failed (%s)",
		    strerror_r(errno, err_buff, sizeof(err_buff)));
		do_deb_destroy_backend();
		close(sock_fd);
		close(memfd);
		return 1;
	}

	close(sock_fd);
	close(memfd);

	do_deb_destroy_backend();
	return 0;
}
