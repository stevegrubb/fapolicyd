/*
 * deb-backend.c - Debian package database backend
 * Copyright (c) 2023-26 Red Hat Inc.
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
 */

#include "config.h"

#include <dpkg/db-ctrl.h>
#include <dpkg/db-fsys.h>
#include <dpkg/pkg-array.h>
#include <dpkg/program.h>
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <uthash.h>

#include "backend-manager.h"
#include "conf.h"
#include "fapolicyd-backend.h"
#include "filter.h"
#include "file.h"
#include "message.h"
#include "md5-backend.h"

static const char kDebBackend[] = "debdb";

static int deb_init_backend(void);
static int deb_load_list(const conf_t *);
static int deb_destroy_backend(void);
int do_deb_init_backend(void);
int do_deb_load_list(const conf_t *, int memfd);
int do_deb_destroy_backend(void);

backend deb_backend = {
    kDebBackend,
    deb_init_backend,
    deb_load_list,
    deb_destroy_backend,
    -1,
    -1,
};

#define BUFFER_SIZE 4096
static const char *deb_loader_path = LIBEXECDIR "/fapolicyd-deb-loader";
static int deb_loader_timeout_ms = BACKEND_LOADER_TIMEOUT_MS;

// ================================================================
// These functions are copied from dpkg source v1.21.1
// For some reason they segfault when i call :/

int parse_filehash_buffer(struct varbuf *buf, struct pkginfo *pkg,
                      struct pkgbin *pkgbin)
{
  char *thisline, *nextline;
  const char *pkgname = pkg_name(pkg, pnaw_nonambig);
  const char *buf_end = buf->buf + buf->used;

  for (thisline = buf->buf; thisline < buf_end; thisline = nextline) {
    struct fsys_namenode *namenode;
    char *endline, *hash_end, *filename;

    endline = memchr(thisline, '\n', buf_end - thisline);
    if (endline == NULL) {
      msg(LOG_ERR,
          "control file '%s' for package '%s' is "
          "missing final newline\n",
          HASHFILE, pkgname);
      return 1;
    }

    /* The md5sum hash has a constant length. */
    hash_end = thisline + kMd5HexSize;

    filename = hash_end + 2;
    if (filename + 1 > endline) {
      msg(LOG_ERR,
          "control file '%s' for package '%s' is "
          "missing value\n",
          HASHFILE, pkgname);
      return 1;
    }

    if (hash_end[0] != ' ' || hash_end[1] != ' ') {
      msg(LOG_ERR,
          "control file '%s' for package '%s' is "
          "missing value separator\n",
          HASHFILE, pkgname);
      return 1;
    }
    hash_end[0] = '\0';

    /* Where to start next time around. */
    nextline = endline + 1;
    /* Strip trailing ‘/’. */
    if (endline > thisline && endline[-1] == '/') endline--;
    *endline = '\0';

    if (endline == thisline) {
      msg(LOG_ERR,
          "control file '%s' for package '%s' "
          "contains empty filename\n",
          HASHFILE, pkgname);
      return 1;
    }

    /* Add the file to the list. */
    namenode = fsys_hash_find_node(filename, 0);
    namenode->newhash = nfstrsave(thisline);
  }
  return 0;
}

void parse_filehash2(struct pkginfo *pkg, struct pkgbin *pkgbin)
{
  const char *hashfile;
  struct varbuf buf = VARBUF_INIT;
  struct dpkg_error err = DPKG_ERROR_INIT;

  hashfile = pkg_infodb_get_file(pkg, pkgbin, HASHFILE);

  if (file_slurp(hashfile, &buf, &err) < 0 && err.syserrno != ENOENT)
    msg(LOG_ERR, "loading control file '%s' for package '%s'", HASHFILE,
        pkg_name(pkg, pnaw_nonambig));

  if (buf.used > 0) parse_filehash_buffer(&buf, pkg, pkgbin);

  varbuf_destroy(&buf);
}

// End of functions copied from dpkg.
// =======================================================================

/*
 * deb_add_file_to_backend - add one dpkg file after filter evaluation.
 *
 * Paths excluded by fapolicyd-filter.conf are skipped before opening or
 * hashing the file, matching the rpm backend's trust-source pruning.
 * Returns the MD5 backend result for included paths, or MD5_BACKEND_SKIPPED
 * when the filter excludes the path.
 */
static md5_backend_result_t
deb_add_file_to_backend(const char *path, const char *hash,
                        struct _hash_record **hashtable)
{
  filter_rc_t f_res = filter_check(path);

  if (f_res != FILTER_ALLOW) {
    if (f_res == FILTER_ERR_DEPTH)
      msg(LOG_WARNING,
          "filter nesting exceeds MAX_FILTER_DEPTH for %s; excluding",
          path);
    return MD5_BACKEND_SKIPPED;
  }

  return add_file_to_backend_by_md5(path, hash, hashtable, SRC_DEB,
                                    &deb_backend);
}

/*
 * deb_backend_add_file_for_tests - exercise debdb add/filter behavior.
 * @path: package-owned path to evaluate.
 * @hash: package MD5 string for the path.
 * @hashtable: duplicate-tracking table used by the MD5 backend helper.
 * Returns the same result as the internal debdb add path.
 */
md5_backend_result_t deb_backend_add_file_for_tests(const char *path,
						    const char *hash,
						    struct _hash_record **hashtable)
{
  return deb_add_file_to_backend(path, hash, hashtable);
}

int do_deb_load_list(const conf_t *conf, int memfd)
{
  const char *control_file = "md5sums";

  struct _hash_record *hashtable = NULL;
  struct _hash_record **hashtable_ptr = &hashtable;
  long entries = 0;

  if (memfd < 0) {
    msg(LOG_ERR, "Invalid memfd supplied to deb loader");
    return 1;
  }

  deb_backend.memfd = memfd;
  deb_backend.entries = -1;

  struct pkg_array array;
  pkg_array_init_from_hash(&array);

  msg(LOG_INFO, "Computing hashes for %d packages.", array.n_pkgs);
  fsys_hash_reset();

  int rc = 0;

  for (int i = 0; i < array.n_pkgs; i++) {
    struct pkginfo *package = array.pkgs[i];
    if (package->status != PKG_STAT_INSTALLED) {
      continue;
    }
    printf("\x1b[2K\rPackage %d / %d : %s", i + 1, array.n_pkgs,
           package->set->name);
    if (pkg_infodb_has_file(package, &package->installed, control_file))
      pkg_infodb_get_file(package, &package->installed, control_file);
    ensure_packagefiles_available(package);

    // Should not need this copy of code ...
    parse_filehash2(package, &package->installed);

    // This is causing segfault in linked lib :/
    // parse_filehash(package, &package->installed);
    // ensure_diversions();

    struct fsys_namenode_list *file = package->files;
    if (!file) {
      // Package does not have any files.
      continue;
    }
    // Loop over all files in the package, adding them to debdb.
    while (file) {
      struct fsys_namenode *namenode = file->namenode;
      // Get the hash and path of the file.
      const char *hash =
          (namenode->newhash == NULL) ? namenode->oldhash : namenode->newhash;
      const char *path = (namenode->divert && !namenode->divert->camefrom)
                             ? namenode->divert->useinstead->name
                             : namenode->name;
      if (hash != NULL) {
        md5_backend_result_t add_rc =
            deb_add_file_to_backend(path, hash, hashtable_ptr);
        if (add_rc == MD5_BACKEND_FATAL) {
          rc = 1;
          goto out;
        }
        if (add_rc == MD5_BACKEND_ADDED)
          entries++;
      }
      file = file->next;
    }
  }

out:
  struct _hash_record *item, *tmp;
  HASH_ITER(hh, hashtable, item, tmp) {
    HASH_DEL(hashtable, item);
    free((void *)item->key);
    free((void *)item);
  }

  pkg_array_destroy(&array);
  if (rc == 0)
    deb_backend.entries = entries;
  return rc;
}

static int deb_load_list(const conf_t *conf)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) < 0) {
		msg(LOG_ERR, "socketpair failed");
		return 1;
	}

	posix_spawn_file_actions_t actions;
	posix_spawn_file_actions_init(&actions);

	// dup sv[1] to FD 3 for the child; SOCK_CLOEXEC ensures both
	// sv[0] and sv[1] are closed on exec, and dup2 clears CLOEXEC
	// on the target FD 3. When sv[1] is already 3, dup2(3,3) is a
	// no-op that does NOT clear CLOEXEC, so move sv[1] to a
	// different FD to avoid the overlap.
	if (sv[1] == 3) {
		int tmp = fcntl(sv[1], F_DUPFD_CLOEXEC, 4);
		if (tmp < 0) {
			msg(LOG_ERR, "fcntl F_DUPFD_CLOEXEC failed");
			close(sv[0]);
			close(sv[1]);
			posix_spawn_file_actions_destroy(&actions);
			return 1;
		}
		close(sv[1]);
		sv[1] = tmp;
	}
	posix_spawn_file_actions_adddup2(&actions, sv[1], 3);

	char *argv[] = { "fapolicyd-deb-loader", NULL };
	char *custom_env[] = { "FAPO_SOCK_FD=3", NULL };

	pid_t pid = -1;
	int spawn_rc = posix_spawn(&pid, deb_loader_path,
				 &actions, NULL, argv, custom_env);
	close(sv[1]);  // Parent doesn't write

	if (spawn_rc == 0) {
		msg(LOG_DEBUG, "fapolicyd-deb-loader spawned with pid: %d",
		    pid);

		if (backend_wait_for_loader(sv[0], deb_loader_timeout_ms)) {
			char err_buff[BUFFER_SIZE];

			msg(LOG_ERR, "deb loader snapshot wait failed (%s)",
			    strerror_r(errno, err_buff, BUFFER_SIZE));
			close(sv[0]);
			posix_spawn_file_actions_destroy(&actions);
			return 1;
		}

		struct msghdr  _msg  = {0};
		struct iovec   iov = { .iov_base = (char[1]){0}, .iov_len = 1 };
		union {
			struct cmsghdr align;
			char buf[CMSG_SPACE(sizeof(int))];
		} cmsgbuf = {0};

		_msg.msg_iov    = &iov;
		_msg.msg_iovlen = 1;
		_msg.msg_control = cmsgbuf.buf;
		_msg.msg_controllen = sizeof cmsgbuf.buf;

		ssize_t rc;
		do {
			rc = recvmsg(sv[0], &_msg, MSG_DONTWAIT);
		} while (rc < 0 && errno == EINTR);
		if (rc < 0) {
			char err_buff[BUFFER_SIZE];
			msg(LOG_ERR, "recvmsg failed (%s)",
			    strerror_r(errno, err_buff, BUFFER_SIZE));
			close(sv[0]);
			posix_spawn_file_actions_destroy(&actions);
			return 1;
		}
		close(sv[0]);

		struct cmsghdr *c = CMSG_FIRSTHDR(&_msg);
		if (!c || c->cmsg_type != SCM_RIGHTS) {
			msg(LOG_ERR, "missing fd");
			posix_spawn_file_actions_destroy(&actions);
			return 1;
		}

		int memfd;
		memcpy(&memfd, CMSG_DATA(c), sizeof memfd);

		// Mark entries unknown until a fresh snapshot is available.
		deb_backend.entries = -1;

		if (fcntl(memfd, F_SETFD, FD_CLOEXEC) == -1) {
			char err_buff[BUFFER_SIZE];
			msg(LOG_WARNING,
			    "Failed to set CLOEXEC on deb memfd (%s)",
			    strerror_r(errno, err_buff, BUFFER_SIZE));
		}

		// Pass the memfd to the backend representation.
		deb_backend.memfd = memfd;
	} else {
		close(sv[0]);
		msg(LOG_ERR, "posix_spawn failed: %s\n", strerror(spawn_rc));
	}

	posix_spawn_file_actions_destroy(&actions);
	return spawn_rc;
}

/*
 * deb_backend_load_from_path_for_tests - exercise deb loader IPC errors.
 * @conf: test configuration.
 * @loader_path: helper executable path to spawn.
 * @timeout_ms: maximum snapshot wait used by the test.
 *
 * Returns the deb backend load result without terminating the caller.
 */
int deb_backend_load_from_path_for_tests(const conf_t *conf,
					 const char *loader_path,
					 int timeout_ms)
{
	const char *previous_loader_path = deb_loader_path;
	int previous_timeout_ms = deb_loader_timeout_ms;
	int rc;

	deb_loader_path = loader_path;
	deb_loader_timeout_ms = timeout_ms;
	rc = deb_load_list(conf);
	deb_loader_path = previous_loader_path;
	deb_loader_timeout_ms = previous_timeout_ms;
	return rc;
}

static int deb_init_backend(void)
{
  return 0;
}

int do_deb_init_backend(void)
{
  dpkg_program_init(kDebBackend);

  msg(LOG_INFO, "Loading debdb backend");

  enum modstatdb_rw status = msdbrw_readonly;
  status = modstatdb_open(msdbrw_readonly);
  if (status != msdbrw_readonly) {
    msg(LOG_ERR, "Could not open database for reading. Status %d", status);
    dpkg_program_done();
    return 1;
  }

  if (filter_init()) {
    msg(LOG_ERR, "Failed initializing filter for debdb backend");
    modstatdb_shutdown();
    dpkg_program_done();
    return 1;
  }
  if (filter_load_file(NULL)) {
    msg(LOG_ERR, "Failed loading filter for debdb backend");
    filter_destroy();
    modstatdb_shutdown();
    dpkg_program_done();
    return 1;
  }

  return 0;
}

static int deb_destroy_backend(void)
{
  return 0;
}

int do_deb_destroy_backend(void)
{
  dpkg_program_done();
  modstatdb_shutdown();
  filter_destroy();
  return 0;
}
