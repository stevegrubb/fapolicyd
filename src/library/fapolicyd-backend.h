/*
 * fapolicyd-backend.h - Header file for database backend interface
 * Copyright (c) 2020-23 Red Hat Inc.
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

#ifndef FAPOLICYD_BACKEND_HEADER
#define FAPOLICYD_BACKEND_HEADER

#include <inttypes.h>
#include <stdint.h>
#include <sys/types.h>

#include "conf.h"
#include "file.h"

// If this gets extended, please put the new items at the end.
typedef enum { SRC_UNKNOWN, SRC_RPM, SRC_FILE_DB, SRC_DEB } trust_src_t;

/*
 * Trust DB payload format
 *
 * Each payload stores "source size digest" as text.  The size is a fixed
 * unsigned 64-bit byte count, rather than native off_t or size_t.  This keeps
 * the on-disk decimal format independent of the process ABI: a 32-bit build
 * with large-file support must parse the same record as a 64-bit build.
 *
 * Keep native filesystem values as off_t and allocation lengths as size_t.
 * Convert only at this serialization boundary, and reject a stored value that
 * cannot be represented by the native off_t needed for a stat comparison.
 */
typedef uint64_t trustdb_size_t;

/* UINT64_MAX has 20 decimal digits. */
#define TRUSTDB_SIZE_DECIMAL_DIGITS 20

// Do not pad the hash value so SHA1 and SHA256 digests parse correctly.
// The input form includes a digest width for scanf's destination buffer.
#define STR_IMPL(x) #x
#define STR(x) STR_IMPL(x)
#define DATA_FORMAT "%u %" PRIu64 " %s"
#define DATA_FORMAT_IN "%u %" SCNu64 " %" STR(FILE_DIGEST_STRING_WIDTH) "s"

/*
 * trustdb_size_from_signed - convert a nonnegative native file size.
 * @size: Native signed file size or package size.
 * @stored_size: Receives the serialized trust DB byte count.
 *
 * Returns 0 on success or 1 when @size is negative or too wide for the
 * wire format.
 */
static inline int trustdb_size_from_signed(intmax_t size,
					   trustdb_size_t *stored_size)
{
	if (size < 0 || (uintmax_t)size > UINT64_MAX)
		return 1;

	*stored_size = (trustdb_size_t)size;
	return 0;
}

/*
 * trustdb_size_from_unsigned - convert an unsigned in-memory size.
 * @size: Native unsigned file or buffer size.
 * @stored_size: Receives the serialized trust DB byte count.
 *
 * Returns 0 on success or 1 when @size exceeds the wire-format range.
 */
static inline int trustdb_size_from_unsigned(uintmax_t size,
					     trustdb_size_t *stored_size)
{
	if (size > UINT64_MAX)
		return 1;

	*stored_size = (trustdb_size_t)size;
	return 0;
}

/*
 * trustdb_size_to_off_t - convert a stored size for filesystem comparison.
 * @stored_size: Serialized trust DB byte count.
 * @size: Receives the native off_t value.
 *
 * A trust record can be valid on a wider ABI but not representable by a
 * narrower off_t.  The checked round trip rejects that record instead of
 * truncating it before comparison.
 *
 * Returns 0 on success or 1 when @stored_size does not fit in off_t.
 */
static inline int trustdb_size_to_off_t(trustdb_size_t stored_size,
					 off_t *size)
{
	off_t native_size;

	if (stored_size > INTMAX_MAX)
		return 1;

	native_size = (off_t)(intmax_t)stored_size;
	if (native_size < 0 ||
	    (trustdb_size_t)(intmax_t)native_size != stored_size)
		return 1;

	*size = native_size;
	return 0;
}

typedef struct _backend
{
	const char * name;
	int (*init)(void);
	int (*load)(const conf_t *);
	int (*close)(void);
	int memfd;
	long entries;
} backend;

extern backend file_backend;

#ifdef USE_RPM
extern backend rpm_backend;
int rpm_backend_load_from_path_for_tests(const conf_t *conf,
	const char *loader_path) __nonnull ((1, 2));
#endif

#ifdef USE_DEB
extern backend deb_backend;
int deb_backend_load_from_path_for_tests(const conf_t *conf,
	const char *loader_path) __nonnull ((1, 2));
#endif

#endif
