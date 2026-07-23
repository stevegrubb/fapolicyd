// Copyright 2024 Red Hat
// SPDX-License-Identifier: GPL-2.0-or-later

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "fapolicyd-backend.h"

int main(void)
{
	const char *digest =
	"68879112e7d8a66c61178c409b07d1233270bcf2375d2ea029ca68f3552846563426b625f946c478c37b910373c44a0b89c08b9897885e9b135b11a6db604550";
	char data[TRUSTDB_DATA_BUFSZ];
	char parsed_digest[FILE_DIGEST_STRING_MAX];
	unsigned int tsource;
	trustdb_size_t size;
	trustdb_size_t expected_size = UINT64_C(4294967296);
	off_t native_size;
	int written;

	written = snprintf(data, sizeof(data), DATA_FORMAT, SRC_RPM,
			   expected_size, digest);
	if (written < 0 || written >= (int)sizeof(data))
		return 1;

	if (sscanf(data, DATA_FORMAT_IN, &tsource, &size, parsed_digest) != 3)
		return 1;

	if (size != expected_size || strcmp(digest, parsed_digest))
		return 1;

	/* Large-file off_t builds must retain a size above 32-bit range. */
	if (sizeof(off_t) >= sizeof(expected_size)) {
		if (trustdb_size_to_off_t(size, &native_size) ||
		    (trustdb_size_t)native_size != size)
			return 1;
	} else if (trustdb_size_to_off_t(size, &native_size) == 0)
		return 1;

	if (trustdb_size_from_signed(-1, &size) == 0 ||
	    trustdb_size_to_off_t(UINT64_MAX, &native_size) == 0)
		return 1;

	return 0;
}
