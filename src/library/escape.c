/*
 * escape.c - Source file for escaping capability
 * Copyright (c) 2021,23 Red Hat Inc.
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
#include "escape.h"

#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "message.h"

static const char sh_set[] = "\"'`$\\!()| ";

/*
 * escape_shell_width - return the encoded width of one input byte.
 * @c: byte to classify.
 *
 * Returns four for control bytes, two for shell metacharacters, and one for
 * bytes copied unchanged.
 */
static size_t escape_shell_width(unsigned char c)
{
	if (c < 32)
		return 4;
	if (strchr(sh_set, c))
		return 2;
	return 1;
}

/*
 * escape_shell_size - calculate the encoded string length.
 * @input: NUL-terminated string to inspect.
 * @needs_escape: receives whether any byte needs shell escaping.
 *
 * Returns the encoded length, or SIZE_MAX if its calculation overflows.
 */
static size_t escape_shell_size(const char *input, int *needs_escape)
	__nonnull ((1, 2))
	__attr_access ((__read_only__, 1))
	__attr_access ((__write_only__, 2));
static size_t escape_shell_size(const char *input, int *needs_escape)
{
	size_t input_pos = 0;
	size_t output_size = 0;

	*needs_escape = 0;
	while (input[input_pos]) {
		size_t width = escape_shell_width(
				(unsigned char)input[input_pos]);

		if (width > 1)
			*needs_escape = 1;
		if (output_size > SIZE_MAX - width)
			return SIZE_MAX;
		output_size += width;
		input_pos++;
	}

	return output_size;
}

/*
 * this function checks whether escaping is needed and if yes
 * it returns positive value and this value represents the size
 * of the string after escaping
 */
size_t check_escape_shell(const char *input)
{
	int needs_escape;
	size_t output_size;

	if (!input)
		return 0;

	output_size = escape_shell_size(input, &needs_escape);
	if (!needs_escape)
		return 0;

	return output_size;
}

#define MAX_SIZE 8192

/*
 * escape_shell_into - shell-escape a bounded string into a bounded buffer.
 * @input: bytes to encode.
 * @input_size: number of readable bytes in @input.
 * @output: destination for the encoded NUL-terminated string.
 * @output_capacity: writable size of @output, including its terminator.
 *
 * Returns the encoded length, or SIZE_MAX if the destination is too small.
 */
static size_t escape_shell_into(const char *input, size_t input_size,
				char *output, size_t output_capacity)
	__nonnull ((1, 3))
	__attr_access ((__read_only__, 1, 2))
	__attr_access ((__write_only__, 3, 4));
static size_t escape_shell_into(const char *input, size_t input_size,
				char *output, size_t output_capacity)
{
	size_t input_pos, output_pos = 0;

	if (output_capacity == 0)
		return SIZE_MAX;

	for (input_pos = 0; input_pos < input_size; input_pos++) {
		unsigned char c = (unsigned char)input[input_pos];
		size_t width = escape_shell_width(c);

		/* Keep one byte available for the terminating NUL. */
		if (width >= output_capacity - output_pos)
			return SIZE_MAX;

		if (width == 4) {
			output[output_pos++] = '\\';
			output[output_pos++] = '0' + ((c & 0300) >> 6);
			output[output_pos++] = '0' + ((c & 0070) >> 3);
			output[output_pos++] = '0' + (c & 0007);
		} else if (width == 2) {
			output[output_pos++] = '\\';
			output[output_pos++] = c;
		} else {
			output[output_pos++] = c;
		}
	}
	output[output_pos] = '\0';

	return output_pos;
}

char *escape_shell(const char *input, size_t expected_size)
{
	char *escape_buffer;
	size_t input_size, output_size;

	if (!input)
		return NULL;

	if (expected_size >= MAX_SIZE)
		return NULL;

	escape_buffer = malloc(expected_size + 1);
	if (escape_buffer == NULL)
		return NULL;

	input_size = strlen(input);
	output_size = escape_shell_into(input, input_size, escape_buffer,
					 expected_size + 1);
	if (output_size != expected_size) {
		free(escape_buffer);
		return NULL;
	}

	return escape_buffer;
}

#define isoctal(a) (((a) & ~7) == '0')

/*
 * unescape_shell - decode shell and octal escapes in place.
 * @s: writable NUL-terminated string.
 * @capacity: writable size of @s, including the terminating NUL.
 *
 * Returns 0 on success and -1 if @capacity is zero or no NUL is found within
 * the buffer. Incomplete octal escapes are copied unchanged.
 */
int unescape_shell(char *s, size_t capacity)
{
	const char *end;
	size_t len;
	size_t sz = 0;
	char *buf = s;

	if (capacity == 0)
		return -1;

	end = memchr(s, '\0', capacity);
	if (end == NULL)
		return -1;
	len = (size_t)(end - s);

	while (sz < len) {
		size_t remaining = len - sz;

		if (*s == '\\' && remaining >= 4 && isoctal(s[1]) &&
		    isoctal(s[2]) && isoctal(s[3])) {

			*buf++ = 64*(s[1] & 7) + 8*(s[2] & 7) + (s[3] & 7);
			s += 4;
			sz += 4;
		} else if (*s == '\\' && remaining >= 2 &&
			   !isoctal(s[1])) {
			*buf++ = s[1];
			s += 2;
			sz += 2;
		} else {
			*buf++ = *s++;
			sz++;
		}
	}
	*buf = '\0';

	return 0;
}

#define IS_HEX(X) (isxdigit((unsigned char)(X)) > 0 && \
		   !(islower((unsigned char)(X)) > 0))

static char asciiHex2Bits(char X)
{
	char base = 0;
	if (X >= '0' && X <= '9') {
		base = '0';
	} else if (X >= 'A' && X <= 'F') {
		base = 'A' - 10;
  }
	return (X - base) & 0X00FF;
}

// unescape old format of a trust file
// it makes code backwards compatible
char *unescape(const char *input)
{
	size_t input_len = strlen(input);
	size_t out_len = 0;

	for (size_t i = 0; i < input_len; i++) {
		if (input[i] == '%' && i + 2 < input_len &&
		    IS_HEX(input[i + 1]) && IS_HEX(input[i + 2])) {
			out_len++;
			i += 2;
		} else {
			out_len++;
		}
	}

	if (out_len > 4096)
		return NULL; //for backward compatibility

	char *buffer = malloc(out_len + 1);
	if (!buffer)
		return NULL;

	size_t pos = 0;

	for (size_t i = 0; i < input_len; i++) {
		if (input[i] == '%' && i + 2 < input_len &&
		    IS_HEX(input[i + 1]) && IS_HEX(input[i + 2])) {
			char c = asciiHex2Bits(input[i + 1]);
			char d = asciiHex2Bits(input[i + 2]);
			buffer[pos++] = (c << 4) + d;
			i += 2;
		} else {
			if (input[i] == '%')
				msg(LOG_WARNING,
				    "Input %s does not have a valid escape sequence, "
				    "unable to unescape, copying char by char",
				    input);
			buffer[pos++] = input[i];
		}
	}

	buffer[pos] = '\0';

	return buffer;
}
