/*
 * escape_test.c - tests for shell escaping helpers
 */

#include "escape.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>

int main(void)
{
	char *tmp;
	size_t sz;

	/* check_escape_shell */
	sz = check_escape_shell("plain");
	if (sz != 0) {
		fprintf(stderr, "[ERROR:1] plain input %zu\n", sz);
		return 1;
	}
	sz = check_escape_shell("a b");
	if (sz != 4) {
		fprintf(stderr, "[ERROR:1] space %zu\n", sz);
		return 1;
	}
	sz = check_escape_shell("a$b");
	if (sz != 4) {
		fprintf(stderr, "[ERROR:1] metachar %zu\n", sz);
		return 1;
	}
	sz = check_escape_shell("a\nb");
	if (sz != 6) {
		fprintf(stderr, "[ERROR:1] control %zu\n", sz);
		return 1;
	}
	const char high_bit[] = { (char)0x80, ' ', '\0' };
	sz = check_escape_shell(high_bit);
	if (sz != 3) {
		fprintf(stderr, "[ERROR:1] high-bit byte %zu\n", sz);
		return 1;
	}

	/* escape_shell */
	tmp = escape_shell(NULL, 0);
	if (tmp) {
		fprintf(stderr, "[ERROR:2] NULL input\n");
		free(tmp);
		return 2;
	}
	char big_in[8192];
	strcpy(big_in, "abc");
	tmp = escape_shell(big_in, 8192);
	if (tmp) {
		fprintf(stderr, "[ERROR:2] size check\n");
		free(tmp);
		return 2;
	}
	sz = check_escape_shell("a b");
	tmp = escape_shell("a b", sz);
	if (!tmp) {
		fprintf(stderr, "[ERROR:2] escape_shell failed\n");
		return 2;
	}
	if (strcmp(tmp, "a\\ b")) {
		fprintf(stderr, "[ERROR:2] escaped '%s'\n", tmp);
		free(tmp);
		return 2;
	}
	free(tmp);
	tmp = escape_shell("a b", sz - 1);
	if (tmp) {
		fprintf(stderr, "[ERROR:2] accepted undersized output\n");
		free(tmp);
		return 2;
	}
	tmp = escape_shell("a b", sz + 1);
	if (tmp) {
		fprintf(stderr, "[ERROR:2] accepted oversized output\n");
		free(tmp);
		return 2;
	}
	const char high_bit_escaped[] = { (char)0x80, '\\', ' ', '\0' };
	sz = check_escape_shell(high_bit);
	tmp = escape_shell(high_bit, sz);
	if (!tmp || memcmp(tmp, high_bit_escaped, sizeof(high_bit_escaped))) {
		fprintf(stderr, "[ERROR:2] high-bit escape failed\n");
		free(tmp);
		return 2;
	}
	free(tmp);

	char max_in[8191];
	memset(max_in, 'a', sizeof(max_in));
	max_in[sizeof(max_in) - 2] = ' ';
	max_in[sizeof(max_in) - 1] = '\0';
	sz = check_escape_shell(max_in);
	if (sz != 8191) {
		fprintf(stderr, "[ERROR:2] maximum size %zu\n", sz);
		return 2;
	}
	tmp = escape_shell(max_in, sz);
	if (!tmp || strlen(tmp) != sz) {
		fprintf(stderr, "[ERROR:2] maximum escape failed\n");
		free(tmp);
		return 2;
	}
	free(tmp);

	char over_in[8192];
	memset(over_in, 'a', sizeof(over_in));
	over_in[sizeof(over_in) - 2] = ' ';
	over_in[sizeof(over_in) - 1] = '\0';
	sz = check_escape_shell(over_in);
	tmp = escape_shell(over_in, sz);
	if (sz != 8192 || tmp) {
		fprintf(stderr, "[ERROR:2] accepted maximum size\n");
		free(tmp);
		return 2;
	}

	/* unescape_shell */
	char buf1[] = "\\040\\$";
	if (unescape_shell(buf1, sizeof(buf1))) {
		fprintf(stderr, "[ERROR:3] unescape_shell failed\n");
		return 3;
	}
	if (strcmp(buf1, " $")) {
		fprintf(stderr, "[ERROR:3] unescape_shell octal '%s'\n", buf1);
		return 3;
	}
	char buf2[] = "abc\\";
	if (unescape_shell(buf2, sizeof(buf2))) {
		fprintf(stderr, "[ERROR:3] trailing escape failed\n");
		return 3;
	}
	if (strcmp(buf2, "abc\\")) {
		fprintf(stderr, "[ERROR:3] trailing '%s'\n", buf2);
		return 3;
	}
	char buf3[] = "abc\\0";
	if (unescape_shell(buf3, sizeof(buf3))) {
		fprintf(stderr, "[ERROR:3] malformed escape failed\n");
		return 3;
	}
	if (strcmp(buf3, "abc\\0")) {
		fprintf(stderr, "[ERROR:3] malformed '%s'\n", buf3);
		return 3;
	}
	char buf4[] = { 'a', 'b', 'c' };
	if (unescape_shell(buf4, sizeof(buf4)) == 0 ||
	    memcmp(buf4, "abc", sizeof(buf4))) {
		fprintf(stderr, "[ERROR:3] accepted unterminated input\n");
		return 3;
	}
	char buf5 = 'x';
	if (unescape_shell(&buf5, 0) == 0 || buf5 != 'x') {
		fprintf(stderr, "[ERROR:3] accepted zero capacity\n");
		return 3;
	}

	/* unescape */
	tmp = unescape("%41%42");
	if (!tmp || strcmp(tmp, "AB")) {
		fprintf(stderr, "[ERROR:4] unescape valid\n");
		free(tmp);
		return 4;
	}
	free(tmp);
	tmp = unescape("%4");
	if (!tmp || strcmp(tmp, "%4")) {
		fprintf(stderr, "[ERROR:4] unescape short\n");
		free(tmp);
		return 4;
	}
	free(tmp);
	tmp = unescape("%GG");
	if (!tmp || strcmp(tmp, "%GG")) {
		fprintf(stderr, "[ERROR:4] unescape invalid\n");
		free(tmp);
		return 4;
	}
	free(tmp);
	char big[4097 + 1];
	memset(big, 'A', sizeof(big));
	big[sizeof(big) - 1] = '\0';
	tmp = unescape(big);
	if (tmp) {
		fprintf(stderr, "[ERROR:4] unescape big\n");
		free(tmp);
		return 4;
	}

	return 0;
}
