/*
 * escape.h - Header file for escaping capability
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

#ifndef ESCAPE_H
#define ESCAPE_H

#include "gcc-attributes.h"

/* @expected_size must be the exact encoded length, excluding its NUL. */
char *escape_shell(const char *input, size_t expected_size) __attribute_malloc__
	__attr_dealloc_free __wur __attr_access ((__read_only__, 1));
/* Return the encoded length when escaping is needed, otherwise zero. */
size_t check_escape_shell(const char *input) __wur
	__attr_access ((__read_only__, 1));
/* @capacity includes the required NUL terminator. */
int unescape_shell(char *s, size_t capacity) __nonnull ((1)) __wur
	__attr_access ((__read_write__, 1, 2));

char *unescape(const char *input) __attribute_malloc__ __attr_dealloc_free
	__nonnull ((1)) __wur __attr_access ((__read_only__, 1));

#endif
