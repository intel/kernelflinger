/*
 * Copyright (c) 2015, Intel Corporation
 * All rights reserved.
 *
 * Authors: Jeremy Compostella <jeremy.compostella@Intel.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <lib.h>

#include "text_parser.h"

void skip_whitespace(char **line)
{
	char *cur = *line;
	while (*cur && isspace(*cur))
		cur++;
	*line = cur;
}

EFI_STATUS parse_text_buffer(VOID *data, UINTN size,
			     EFI_STATUS (*parse_line)(char *line, VOID *ctx),
			     VOID *context)
{
	EFI_STATUS ret = EFI_SUCCESS;
	char *buf, *line, *eol, *p;
	int lineno = 0;

	/* Extra byte so we can always terminate the last line. */
	buf = AllocatePool(size + 1);
	if (!buf) {
		error(L"Failed to allocate text copy buffer");
		return EFI_OUT_OF_RESOURCES;
	}
	ret = memcpy_s(buf, size + 1, data, size);
	if (EFI_ERROR(ret))
		return ret;

	buf[size] = 0;

	for (line = buf; line - buf < (ssize_t)size; line = eol + 1) {
		lineno++;

		/* Detect line and terminate. */
		eol = (char *)strchr((CHAR8 *)line, '\n');
		if (!eol)
			eol = line + strlen((CHAR8 *)line);
		*eol = 0;

		/* Snip space character for sanity. */
		p = line + strlen((CHAR8 *)line);
		while (p > line && isspace(*(p-1)))
			*(--p) = 0;

		skip_whitespace(&line);
		if (*line == '\0')
			continue;

		ret = parse_line(line, context);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed at line %d", lineno);
			break;
		}
	}

	FreePool(buf);
	return ret;
}
