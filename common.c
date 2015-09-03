#include <stdio.h>
#include <stdlib.h>

#include "platform/platform.h"
#include "common.h"
#include "reallocarray.h"

static void
_debug(const char *pfx, const char *msg, va_list ap)
{

	if (pfx)
		fprintf(stderr, "%s", pfx);
	vfprintf(stderr, msg, ap);
	fprintf(stderr, "\n");
}

void
die(const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	_debug("[!] ", msg, ap);
	va_end(ap);

	exit(1);
}

void
debug(const char *msg, ...)
{

	va_list ap;

	va_start(ap, msg);
	_debug("[+] ", msg, ap);
	va_end(ap);
}

void
error(const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	_debug("[-] ", msg, ap);
	va_end(ap);
}

int
fd_array_push(struct fd_array *fda, int fd)
{
	int *tmp;

	if (fda->n == fda->allocated) {
		fda->allocated = fda->allocated ? 2 * fda->allocated : 2;
		tmp = xreallocarray(fda->fds, fda->allocated, sizeof *tmp);
		if (tmp == NULL) {
			free(fda->fds);
			fda->fds = NULL;
			fda->allocated = 0;
			return -1;
		}
		fda->fds = tmp;
	}
	fda->fds[fda->n++] = fd;
	return 0;
}
