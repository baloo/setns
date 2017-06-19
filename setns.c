/*
 * Copyright (C) 2011 by Nelson Elhage
 * Copyright (C) 2015 by Arthur Gautier
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <ctype.h>
#include <errno.h>
#include <linux/capability.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/prctl.h>

#include "platform/platform.h"
#include "common.h"
#include "ptrace.h"

#ifdef HAVE___PROGNAME
extern const char *__progname;
#else
#define __progname "setns"
#endif

#define NETNS_RUN_DIR "/var/run/netns"
#define PROC_NS_NET "/proc/%s/ns/net"

static void
do_unmap(struct ptrace_child *child, child_addr_t addr, unsigned long len)
{
	if (addr == (child_addr_t)-1)
		return;
	do_syscall(child, munmap, (unsigned long)addr, len, 0, 0, 0, 0);
}

static int
mmap_scratch(struct ptrace_child *child, child_addr_t *addr)
{
	long mmap_syscall;
	child_addr_t scratch_page;

	mmap_syscall = ptrace_syscall_numbers(child)->nr_mmap2;
	if (mmap_syscall == -1)
		mmap_syscall = ptrace_syscall_numbers(child)->nr_mmap;
	scratch_page = ptrace_remote_syscall(
	    child, mmap_syscall, 0, sysconf(_SC_PAGE_SIZE),
	    PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);

	if (scratch_page > (unsigned long)-1000) {
		return -(signed long)scratch_page;
	}

	*addr = scratch_page;

	return 0;
}

static int
grab_pid(pid_t pid, struct ptrace_child *child, child_addr_t *scratch)
{
	int err;

	if (ptrace_attach_child(child, pid)) {
		err = child->error;
		goto out;
	}
	if (ptrace_advance_to_state(child, ptrace_at_syscall)) {
		err = child->error;
		goto out;
	}
	if (ptrace_save_regs(child)) {
		err = child->error;
		goto out;
	}

	if ((err = mmap_scratch(child, scratch)))
		goto out_restore_regs;

	return 0;

out_restore_regs:
	ptrace_restore_regs(child);

out:
	ptrace_detach_child(child);

	return err;
}

static int
ignore_hup(struct ptrace_child *child, child_addr_t scratch_page)
{
	int err;

	struct sigaction act = {
	    .sa_handler = SIG_IGN,
	};
	err = ptrace_memcpy_to_child(child, scratch_page, &act, sizeof act);
	if (err < 0)
		return err;
	err = do_syscall(child, rt_sigaction, SIGHUP,
			 (unsigned long)scratch_page, 0, 8, 0, 0);

	return err;
}

static int
child_setns(pid_t pid, const char *nspath, bool drop_capability)
{
	int err, nsfd;
	struct ptrace_child child;
	child_addr_t scratch_page = -1;
	long page_size = sysconf(_SC_PAGE_SIZE);

	if ((err = grab_pid(pid, &child, &scratch_page))) {
		return 3;
	}

	err = ptrace_memcpy_to_child(&child, scratch_page, nspath,
				     strlen(nspath) + 1);
	if (err < 0) {
		err = 4;
		goto unmap;
	}

	nsfd = do_syscall(&child, open, scratch_page, O_RDONLY | O_CLOEXEC, 0,
			  0, 0, 0);
	if (nsfd < 0) {
		err = 5;
		goto unmap;
	}

	err = ignore_hup(&child, scratch_page);
	if (err < 0) {
		goto close;
	}

	err = do_syscall(&child, setns, nsfd, CLONE_NEWNET, 0, 0, 0, 0);
	if (err < 0) {
		error("setns failed");
		goto close;
	}

	if (drop_capability) {
		struct __user_cap_header_struct header;
		struct __user_cap_data_struct data;

		child_addr_t scratch_page_header = -1;
		child_addr_t scratch_page_data = -1;

		/* Drop SYS_ADMIN capability in all future tasks */
		if ((err = do_syscall(&child, prctl, PR_CAPBSET_DROP,
				      CAP_SYS_ADMIN, 0, 0, 0, 0)) != 0) {
			error("prctl failed");
			goto close;
		}

		/* Avoid getting back SYS_ADMIN capability by calling setuid */
		if ((err = do_syscall(&child, prctl, PR_SET_KEEPCAPS,
				      1, 0, 0, 0, 0)) != 0) {
			error("prctl failed");
			goto close;
		}

		/* Allocate two shared pages to store capset header/data */
		if ((err = mmap_scratch(&child, &scratch_page_header)) != 0) {
			error("scratch_page_header allocation failed");
			goto close;
		}

		if ((err = mmap_scratch(&child, &scratch_page_data)) != 0) {
			error("scratch_page_data allocation failed");
			goto unmap_header;
		}

		header.pid = pid;
		header.version = _LINUX_CAPABILITY_VERSION_3;

		/* Fill header page with valid data */
		if ((err = ptrace_memcpy_to_child(&child, scratch_page_header,
						  &header, sizeof(header))) !=
		    0) {
			error("capget copy header failed");
			goto unmap_data;
		}

		/* Get current capabilities back in data page */
		if ((err = do_syscall(&child, capget, scratch_page_header,
				      scratch_page_data, 0, 0, 0, 0)) != 0) {
			error("capget failed");
			goto unmap_data;
		}

		/* Get back data page in current context */
		if ((err = ptrace_memcpy_from_child(&child, &data,
						    scratch_page_data,
						    sizeof(data))) != 0) {
			error("capget copy failed");
			goto unmap_data;
		}

		/* Drop SYS_ADMIN capability */
		data.effective &= ~CAP_TO_MASK(CAP_SYS_ADMIN);

		/* Put back data in child' page */
		if ((err = ptrace_memcpy_to_child(&child, scratch_page_data,
						  &data, sizeof(data))) != 0) {
			error("capget copyback failed");
			goto unmap_data;
		}

		/* Actually call capset to drop SYS_ADMIN capability */
		if ((err = do_syscall(&child, capset, scratch_page_header,
				      scratch_page_data, 0, 0, 0, 0)) != 0) {
			error("capset failed");
		}

	unmap_data:
		do_unmap(&child, scratch_page_data, page_size);
	unmap_header:
		do_unmap(&child, scratch_page_header, page_size);
	}

close:
	err = do_syscall(&child, close, nsfd, 0, 0, 0, 0, 0);

unmap:
	do_unmap(&child, scratch_page, page_size);

	ptrace_restore_regs(&child);
	ptrace_detach_child(&child);

	kill(child.pid, SIGWINCH);
	kill(child.pid, SIGCONT);

	return err;
}

static void
usage()
{
	fprintf(stderr, "Usage:   %s [OPTIONS ...]\n", __progname);
	fprintf(stderr, "-n name   Name of netns.\n");
	fprintf(stderr, "-p pid    Pid of target, if undefined ppid is used\n");
	fprintf(stderr, "-d        Drop CAP_SYS_ADMIN capability\n");
	exit(EXIT_FAILURE);
}

static int
is_pid(const char *str)
{
	int ch;
	for (; (ch = *str); str++) {
		if (!isdigit(ch))
			return 0;
	}
	return 1;
}

int
main(int argc, char **argv)
{
	pid_t child = -1;
	bool drop_capability = false;
	char ch;
	char pathbuf[MAXPATHLEN];
	char *nspath = NULL, *pidspec = NULL, *netspec = NULL;
	const char *options = "dn:p:";

	while ((ch = getopt(argc, argv, options)) != -1) {
		switch (ch) {
		case 'p':
			pidspec = optarg;
			break;
		case 'n':
			netspec = optarg;
			break;
		case 'd':
			drop_capability = true;
			break;
		default:
			usage();
		}
	}

	if (netspec == NULL)
		usage();

	if (pidspec != NULL) {
		char *endptr = NULL;
		errno = 0;
		long t = strtol(pidspec, &endptr, 10);
		if (errno == ERANGE)
			perror("Invalid pid");
		if (*endptr != '\0') {
			fprintf(stderr, "Invalid pid: must be integer %s\n",
				endptr);
			exit(EXIT_FAILURE);
		}
		child = (pid_t)t;
	} else {
		child = getppid();
	}

	if (is_pid(netspec) == 1) {
		snprintf(pathbuf, sizeof(pathbuf) - 1, PROC_NS_NET, netspec);
		nspath = pathbuf;
	} else {
		const char *ptr;

		nspath = netspec;
		ptr = strchr(netspec, '/');

		if (!ptr) {
			snprintf(pathbuf, sizeof(pathbuf), "%s/%s",
				 NETNS_RUN_DIR, netspec);
		}
		nspath = pathbuf;
	}

	return child_setns(child, nspath, drop_capability);
}
