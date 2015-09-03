
CFLAGS += -D_GNU_SOURCE
CFLAGS += -Wall
CFLAGS += -Wextra
CFLAGS += -Werror
CFLAGS += -Wmissing-declarations

OBJS=setns.o
OBJS+=common.o
OBJS+=reallocarray.o

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	OBJS+=platform/linux/linux_ptrace.o
	OBJS+=platform/linux/linux.o
endif

.PHONY: all
all: setns

setns: $(OBJS)

common.o: common.h
setns.o: ptrace.h common.h platform/platform.h $(wildcard platform/*/arch/*.h)
ptrace.o: ptrace.h platform/platform.h $(wildcard platform/*/arch/*.h)

.PHONY: clean
clean:
	rm -f setns $(OBJS)

.PHONY: format
format:
	clang-format-3.7 -i *.h *.c $(shell find platform -type f -name '*.c' -o -name '*.h')
