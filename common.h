
#include <stdarg.h>

#define assert_nonzero(expr)                                                   \
	({                                                                     \
		typeof(expr) __val = expr;                                     \
		if (__val == 0)                                                \
			die("Unexpected: %s == 0!\n", #expr);                  \
		__val;                                                         \
	})

#define __printf __attribute__((format(printf, 1, 2)))
void __printf die(const char *msg, ...) __attribute__((noreturn));
void __printf debug(const char *msg, ...);
void __printf error(const char *msg, ...);
