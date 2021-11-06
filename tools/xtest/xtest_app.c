#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <errno.h>

#include "xtest.h"

static void parse_and_load_dll(const char *sos)
{
	char *p = strdup(sos);
	char *res = strtok(p, ", ");
	while (res) {
		if (dlopen(res, RTLD_NOW) == NULL) {
			fprintf(stderr, "[Warnning ]: Can not load shared lib: %s, error: %s(errno: %d)\n", res, dlerror(), errno);
		}
		res = strtok(NULL, ", ");
	}
	free(p);
}

static void load_dll(int argc, char **argv)
{
	int i;
	for (i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "--so") == 0) {
			++i;
			if (i < argc)
				parse_and_load_dll(argv[i]);
		}
	}
}

int main(int argc, char **argv)
{
	load_dll(argc, argv);
	
	return xtest_start_test(argc, argv);
}
