#pragma once

#include <stddef.h>

/*
 * Reference client subcommand dispatch.
 * argv[0] is "client", argv[1] is the subcommand name.
 * All JSON output goes to stdout; diagnostics to stderr.
 *
 * Exit codes:
 *   0 = success
 *   1 = usage error
 *   2 = connection failed
 *   3 = service error
 */
int client_run(int argc, char **argv);
