#pragma once

#include "fixture.h"

typedef struct {
    char *fixturePath;
    char *endpointUrl;  /* full opc.tcp://... URL */
    char *pkiDir;
    char *readyFile;
} ServerArgs;

/*
 * Parse server subcommand arguments.
 * Returns 0 on success, non-zero on usage error.
 */
int server_parse_args(int argc, char **argv, ServerArgs *out,
                      char *errBuf, size_t errLen);

/*
 * Build and run an OPC UA server from the loaded Fixture.
 * Blocks until SIGTERM/SIGINT is received.
 * Returns 0 on clean shutdown, non-zero on error.
 */
int server_run(const ServerArgs *args);
