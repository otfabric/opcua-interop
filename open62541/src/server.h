#pragma once

#include "fixture.h"

typedef struct {
    char *fixturePath;

    /* Network binding */
    char *bindAddress;      /* default: "0.0.0.0" */
    int   bindPort;         /* default: from fixture endpoint.port */

    /* What clients see in GetEndpoints */
    char *advertisedHost;   /* default: "localhost" */
    int   advertisedPort;   /* default: same as bindPort */
    char *endpointPath;     /* default: from fixture endpoint.path */

    /* PKI and readiness */
    char *pkiDir;
    char *certFile;     /* server application certificate (DER) */
    char *keyFile;      /* server private key (DER) */
    char *readyFile;
    int   readyFileExplicit; /* 1 if --ready-file was given on the command line */
} ServerArgs;

/*
 * Parse server subcommand arguments.
 * Returns 0 on success, non-zero on usage error (errBuf filled).
 */
int server_parse_args(int argc, char **argv, ServerArgs *out,
                      char *errBuf, size_t errLen);

/*
 * Build and run an OPC UA server from the loaded Fixture.
 * Blocks until SIGTERM/SIGINT is received.
 * Returns 0 on clean shutdown, non-zero on error.
 */
int server_run(const ServerArgs *args);
