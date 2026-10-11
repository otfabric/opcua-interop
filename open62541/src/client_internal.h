#pragma once

#include <open62541.h>

/*
 * Helpers shared between client.c and the command modules that live in their
 * own translation units (codec.c, discovery.c).
 */

/* Value of `flag` in argv, or NULL. */
const char *cli_find_arg(int argc, char **argv, const char *flag);

/* Number of occurrences of `flag`. */
int cli_count_flag(int argc, char **argv, const char *flag);

/* 0 when `s` is a structurally valid NodeId string (§8 of the contract). */
int cli_validate_nodeid(const char *s);

/* Parse the i= / ns= forms (no nsu=). UA_NODEID_NULL on error. */
UA_NodeId cli_parse_nodeid_local(const char *s);

/* Resolve an nsu= NodeId on a connected client. 0 on success. */
int cli_resolve_nsu_nodeid(UA_Client *client, const char *s, UA_NodeId *out);

/*
 * Create a client and establish a session honouring the global flags
 * (security, user identity, channel lifetime, reverse listen). On failure the
 * complete error envelope for `op` has been written and *exit_code is set.
 */
UA_Client *cli_make_client(const char *url, int request_ms, const char *op,
                           int *exit_code);

/*
 * Like cli_make_client, but only opens the SecureChannel (no Session), for
 * the discovery service set. Honours the global security flags.
 */
UA_Client *cli_make_channel_client(const char *url, int request_ms, const char *op,
                                   int *exit_code);

/*
 * Create an unconnected client with the default (None) configuration and the
 * silent logger, as used by the session-less discovery commands.
 */
UA_Client *cli_new_plain_client(int request_ms);

/* Emit a complete failure envelope (empty results). */
void cli_emit_failure(const char *op, UA_StatusCode sc, const char *category,
                      const char *message);

/* Print "key":{"name":..,"code":..,"severity":..} (no leading comma). */
void cli_print_status(const char *key, UA_StatusCode sc);

/* Command modules. argv[0] is the subcommand name. */
int cmd_codec(int argc, char **argv);
int cmd_find_servers_on_network(int argc, char **argv);
int cmd_register_server(int argc, char **argv);
