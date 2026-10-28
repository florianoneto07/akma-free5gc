/*
 * Copyright 2026 Floriano Neto.
 * Licensed under the GNU General Public License v3.0 or later; see COPYING.
 *
 * Callbacks of wolfSSL that call back into Go. Every WOLFSSL object carries
 * the cgo.Handle of its Conn as I/O context and as PSK callback context.
 */
#ifndef WOLFTLS_SHIM_H
#define WOLFTLS_SHIM_H

#include <stdint.h>
#include <stdlib.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

/* Configures a context made by the Go side: callbacks, PSK, tickets, DTLS
 * cookies. */
void wolftls_setup_server(WOLFSSL_CTX *ctx, int tls13, int tickets, int dtls);
void wolftls_setup_client(WOLFSSL_CTX *ctx, int tls13);

/* Attaches the cgo.Handle h of a Conn to ssl. */
void wolftls_attach(WOLFSSL *ssl, uintptr_t h);

/* Gives a DTLS server connection the address of its client, which the
 * cookies bind to, and turns on the HelloRetryRequest cookie of DTLS 1.3.
 * ip is 4 or 16 octets. Returns 0 on success. */
int wolftls_dtls_peer(WOLFSSL *ssl, const unsigned char *ip, int ipLen, int port, int tls13);

/* Returns the reason text of a wolfSSL error code into buf. */
void wolftls_error_string(int err, char *buf, int len);

#endif
