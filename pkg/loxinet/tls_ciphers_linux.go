/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package loxinet

/*
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// The two calls the data plane makes with a rule's cipher string, on a
// context of its own. Bit 0: the TLS 1.3 ciphersuites do not take it. Bit 1:
// the TLS 1.2 cipher list does not take it. -1: no context to ask.
static int llb_tls_ciphers_refused(const char *ciphers) {
  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
  int refused = 0;
  if (!ctx) {
    ERR_clear_error();
    return -1;
  }
  if (SSL_CTX_set_ciphersuites(ctx, ciphers) != 1)
    refused |= 1;
  if (SSL_CTX_set_cipher_list(ctx, ciphers) != 1)
    refused |= 2;
  SSL_CTX_free(ctx);
  ERR_clear_error();
  return refused;
}
*/
import "C"

import "unsafe"

// tlsCiphersRefused asks the TLS library the data plane is built with
// whether it takes a cipher string, as the TLS 1.3 ciphersuites and as the
// TLS 1.2 cipher list. asked is false when the library could not be asked.
func tlsCiphersRefused(ciphers string) (tls13, tls12, asked bool) {
	cCiphers := C.CString(ciphers)
	defer C.free(unsafe.Pointer(cCiphers))
	refused := int(C.llb_tls_ciphers_refused(cCiphers))
	if refused < 0 {
		return false, false, false
	}
	return refused&1 != 0, refused&2 != 0, true
}
