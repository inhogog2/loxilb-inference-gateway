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
#include <stdint.h>
void proxy_update_halfclose_config(int allow, uint32_t cap_sec, uint8_t default_mode);
void proxy_halfclose_release(void);
*/
import "C"

// The half-close hold's process-wide settings and release, over the controls
// the sockproxy provides for them (loxilb-ebpf/common/sockproxy_hold.h).

// DpHalfCloseConfig - whether new holds may be taken, the idle bound on a
// hold in seconds (the data path clamps it to 1..3600), and the mode of a
// rule that leaves its own unset (enum sp_hold_mode: hold, else off).
func (e *DpEbpfH) DpHalfCloseConfig(allow bool, capSec uint32, defaultMode uint8) {
	a := C.int(0)
	if allow {
		a = 1
	}
	C.proxy_update_halfclose_config(a, C.uint32_t(capSec), C.uint8_t(defaultMode))
}

// DpHalfCloseRelease - close every held client at the data path's next pass.
func (e *DpEbpfH) DpHalfCloseRelease() {
	C.proxy_halfclose_release()
}
