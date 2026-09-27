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

package common

// FcQueuePairError holds the one rule that spans a service's two capacity
// queue fields: a depth without a wait window would park a request forever,
// so the window is required with it. It is judged on the values that will be
// stored, which on a replace or a PATCH means after the request is merged
// with the stored rule: an update may carry one field and keep the other.
func FcQueuePairError(depth, waitMs uint32) error {
	if depth > 0 && waitMs == 0 {
		return NewValidationError("fc_max_queue_wait_ms",
			"fc_max_queue_wait_ms must be greater than 0 when fc_max_queue_depth is set")
	}
	return nil
}
