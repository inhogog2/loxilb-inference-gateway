//go:build linux

/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package syslog

import (
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// TCP states in which the peer has closed its side or the connection is
// gone, as TCP_INFO reports them.
const (
	tcpStateClose     = 7
	tcpStateCloseWait = 8
	tcpStateLastAck   = 9
)

// boundSilence makes the connection fail once what was written has gone
// unacknowledged for d. Without it the kernel keeps retransmitting to a
// peer that is gone for many minutes, and every write in that time
// succeeds.
func boundSilence(c net.Conn, d time.Duration) {
	tc, ok := c.(*net.TCPConn)
	if !ok || d <= 0 {
		return
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(d/time.Millisecond))
	})
}

// transportState asks the kernel about the connection: how many of the
// bytes written to it the peer has not acknowledged, and whether the peer
// has closed. ok is false when it cannot be asked.
func transportState(c net.Conn) (unacked uint64, peerClosed, ok bool) {
	tc, isTCP := c.(*net.TCPConn)
	if !isTCP {
		return 0, false, false
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return 0, false, false
	}
	cerr := rc.Control(func(fd uintptr) {
		q, err := unix.IoctlGetInt(int(fd), unix.SIOCOUTQ)
		if err != nil || q < 0 {
			return
		}
		info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if err != nil {
			return
		}
		unacked, ok = uint64(q), true
		switch info.State {
		case tcpStateClose, tcpStateCloseWait, tcpStateLastAck:
			peerClosed = true
		}
	})
	if cerr != nil {
		return 0, false, false
	}
	return unacked, peerClosed, ok
}
