#!/usr/bin/env python3
"""hold_client.py - a client that half-closes after its request, for
validation_hold.sh. Prints one JSON line.

  answered <host> <port> <id>
      ask for a 64 KiB answer held back 300 ms, half-close 20 ms after the
      request, read to EOF: {"status": 200, "body": <bytes>}
  rstidle <host> <port> <id>
      ask for an answer held back 8 s, half-close 20 ms after the request,
      reset 200 ms after that, while nothing has been written to it:
      {"rst": <epoch seconds>}
  rstdrain <host> <port> <id>
      ask for a 32 MiB answer at once with a 64 KiB receive buffer,
      half-close 20 ms after the request, read 64 KiB a second for a second,
      then reset while the answer is still being written to it:
      {"rst": <epoch seconds>, "got": <bytes>}

A reset is SO_LINGER 0 then close: the kernel sends RST and drops the socket.
"""
import json
import socket
import struct
import sys
import time

DRAIN_BYTES = 32 << 20
DRAIN_RATE = 64 << 10


def connect(host, port, rcvbuf=0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if rcvbuf:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    s.settimeout(30)
    s.connect((host, port))
    return s


def request(s, query):
    s.sendall(("GET /?%s HTTP/1.1\r\nHost: hold\r\n\r\n" % query).encode())
    time.sleep(0.02)
    s.shutdown(socket.SHUT_WR)


def reset(s):
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    t = time.time()
    s.close()
    return t


def answered(host, port, rid):
    s = connect(host, port)
    request(s, "id=%s&wait=300&bytes=65536" % rid)
    buf = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            buf += d
    except OSError:
        pass
    head, _, body = buf.partition(b"\r\n\r\n")
    line = head.split(b"\r\n", 1)[0].split(b" ")
    status = int(line[1]) if len(line) > 1 and line[1].isdigit() else 0
    return {"status": status, "body": len(body)}


def rstidle(host, port, rid):
    s = connect(host, port)
    request(s, "id=%s&wait=8000" % rid)
    time.sleep(0.2)
    return {"rst": reset(s)}


def rstdrain(host, port, rid):
    s = connect(host, port, rcvbuf=DRAIN_RATE)
    request(s, "id=%s&bytes=%d" % (rid, DRAIN_BYTES))
    got = 0
    end = time.time() + 1.0
    while time.time() < end:
        try:
            got += len(s.recv(8192))
        except OSError:
            break
        time.sleep(8192.0 / DRAIN_RATE)
    return {"rst": reset(s), "got": got}


def main():
    mode, host, port, rid = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
    fn = {"answered": answered, "rstidle": rstidle, "rstdrain": rstdrain}[mode]
    print(json.dumps(fn(host, port, rid)))


if __name__ == "__main__":
    main()
