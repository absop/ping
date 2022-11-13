"""
Copyright 2022 absop

"""

__version__ = '1.0.0'

import errno
import os
import socket
import struct
import threading

from collections import namedtuple
from time import sleep
from time import time as _get_curr_time


_IPPROTO_ICMPV6 = (socket.IPPROTO_ICMPV6
                    if hasattr(socket, 'IPPROTO_ICMPV6')
                    else 58)


class PingError(Exception): pass


class PingSocketError(socket.gaierror): pass


Reply = namedtuple('Reply', ['seq', 'time'])


class Pinger(object):
    class Args:
        __slots__ = 'addr_set', 'seq_range', 'count', 'waiting_replies'

        def __init__(self, addr_set, seq_range, count, waiting_replies):
            self.addr_set           = addr_set
            self.seq_range          = seq_range
            self.count              = count
            self.waiting_replies    = waiting_replies

        def __iter__(self):
            return map(self.__getattribute__, self.__slots__)

    class ICMPv4:
        ECHO_REQUEST = 8
        ECHO_REPLY   = 0

    class ICMPv6:
        ECHO_REQUEST = 128
        ECHO_REPLY   = 129

    delay = 0.001

    def __init__(self):
        self.pid = os.getpid() & 0xffff
        self._sock4 = None
        self._sock6 = None

    def __del__(self):
        for sock in (self._sock4, self._sock6):
            if sock:
                sock.close()

    def ping(self, addresses, count=2, interval=1.0, timeout=1.0):
        def add_aka(replies, akas_of_ip):
            for ip, info in replies.items():
                akas = akas_of_ip[ip]
                if akas:
                    info['aka'] = ' '.join(set(akas))
        def add_no_replies(akas_of_ip, no_reply_ips):
            for ip in no_reply_ips:
                akas = akas_of_ip[ip]
                if akas:
                    for aka in akas:
                        no_replies[aka] = ip
                else:
                    no_replies[ip] = None
        def handle_ipv6_addrs():
            nonlocal ipv6_replies, no_replies
            ipv6_replies, ipv6_no_replies = self.ping_ipv6(
                akas_of_ipv6, count=count, interval=interval, timeout=timeout)
            add_aka(ipv6_replies, akas_of_ipv6)
            add_no_replies(akas_of_ipv6, ipv6_no_replies)
        akas_of_ipv4, akas_of_ipv6, no_replies = self.resolve_addrs(addresses)
        ipv6_replies = {}
        if akas_of_ipv4:
            ping_ipv6_thread = None
            if akas_of_ipv6:
                ping_ipv6_thread = threading.Thread(target=handle_ipv6_addrs)
                ping_ipv6_thread.start()
            ipv4_replies, ipv4_no_replies = self.ping_ipv4(
                akas_of_ipv4, count=count, interval=interval, timeout=timeout)
            add_aka(ipv4_replies, akas_of_ipv4)
            add_no_replies(akas_of_ipv4, ipv4_no_replies)
            if ping_ipv6_thread:
                ping_ipv6_thread.join()
            if ipv6_replies:
                ipv6_replies.update(ipv4_replies)
            else:
                ipv6_replies = ipv4_replies
        elif akas_of_ipv6:
            handle_ipv6_addrs()
        return ipv6_replies, no_replies

    def ping_ipv4(self, addrs, count=2, interval=1.0, timeout=1.0):
        if self._sock4 is None:
            self._sock4 = self._open_icmp_socket(socket.AF_INET,
                socket.IPPROTO_ICMP)
        return self._ping(self._sock4,
            self.ICMPv4, addrs, count, interval, timeout)

    def ping_ipv6(self, addrs, count=2, interval=1.0, timeout=1.0):
        if self._sock6 is None:
            try:
                self._sock6 = self._open_icmp_socket(socket.AF_INET6,
                    _IPPROTO_ICMPV6)
            except socket.error:
                raise PingSocketError("IPv6 address family not supported")
        return self._ping(self._sock6,
            self.ICMPv6, addrs, count, interval, timeout)

    def _ping(self, sock, proto, addrs, count, interval, timeout):
        if not addrs:
            return {}, []
        args = self._check_args(addrs, count, interval, timeout)
        send = self._send_icmp_echo_request
        recv = self._recv_icmp_echo_replies
        send_type = proto.ECHO_REQUEST
        recv_type = proto.ECHO_REPLY
        replies, no_replies = {}, []
        remaining_time = timeout + (count - 1) * interval
        thread = threading.Thread(target=recv,
            args=(sock, recv_type, replies, remaining_time, args)
            )
        thread.start()
        for seq in args.seq_range:
            for addr in args.addr_set:
                send(sock, send_type, addr, seq)
            if seq < count:
                sleep(interval)
        end_time = _get_curr_time() + timeout
        thread.join()
        remaining_time = end_time - _get_curr_time()
        if remaining_time > self.delay and args.waiting_replies:
            recv(sock, recv_type, replies, remaining_time, args)
        for addr in args.addr_set:
            if addr in replies:
                replies[addr] = {'replies': replies[addr]}
            else:
                no_replies.append(addr)
        return replies, no_replies

    def _check_args(self, addrs, count, interval, timeout):
        if len(addrs) > 2000:
            raise PingError("Too many addresses (maximum 2000)")
        if count < 1:
            raise PingError("Invalid count %s" % count)
        if interval < 0.1:
            raise PingError("Too small interval (minimum 0.1)")
        if timeout < self.delay:
            raise PingError("Too small timeout (minimum %s)" % self.delay)
        addr_set = addrs
        if not isinstance(addr_set, (set, dict)):
            addr_set = set(addr_set)
        waiting_replies = count * len(addr_set)
        return self.Args(addr_set, range(1, count + 1), count, waiting_replies)

    def resolve_addrs(self, addresses):
        ipv4_addrs = {}
        ipv6_addrs = {}
        unkown_addrs = {}
        for addr in addresses:
            ipaddr = None
            family = None
            try:
                addr_info = socket.getaddrinfo(addr, None)
                for res in addr_info:
                    # Prefer IPv4 addresses
                    if res[0] == socket.AF_INET:
                        family = socket.AF_INET
                        ipaddr = res[4][0]
                        break
                    elif not ipaddr:
                        family = socket.AF_INET6
                        ipaddr = res[4][0]
            except socket.gaierror:
                pass
            if family == socket.AF_INET:
                if ipaddr not in ipv4_addrs:
                    ipv4_addrs[ipaddr] = []
                if addr != ipaddr:
                    ipv4_addrs[ipaddr].append(addr)
            elif family == socket.AF_INET6:
                if ipaddr not in ipv6_addrs:
                    ipv6_addrs[ipaddr] = []
                if addr != ipaddr:
                    ipv6_addrs[ipaddr].append(addr)
            else:
                unkown_addrs[addr] = None
        return ipv4_addrs, ipv6_addrs, unkown_addrs

    @staticmethod
    def _open_icmp_socket(family, proto):
        """ Let exceptions be exceptions
        """
        sock = socket.socket(family, socket.SOCK_RAW, proto)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 131072)
        return sock

    def _checksum(self, msg):
        """
        Calculate the checksum of a packet.

        This is inspired by a response on StackOverflow here:
        https://stackoverflow.com/a/1769267/7242672

        Thank you to StackOverflow user Jason Orendorff.

        """
        def carry_around_add(a, b):
            c = a + b
            return (c & 0xffff) + (c >> 16)

        s = 0
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + msg[i + 1]
            s = carry_around_add(s, w)
        s = ~s & 0xffff

        return s

    def _send_icmp_echo_request(self, sock, ipcmtyp, dest_address, seq_number):
        """
        Send an ICMP Echo message to the given address.

                    ICMPv4 Echo and Echo Reply Message Format

        0       4       8       12      16      20      24      28      32
        |_______|_______|_______|_______|_______|_______|_______|_______|
        | Type = 0 or 8 |   Code = 0    |           Checksum            |
        |-------------------------------+-------------------------------|
        |            Identifier         |        Sequence Number        |
        |---------------------------------------------------------------|
        |                                                               |
        =                        Optional Data                          =
        |                                                               |
        -----------------------------------------------------------------
                                  ICMPv6 packet
        |---------------------------------------------------------------|
        | Bit offset |    0-7     |    8-15    |         16-31          |
        |     0      |    Type    |    Code    |         Checksum       |
        |------------|--------------------------------------------------|
        |     32     |                   Message body                   |
        |---------------------------------------------------------------|
        """
        payload = struct.pack('!d', _get_curr_time())
        icmp_header = struct.pack('!BBHHH',
                                  ipcmtyp, 0, 0, self.pid, seq_number & 0xffff)
        packet = bytearray(icmp_header + payload)
        checksum = self._checksum(packet)
        packet[2:4:] = struct.pack('!H', checksum)
        try:
            sock.sendto(packet, (dest_address, 0))
        except Exception:
            pass

    def _recv_icmp_echo_replies(self, sock, ipcmtyp, replies, timeout, args):
        if ipcmtyp == self.ICMPv4.ECHO_REPLY:
            offset, end = 20, 36
        else:
            offset, end = 0, 16
        end_time = _get_curr_time() + timeout
        remaining_time = timeout
        dest_addresses, seq_range, count, waiting_replies = args
        while waiting_replies > 0 and remaining_time > 0:
            try:
                sock.settimeout(remaining_time)
                while waiting_replies > 0:
                    pkt, address = sock.recvfrom(64)
                    receive_time = _get_curr_time()
                    _type, _, _, pkt_id, seq, sent_time = struct.unpack(
                        '!BBHHHd', pkt[offset:end]
                    )
                    if _type == ipcmtyp and pkt_id == self.pid:
                        time = receive_time - sent_time
                        addr = address[0]
                        if addr not in dest_addresses:
                            continue
                        reps = replies.setdefault(addr, [])
                        if time > 0 and seq in seq_range or len(reps) < count:
                            reps.append(Reply(seq, time))
                            waiting_replies -= 1
                            sock.settimeout(0)
            except socket.timeout:
                pass
            except socket.error as e:
                if e.errno == errno.EWOULDBLOCK:
                    pass
                else:
                    raise
            remaining_time = end_time - _get_curr_time()
        args.waiting_replies = waiting_replies
