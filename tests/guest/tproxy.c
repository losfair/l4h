// SPDX-License-Identifier: GPL-2.0-only
// Native nftables TPROXY data path, used by tests/run-router.sh. The client
// addresses destinations owned by neither VM. TCP getsockname() and UDP
// RECVORIGDSTADDR must preserve those destinations, including the port.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <err.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEST_PORT 4242
#define PROXY_PORT 12345

static const struct {
	int family, type;
	const char *destination, *loopback, *name;
} cases[] = {
	{AF_INET, SOCK_STREAM, "198.51.100.77", "127.0.0.1", "IPv4 TCP"},
	{AF_INET, SOCK_DGRAM, "198.51.100.77", "127.0.0.1", "IPv4 UDP"},
	{AF_INET6, SOCK_STREAM, "2001:db8:77::77", "::1", "IPv6 TCP"},
	{AF_INET6, SOCK_DGRAM, "2001:db8:77::77", "::1", "IPv6 UDP"},
};

static void check(int ok, const char *what)
{
	if (!ok)
		err(1, "TPROXY: FAIL: %s", what);
}

static socklen_t addrlen(int family)
{
	return family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
}

static struct sockaddr_storage address(int family, const char *ip, int port)
{
	struct sockaddr_storage address = {0};
	address.ss_family = family;
	if (family == AF_INET) {
		struct sockaddr_in *a = (void *)&address;
		a->sin_port = htons(port);
		check(inet_pton(family, ip, &a->sin_addr) == 1, "parse IPv4 address");
	} else {
		struct sockaddr_in6 *a = (void *)&address;
		a->sin6_port = htons(port);
		check(inet_pton(family, ip, &a->sin6_addr) == 1, "parse IPv6 address");
	}
	return address;
}

static void same_address(const struct sockaddr_storage *actual,
			 const struct sockaddr_storage *expected)
{
	int same = actual->ss_family == expected->ss_family;
	if (same && actual->ss_family == AF_INET) {
		const struct sockaddr_in *a = (const void *)actual, *e = (const void *)expected;
		same = a->sin_port == e->sin_port && a->sin_addr.s_addr == e->sin_addr.s_addr;
	} else if (same && actual->ss_family == AF_INET6) {
		const struct sockaddr_in6 *a = (const void *)actual, *e = (const void *)expected;
		same = a->sin6_port == e->sin6_port &&
		       !memcmp(&a->sin6_addr, &e->sin6_addr, sizeof(a->sin6_addr));
	}
	if (!same)
		errx(1, "TPROXY: FAIL: original destination address/port changed");
}

static int new_socket(unsigned i, int transparent)
{
	int family = cases[i].family, one = 1;
	int fd = socket(family, cases[i].type, 0);
	check(fd >= 0, "socket");
	if (family == AF_INET6)
		check(!setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)), "V6ONLY");
	if (transparent) {
		int level = family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
		int option = family == AF_INET ? IP_TRANSPARENT : IPV6_TRANSPARENT;
		check(!setsockopt(fd, level, option, &one, sizeof(one)), "TRANSPARENT");
		if (cases[i].type == SOCK_DGRAM) {
			option = family == AF_INET ? IP_RECVORIGDSTADDR : IPV6_RECVORIGDSTADDR;
			check(!setsockopt(fd, level, option, &one, sizeof(one)), "RECVORIGDSTADDR");
		}
	}
	return fd;
}

// Fixed-size records and two round trips: the second UDP packet must reach a
// connected transparent socket through `socket transparent`, as TCP ACK/data
// packets do after the SYN went through `tproxy`.
struct payload {
	uint32_t magic, testcase, round;
};

static struct payload payload(unsigned testcase, unsigned round)
{
	return (struct payload){0x4c346854, testcase, round};
}

static void check_payload(const struct payload *actual, unsigned i, unsigned round)
{
	struct payload expected = payload(i, round);
	if (memcmp(actual, &expected, sizeof(expected)))
		errx(1, "TPROXY: FAIL: %s round %u payload", cases[i].name, round);
}

static void send_payload(int fd, const struct payload *p)
{
	check(send(fd, p, sizeof(*p), MSG_NOSIGNAL) == sizeof(*p), "send payload");
}

static struct payload receive_payload(int fd)
{
	struct payload p;
	check(recv(fd, &p, sizeof(p), MSG_WAITALL) == sizeof(p), "receive payload");
	return p;
}

static struct payload receive_udp(int fd, unsigned i, struct sockaddr_storage *peer)
{
	struct payload p;
	union {
		struct cmsghdr align;
		char bytes[CMSG_SPACE(sizeof(struct sockaddr_in6))];
	} control;
	struct iovec iov = {&p, sizeof(p)};
	struct msghdr msg = {
		.msg_name = peer, .msg_namelen = sizeof(*peer),
		.msg_iov = &iov, .msg_iovlen = 1,
		.msg_control = &control, .msg_controllen = sizeof(control),
	};
	check(recvmsg(fd, &msg, 0) == sizeof(p), "recvmsg UDP");
	check(!(msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)), "UDP truncation");
	int family = cases[i].family;
	struct sockaddr_storage destination = address(family, cases[i].destination, DEST_PORT);
	for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
		if (c->cmsg_level == (family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6) &&
		    c->cmsg_type == (family == AF_INET ? IP_ORIGDSTADDR : IPV6_ORIGDSTADDR)) {
			struct sockaddr_storage original = {0};
			check(c->cmsg_len >= CMSG_LEN(addrlen(family)), "original destination cmsg size");
			memcpy(&original, CMSG_DATA(c), addrlen(family));
			same_address(&original, &destination);
			return p;
		}
	}
	errx(1, "TPROXY: FAIL: %s missing original destination cmsg", cases[i].name);
}

static void serve_tcp(int listener, unsigned i)
{
	int fd = accept(listener, NULL, NULL);
	check(fd >= 0, "accept TCP");
	struct sockaddr_storage local, expected = address(cases[i].family, cases[i].destination, DEST_PORT);
	socklen_t len = sizeof(local);
	check(!getsockname(fd, (void *)&local, &len), "TCP getsockname");
	same_address(&local, &expected);
	for (unsigned round = 0; round < 2; round++) {
		struct payload p = receive_payload(fd);
		check_payload(&p, i, round);
		send_payload(fd, &p);
	}
	close(fd);
}

static void serve_udp(int listener, unsigned i)
{
	struct sockaddr_storage peer;
	struct payload p = receive_udp(listener, i, &peer);
	check_payload(&p, i, 0);
	// Reply from the original destination, not the loopback listener. Keep
	// this connected socket for the second request so nft_socket must find it.
	int fd = new_socket(i, 1);
	struct sockaddr_storage local = address(cases[i].family, cases[i].destination, DEST_PORT);
	check(!bind(fd, (void *)&local, addrlen(local.ss_family)), "bind original UDP destination");
	check(!connect(fd, (void *)&peer, addrlen(peer.ss_family)), "connect UDP reply");
	send_payload(fd, &p);
	struct sockaddr_storage second_peer;
	p = receive_udp(fd, i, &second_peer);
	same_address(&second_peer, &peer);
	check_payload(&p, i, 1);
	send_payload(fd, &p);
	close(fd);
}

int main(int argc, char **argv)
{
	if (argc != 2 || (strcmp(argv[1], "server") && strcmp(argv[1], "client")))
		errx(1, "usage: %s server|client", argv[0]);
	setvbuf(stdout, NULL, _IOLBF, 0);
	int server = !strcmp(argv[1], "server");
	int listeners[4];
	if (server) {
		for (unsigned i = 0; i < 4; i++) {
			listeners[i] = new_socket(i, 1);
			struct sockaddr_storage local = address(cases[i].family, cases[i].loopback, PROXY_PORT);
			check(!bind(listeners[i], (void *)&local, addrlen(local.ss_family)), "bind listener");
			if (cases[i].type == SOCK_STREAM)
				check(!listen(listeners[i], 1), "listen");
		}
		puts("TPROXY: listeners ready");
	}
	for (unsigned i = 0; i < 4; i++) {
		// Bound every blocking operation, including TCP connect and accept.
		alarm(60);
		if (server) {
			if (cases[i].type == SOCK_STREAM)
				serve_tcp(listeners[i], i);
			else
				serve_udp(listeners[i], i);
			close(listeners[i]);
		} else {
			int fd = new_socket(i, 0);
			struct sockaddr_storage destination = address(cases[i].family, cases[i].destination, DEST_PORT);
			check(!connect(fd, (void *)&destination, addrlen(destination.ss_family)), "connect client");
			for (unsigned round = 0; round < 2; round++) {
				struct payload p = payload(i, round);
				send_payload(fd, &p);
				p = receive_payload(fd);
				check_payload(&p, i, round);
			}
			close(fd);
		}
		printf("TPROXY: %s %s original destination %s:%d and two replies verified\n",
		       server ? "server" : "client", cases[i].name, cases[i].destination, DEST_PORT);
	}
	return 0;
}
