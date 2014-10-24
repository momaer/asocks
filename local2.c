/*
 * local.c
 *
 *  Created on: Oct 15, 2014
 *      Author: gaoshijie
 */

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>

static int listen_port = 1080;
static char* server = NULL;
static int server_port = 10800;
static struct addrinfo *result;

static unsigned char* xorencode(void *data, int len)
{
	unsigned char *buf = (unsigned char *)data;
	while(len-- > 0)
	{
		*(buf+len) ^= 0xff;
	}

	return buf;
}

static int send_all(int fd, void *data, int len)
{

	return len;
}

static int recv_all(int fd, void *data, int len)
{
	char *buf = (char *)data;
	int l = 0;
	while(l < len)
	{
		int s = recv(fd, buf+l, len-l, 0);

		if(s <= 0)
			return s;
		else
			l += s;
	}

	return l;
}

static void redirect_data(int fd, int remotefd)
{
	fd_set read;

	while(1)
	{
		FD_ZERO(&read);
		FD_SET(fd, &read);
		FD_SET(remotefd, &read);

		int ret = select(fd+remotefd, &read, NULL, NULL, NULL);
		if(ret == -1)
			continue;

		char buf[4096] = {0};

		if(FD_ISSET(fd, &read))
		{
			int len = recv(fd, buf, 4096, 0);

			if(len == -1 || len == 0)
			{
				shutdown(fd, SHUT_RDWR);
				close(fd);
				shutdown(remotefd, SHUT_RDWR);
				close(remotefd);
				return;
			}
			send(remotefd, xorencode(buf,len), len, 0);
		}

		if(FD_ISSET(remotefd, &read))
		{
			int len = recv(remotefd, buf, 4096, 0);

			if(len == -1 || len == 0)
			{
				shutdown(fd, SHUT_RDWR);
				close(fd);
				shutdown(remotefd, SHUT_RDWR);
				close(remotefd);
				return;
			}
			send(fd, xorencode(buf,len), len, 0);
		}
	}
}

static void *worker(void *arg)
{
	int clientfd = *((int *)arg);

	/* 版本协商和认证方法 */
	char buf[262] = {0};
	int ret = recv_all(clientfd, buf, 2);
	if(ret <=0)
	{
		shutdown(clientfd, SHUT_RDWR);
		close(clientfd);
		return 0;
	}

	if(buf[0] != 0x05)
	{
		printf("only support socks5.\n");
		shutdown(clientfd, SHUT_RDWR);
		close(clientfd);
		return 0;
	}
	ret = recv_all(clientfd, buf+2, buf[1]);
	if(ret <=0)
	{
		shutdown(clientfd, SHUT_RDWR);
		close(clientfd);
		return 0;
	}

	/* 使用5协议，不需要认证 */
	buf[0] = 0x05;
	buf[1] = 0x00;
	send(clientfd, buf, 2, 0);

	char sendbuf[256] = {0};
	char sendbufindex = 0;

	/* 请求 */
	bzero(buf, 262);
//	recv(clientfd, buf, 4, 0);
	ret = recv_all(clientfd, buf, 4);
	if(ret <= 0)
	{
		printf("recv first 4 bytes request.%d\n", ret);
		shutdown(clientfd, SHUT_RDWR);
		close(clientfd);
		return 0;
	}

	/* only accept connect cmd  */
	if(buf[1] != 1)
	{
		printf("only accept connect cmd. recv cmd:[%d].\n", buf[1]);
		shutdown(clientfd, SHUT_RDWR);
		close(clientfd);
		return 0;
	}

	memcpy(sendbuf+sendbufindex, buf+3, 1);
	sendbufindex += 1;

	/* ip v4 */
	if(buf[3] == 1)
	{
		char remoteip[4] = {0};
//		recv(clientfd, remoteip, 4, 0);
		ret = recv_all(clientfd, remoteip, 4);
		if(ret <= 0)
		{
			shutdown(clientfd, SHUT_RDWR);
			close(clientfd);
			return 0;
		}

		memcpy(sendbuf+sendbufindex, remoteip, 4);
		sendbufindex += 4;
	}
	/* domain name */
	else if(buf[3] == 3)
	{
		char len[1] = {0};
		ret = recv(clientfd, len, 1, 0);
		if(ret <= 0)
		{
			shutdown(clientfd, SHUT_RDWR);
			close(clientfd);
			return 0;
		}

		char *domainame = (char *)malloc(len[0]);
//		recv(clientfd, domainame, len[0], 0);
		recv_all(clientfd, domainame, len[0]);
		if(ret <= 0)
		{
			shutdown(clientfd, SHUT_RDWR);
			close(clientfd);
			return 0;
		}

		memcpy(sendbuf+sendbufindex, len, 1);
		sendbufindex += 1;
		memcpy(sendbuf+sendbufindex, domainame, len[0]);
		sendbufindex += len[0];

		free(domainame);
	}
	/* ip v6 */
	else if(buf[3] == 4)
	{
		printf("remote addr type ip v6 is not supported.\n");
		shutdown(clientfd, SHUT_RDWR);
		close(clientfd);
		return 0;
	}
	else
	{
		//shutdown and destroy client
		printf("remote addr type error.\n");
		shutdown(clientfd, SHUT_RDWR);
		close(clientfd);
		return 0;
	}

	char dstportbuf[2] = {0};
//	recv(clientfd, dstportbuf, 2, 0);
	ret = recv_all(clientfd, dstportbuf, 2);
	if(ret <= 0)
	{
		shutdown(clientfd, SHUT_RDWR);
		close(clientfd);
		return 0;
	}

	//printf("remote port:%d\n", ntohs( *((unsigned short int *)dstportbuf) ) );
	memcpy(sendbuf+sendbufindex, dstportbuf, 2);
	sendbufindex += 2;

	/* 响应 */
	char response[4] = {0x05, 0x00, 0x00, 0x01};
	send(clientfd, response, 4, 0);

	char bndaddr[4] = {0};
	inet_pton(AF_INET, "0.0.0.0", bndaddr);
	send(clientfd, bndaddr, 4, 0);

	unsigned short int bndport = htons((short)listen_port);
	send(clientfd, &bndport, 2, 0);

	/* connect to server */
	int remotefd = socket(AF_INET, SOCK_STREAM, 0);
	int conn = connect(remotefd, result->ai_addr, result->ai_addrlen);

	/* 请求转发给server */
	if(conn == 0)
	{
		char username[10] = {0};
		strcpy(username, "gaoshijie");
		char password[9] = {0};
		strcpy(password, "password");

		char ulen = strlen(username);
		char plen = strlen(password);

		send(remotefd, xorencode(&ulen,1), 1, 0);
		xorencode(&ulen,1);
		send(remotefd, xorencode(username, ulen), ulen, 0);

		send(remotefd, xorencode(&plen,1), 1, 0);
		xorencode(&plen,1);
		send(remotefd, xorencode(password,plen), plen, 0);

		send(remotefd, xorencode(sendbuf,sendbufindex), sendbufindex, 0);
	}
	else
	{
		printf("connect to server failed. return value:%d\n", conn);
		shutdown(clientfd, SHUT_RDWR);
		close(clientfd);
		shutdown(remotefd, SHUT_RDWR);
		close(remotefd);
		return 0;
	}

	redirect_data(clientfd, remotefd);
	return 0;
}



int main(int argc, char* argv[])
{
	if(argc < 4)
	{
		printf("Usage:%s listen_port server server_port\n", argv[0]);
		return 1;
	}

	listen_port = atoi(argv[1]);
	server = argv[2];
	server_port = atoi(argv[3]);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGABRT, SIG_IGN);

	char p[5] = {0};
	sprintf(p, "%d", server_port);

	struct addrinfo hints;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	int err = getaddrinfo(server, p, &hints, &result);

	if(err)
	{
		printf("getaddrinfo error.\n");
		return 1;
	}

	int listenfd = socket(AF_INET, SOCK_STREAM, 0);
	assert(listenfd);

	int opt = 1;
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	inet_pton(AF_INET, "0.0.0.0", &addr.sin_addr);
	addr.sin_port = htons(listen_port);

	int ret = bind(listenfd, (struct sockaddr *)&addr, sizeof(addr));
	assert(ret != -1);

	ret = listen(listenfd, 32);
	assert(ret == 0);

	printf("listening...\n");

	while(1)
	{
		int clientfd = accept(listenfd, NULL, NULL);
//		printf("new connection.\n");

		pthread_t threadid;
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		int ret = pthread_create(&threadid, &attr, &worker, &clientfd);
		pthread_attr_destroy(&attr);

		/* EAGAIN? */
		if(ret != 0)
		{
			printf("pthread_create return %d.\n", ret);
			close(clientfd);
		}
	}

	freeaddrinfo(result);
	close(listenfd);
	return 0;
}
