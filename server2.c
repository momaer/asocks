/*
 * server.c
 *
 *  Created on: Oct 22, 2014
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
#include <signal.h>
#include <pthread.h>

struct client
{
	int fd;
	char state;
	int remotefd;
};

static unsigned char* xorencode(void *data, int len)
{
	unsigned char *buf = (unsigned char *)data;
	while(len-- > 0)
	{
		*(buf+len) ^= 0xff;
	}

	return buf;
}

void close_socket(int fd)
{
	shutdown(fd, SHUT_RDWR);
	close(fd);
}

void redirect_data(int fd, int remotefd)
{
	fd_set read;

	while(1)
	{
		FD_ZERO(&read);
		FD_SET(fd, &read);
		FD_SET(remotefd, &read);

		int ret = select(fd+remotefd, &read, NULL, NULL, NULL);

		if(ret == -1)
		{
			continue;
		}

		char buf[4096] = {0};

		if(FD_ISSET(fd, &read))
		{
			int len = recv(fd, buf, 4096, 0);

			if(len == -1 || len == 0)
			{
				close_socket(fd);
				close_socket(remotefd);
				return;
			}
			send(remotefd, xorencode(buf,len), len, 0);
		}

		if(FD_ISSET(remotefd, &read))
		{
			int len = recv(remotefd, buf, 4096, 0);

			if(len == -1 || len == 0)
			{
				close_socket(fd);
				close_socket(remotefd);
				return;
			}
			send(fd, xorencode(buf,len), len, 0);
		}
	}
}

void *worker(void *arg)
{
	struct client *c = (struct client *)arg;

	char buf[256] = {0};
	int len = recv(c->fd, buf, 1, 0);
	xorencode(buf, 1);

	if( !(buf[0]>0 && buf[0]<=128) )
	{
		shutdown(c->fd, SHUT_RDWR);
		close(c->fd);
		return 0;
	}

	char* username = (char *)malloc(buf[0] + 1);
	bzero(username, buf[0]+1);
	recv(c->fd, username, buf[0], 0);
	xorencode(username, buf[0]);

	bzero(buf, 1);
	len = recv(c->fd, buf, 1, 0);
	xorencode(buf, 1);

	if( !(buf[0]>0 && buf[0]<=128) )
	{
		shutdown(c->fd, SHUT_RDWR);
		close(c->fd);
		return 0;
	}

	char* password = (char *)malloc(buf[0] + 1);
	bzero(password, buf[0]+1);
	recv(c->fd, password, buf[0], 0);
	xorencode(password, buf[0]);

	free(username);
	free(password);
	/* todo validate username and password */

	len = recv(c->fd, buf, 1, 0);
	xorencode(buf, 1);
	char type = buf[0];

	int remotefd = 0;

	/* ip v4 */
	if(type == 1)
	{
		char dstip[4] = {0};
		len = recv(c->fd, dstip, 4, 0);
		xorencode(dstip, 4);

		unsigned int *pip = NULL;
		pip = (unsigned int *)dstip;

		char port[2] = {0};
		len = recv(c->fd, port, 2, 0);
		xorencode(port, 2);

		unsigned short int *pport = NULL;
		pport = (unsigned short int *)port;

		remotefd = socket(AF_INET, SOCK_STREAM, 0);

		struct sockaddr_in addr;
		bzero(&addr, sizeof(addr));

		addr.sin_family = AF_INET;
		addr.sin_port = *pport;
		addr.sin_addr.s_addr = *pip;

		char humanaddr[256] = {0};
		inet_ntop(AF_INET, (void *)&addr.sin_addr, humanaddr, 256);

		int conn = connect(remotefd, (struct sockaddr *)&addr, sizeof(addr));
		if(conn != 0)
		{
			printf("connecte to remote failed.host:[%s], port:[%d]\n", humanaddr, ntohs(addr.sin_port));
			close_socket(c->fd);
			close(remotefd);
			remotefd = 0;
		}
		else
		{
			//printf("connecte to remote success.host:[%s], port:[%d]\n", humanaddr, ntohs(addr.sin_port));
		}
	}
	else if(type == 3)
	{
		recv(c->fd, buf, 1, 0);
		xorencode(buf, 1);
		char domainnamelen = buf[0];

		char* domainname = (char *)malloc(domainnamelen + 1);
		recv(c->fd, domainname, domainnamelen, 0);
		xorencode(domainname, domainnamelen);
		*(domainname + domainnamelen) = 0;

		char port[2] = {0};
		recv(c->fd, port, 2, 0);
		xorencode(port, 2);

		char temp = port[1];
		port[1] = port[0];
		port[0] = temp;


		short int shortport = *((unsigned short int *)port);
		char a[6] = {0};
		sprintf(a, "%d", shortport);

		struct addrinfo *result;

		struct addrinfo hints;
		//memset(&hints, 0, sizeof(hints));
        bzero(&hints, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;

		int err = getaddrinfo(domainname, a, &hints, &result);

		if(err)
		{
			printf("getaddrinfo error.host:[%s], port:[%s]\n", domainname, a);
			close_socket(c->fd);
			close(remotefd);
			remotefd = 0;
		}
		else
		{
			remotefd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
			int conn = connect(remotefd, result->ai_addr, result->ai_addrlen);

			if(conn != 0)
			{
				printf("connect to remote failed.host:[%s], port:[%s]\n", domainname, a);
				close_socket(c->fd);
				close(remotefd);
				remotefd = 0;
			}
			else
			{
				printf("connecte to remote success.host:[%s], port:[%s]\n", domainname, a);
			}

			freeaddrinfo(result);
		}

		free(domainname);
	}

	if(remotefd > 0)
	{
		redirect_data(c->fd, remotefd);
	}

	free(c);
	return 0;
}

int main(int argc, char* argv[])
{
	if(argc < 3)
	{
		printf("Usage:%s ip port\n", argv[0]);
		return 1;
	}

	signal(SIGPIPE, SIG_IGN);
	signal(SIGABRT, SIG_IGN);

	char* ip = argv[1];
	int port = atoi(argv[2]);

	int listenfd = socket(AF_INET, SOCK_STREAM, 0);

	int opt = 1;
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	inet_pton(AF_INET, ip, &addr.sin_addr);
	addr.sin_port = htons(port);

	int ret = bind(listenfd, (struct sockaddr *)&addr, sizeof(addr));
	assert(ret != -1);

	ret = listen(listenfd, 32);
	assert(ret == 0);

	printf("listening ... \n");

	while(1)
	{
		int clientfd = accept(listenfd, NULL, NULL);
//		printf("new connection.\n");

		struct client *new_client = (struct client *)malloc(sizeof(struct client));
		new_client->fd = clientfd;
		new_client->remotefd = 0;
		new_client->state = 0;

		pthread_t thread;
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		int ret = pthread_create(&thread, &attr, &worker, new_client);
		pthread_attr_destroy(&attr);

		if(ret != 0)
		{
			printf("pthread_create return %d.\n", ret);
			close(clientfd);
			free(new_client);
		}
	}

	close(listenfd);
	return 0;
}
