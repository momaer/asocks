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
#include "json.h"

struct client
{
	int fd;
	char state;
	int remotefd;
};

struct account
{
    char id[32+1];
    char password[32+1];
    char expire[10+1];
};

struct server_config
{
    char server[15+1];
    char server_port[5+1];
    struct account accounts[64];
};

static struct server_config *config = NULL;

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

int check_account(const char *id, const char *password)
{
    int i = 0;
    for(; i<64; i++)
    {
        struct account a = config->accounts[i];

        if(a.id[0] != 0x00)
        {
            if(strcmp(a.id, id) == 0 && strcmp(a.password, password) == 0)
            {
                time_t rawtime;
                struct tm *timeinfo;
                char buf[80];

                time(&rawtime);
                timeinfo = localtime(&rawtime);

                strftime(buf, 80, "%Y-%m-%d", timeinfo);

                if(strcmp(a.expire, buf) > 0)
                {
                    return 0;
                }
                break;
            }
        }
    }

    return 1;
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

    //printf("id:%s, password:%s.\n", username, password);

    if(check_account(username, password) != 0)
    {
        free(username);
        free(password);

        shutdown(c->fd, SHUT_RDWR);
        close(c->fd);

        free(c);
        c = NULL;
        return 0;
    }

	free(username);
	free(password);

    bzero(buf, sizeof(buf));
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
    else
    {
        printf("Invalid type:%d\n", type);
    }

	if(remotefd > 0)
	{
		redirect_data(c->fd, remotefd);
	}

	free(c);
    c = NULL;
	return 0;
}

static int parse_config(const char* config_path, struct server_config *config)
{
    FILE *f = fopen(config_path, "rb");
    if(f == NULL)
    {
        printf("Invalid config path.\n");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long pos = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = (char *)malloc(pos + 1);
    if(buf == NULL)
    {
        printf("No enough memory.\n");
        return 1;
    }

    int nread = fread(buf, pos, 1, f);
    if(!nread)
    {
        printf("Failed to read the config file.\n");
        fclose(f);
        return 1;
    }
    buf[pos] = 0x00;

    json_settings settings = {0};
    char error_buf[512];
    json_value *obj;
    obj = json_parse_ex(&settings, buf, pos, error_buf);
    if(obj == NULL)
    {
        printf("%s", error_buf);
        return 1;
    }

    if(obj->type == json_object)
    {
        unsigned int i;
        for(i = 0; i < obj->u.object.length; i++)
        {
            char *name = obj->u.object.values[i].name;
            json_value *value = obj->u.object.values[i].value;

            if(strcmp(name, "server") == 0)
            {
                strncpy(config->server, value->u.string.ptr, value->u.string.length);
            }
            else if(strcmp(name, "server_port") == 0)
            {
                strncpy(config->server_port, value->u.string.ptr, value->u.string.length);
            }
            else if(strcmp(name, "accounts") == 0)
            {
                if(value->type == json_array)
                {
                    unsigned int j;
                    for(j = 0; j < value->u.array.length; j++)
                    {
                        json_value *item = value->u.array.values[j];
                        unsigned int fields_length = item->u.object.length;
                        unsigned int k;
                        for(k = 0; k < fields_length; k++)
                        {
                            char *account_name = item->u.object.values[k].name;
                            json_value *account_value = item->u.object.values[k].value;

                            if(strcmp(account_name, "id") == 0)
                            {
                                strncpy( config->accounts[j].id, account_value->u.string.ptr, account_value->u.string.length );
                            }
                            else if(strcmp(account_name, "password") == 0)
                            {
                                strncpy( config->accounts[j].password, account_value->u.string.ptr, account_value->u.string.length );
                            }
                            else if(strcmp(account_name, "expire") == 0)
                            {
                                strncpy( config->accounts[j].expire, account_value->u.string.ptr, account_value->u.string.length );
                            }
                        }
                    }
                }
            }
        }
    }
    else
    {
        printf("Invalid config file.\n");
        return 1;
    }

    free(buf);
    json_value_free(obj);

    return 0;
}

int main(int argc, char* argv[])
{
	char *config_path = "config.json";

    config = (struct server_config *)malloc(sizeof(struct server_config));
    bzero(config, sizeof(struct server_config));

    int ret = 0;

    ret = parse_config(config_path, config);
    if(ret != 0)
    {
        return 1;
    }

	signal(SIGPIPE, SIG_IGN);
	signal(SIGABRT, SIG_IGN);

	int listenfd = socket(AF_INET, SOCK_STREAM, 0);

	int opt = 1;
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	inet_pton(AF_INET, config->server, &addr.sin_addr);
	addr.sin_port = htons( atoi(config->server_port) );

	ret = bind(listenfd, (struct sockaddr *)&addr, sizeof(addr));
	assert(ret != -1);

	ret = listen(listenfd, 32);
	assert(ret == 0);

	printf("listening on %s:%s ... \n", config->server, config->server_port);

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
