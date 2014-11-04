// asocks.cpp : 定义控制台应用程序的入口点。
//

#include <WinSock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <assert.h>
#include <map>
#include <list>
#pragma comment (lib, "Ws2_32.lib")

using namespace std;

#define BUFFER_SIZE 4096
#define CLIENT_COUNT 1024

typedef struct remote_ctx
{
	SOCKET remote_fd;
	char read_buf[BUFFER_SIZE];
	char write_buf[BUFFER_SIZE];
	int read_base;
	int read_length;
	int write_base;
	int write_length;
	int state;
	int connected;
	struct client_ctx *client;
} remote_ctx;

typedef struct client_ctx
{
	SOCKET client_fd;
	char read_buf[BUFFER_SIZE];
	char write_buf[BUFFER_SIZE];
	int read_base;
	int read_length;
	int write_base;
	int write_length;
	int state;
	struct remote_ctx *remote;
} client_ctx;

static unsigned char* xorencode(void *data, int len)
{
	unsigned char *buf = (unsigned char *)data;
	while(len-- > 0)
	{
		*(buf+len) ^= 0xff;
	}
	return buf;
}

static void set_nonblock(SOCKET fd)
{
	u_long i = 1;
	ioctlsocket(fd, FIONBIO, &i);
}

static std::map<SOCKET, client_ctx*> clients;
static std::map<SOCKET, remote_ctx*> remotes;

int main(int argc, char* argv[])
{
	if(argc < 4)
	{
		printf("Usage:%s local_port server server_port\n", argv[0]);
		return 1;
	}
	//char* server = "sg.actself.me";
	//char* server_port = "10801";
	//char* local_addr = "0.0.0.0";
	//char* local_port = "1081";

	char* local_port = argv[1];
	char* server = argv[2];
	char* server_port = argv[3];
	char* local_addr = "0.0.0.0";
	
	int ret = 0;

	WSADATA wsa;
	if(WSAStartup(MAKEWORD(2,2), &wsa) != 0)
	{
		printf("WSAStartup failed.\n");
		return 1;
	}

	struct addrinfo *result;
	
	struct addrinfo hints;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(local_addr, local_port, &hints, &result);
	if(ret != 0)
	{
		printf("getaddrinfo failed.%d\n", ret);
		return 1;
	}

	struct addrinfo *result2;
	
	struct addrinfo hints2;
	ZeroMemory(&hints2, sizeof(hints2));
	hints2.ai_family = AF_INET;
	hints2.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(server, server_port, &hints2, &result2);
	if(ret != 0)
	{
		printf("getaddrinfo failed.%d\n", ret);
		return 1;
	}

	SOCKET listen_fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if(listen_fd == INVALID_SOCKET)
	{
		printf("socket() failed.\n");
		return 1;
	}
	
	ret = bind(listen_fd, result->ai_addr, result->ai_addrlen);
	assert(ret == 0);
	freeaddrinfo(result);

	ret = listen(listen_fd, 32);
	assert(ret == 0);
	printf("listen on %s:%s ...\n", local_addr, local_port);

	fd_set readfds;
	fd_set writefds;

	std::list<SOCKET> client_to_remove;
	std::list<SOCKET> remote_to_remove;
	
	for(; ;)
	{
		client_to_remove.clear();
		remote_to_remove.clear();

		FD_ZERO(&readfds);
		FD_ZERO(&writefds);

		FD_SET(listen_fd, &readfds);

		map<SOCKET, client_ctx*>::iterator it = clients.begin();
		for(; it != clients.end(); it++)
		{
			SOCKET client_fd = it->first;
			client_ctx *c = it->second;

			FD_SET(client_fd, &readfds);

			if( c->write_length - c->write_base > 0 )
			{
				FD_SET(client_fd, &writefds);
			}
		}

		map<SOCKET, remote_ctx*>::iterator it2 = remotes.begin();
		for(; it2 != remotes.end(); it2++)
		{
			SOCKET remote_fd = it2->first;
			remote_ctx *r = it2->second;

			FD_SET(remote_fd, &readfds);

			if( (r->connected == 0) ||  (r->write_length - r->write_base > 0) )
			{
				FD_SET(remote_fd, &writefds);
			}
		}

		ret = select(0, &readfds, &writefds, NULL, NULL);
		
		if(ret == 0)
		{
			printf("select time out.\n");
			continue;
		}
		else if (ret == SOCKET_ERROR)
		{
			int error_code = WSAGetLastError();
			printf("select return error. code:%d\n", error_code);
			continue;
		}

		/* accept */
		if(FD_ISSET(listen_fd, &readfds))
		{
			SOCKET client_fd = accept(listen_fd, NULL, NULL);

			set_nonblock(client_fd);

			client_ctx *new_client = (client_ctx *)malloc(sizeof(client_ctx));
			ZeroMemory(new_client, sizeof(client_ctx));
			new_client->client_fd = client_fd;
			
			clients.insert(std::pair<SOCKET, client_ctx*>(client_fd, new_client));
			//printf("new client connected.\n");
		}

		/* recv data from client */
		it = clients.begin();
		for(; it != clients.end(); it++)
		{
			SOCKET client_fd = it->first;
			client_ctx *c = it->second;

			if(FD_ISSET(client_fd, &readfds))
			{
				int left = (BUFFER_SIZE-c->read_length);
				if(left == 0)
				{
					printf("client read buf has no space left.\n");
				}
				else
				{
					int len = recv(client_fd, c->read_buf + c->read_length, left, 0);
					if(len <= 0)
					{
						//printf("recv data from client failed. recv length:%d, state:%d\n", len, c->state);
						client_to_remove.push_back(client_fd);
						continue;
					}
					c->read_length += len;
				}

				/* 版本协商和认证方法  */
				if(c->state == 0)
				{
					if(c->read_length < 2)
					{
						continue;
					}
					else
					{
						char ver = c->read_buf[0];
						char nmethods = c->read_buf[1];
						if(ver != 0x05)
						{
							printf("only support socks5. recv ver:[%d]\n", ver);
							client_to_remove.push_back(client_fd);
							continue;
						}
						else if(nmethods > 255)
						{
							printf("nmethods invalid.%d\n", nmethods);
							client_to_remove.push_back(client_fd);
							continue;
						}
						c->read_base = 2;
						c->state = 1;
					}
				}
				/* 接收认证方法 */
				if(c->state == 1)
				{
					int nmethods = c->read_buf[1];

					if(c->read_length < 2 + nmethods)
					{
						continue;
					}
					else
					{
						//ZeroMemory(c->read_buf, c->read_length);
						c->read_base = c->read_length = 0;
						
						/* 告诉客户端使用socks5协议，不需要认证 */
						c->write_buf[0] = 0x05;
						c->write_buf[1] = 0x00;
						c->write_base = 0;
						c->write_length = 2;
					}
				}
				/*接收请求*/
				else if(c->state == 2)
				{
					if(c->read_length < 4)
					{
						continue;
					}

					char cmd = c->read_buf[1];
					char dst_type = c->read_buf[3];

					if(cmd != 0x01)
					{
						printf("only accept connect cmd. recv cmd:[%d]\n", cmd);
						char response[4] = {0x05, 0x07, 0x00, 0x01};
						
						memcpy(c->write_buf+c->write_length, response, 4);

						c->write_base = 0;
						c->write_length = 4;

						client_to_remove.push_back(client_fd);
						continue;
					}

					/* ip v4 */
					if(dst_type == 0x01)
					{
						if(c->read_length < 4 + 4 +2)
						{
							continue;
						}
					}
					/* domain name */
					else if (dst_type == 0x03)
					{
						if(c->read_length < 5)
						{
							continue;
						}
						char domain_len = c->read_buf[4];
						if(c->read_length < 4 + domain_len + 2)
						{
							continue;
						}
					}
					/* dst addr type不正确 */
					else
					{
						printf("dst addr type invalid. value:%d\n", dst_type);
						char response[4] = {0x05, 0x08, 0x00, 0x01};
						
						memcpy(c->write_buf+c->write_length, response, 4);
						c->write_length += 4;

						client_to_remove.push_back(client_fd);
						continue;
					}

					c->remote = (remote_ctx*)malloc(sizeof(remote_ctx));
					ZeroMemory(c->remote, sizeof(remote_ctx));
					c->remote->client = c;

					c->remote->remote_fd = socket(result2->ai_family, result2->ai_socktype, result2->ai_protocol);
					set_nonblock(c->remote->remote_fd);
					
					int ret = connect(c->remote->remote_fd, result2->ai_addr, result2->ai_addrlen);
					if(ret == 0)
					{
						c->remote->connected = 1;
					}

					remotes.insert(std::pair<SOCKET, remote_ctx*>(c->remote->remote_fd, c->remote));
					continue;
				}
				/* redirect data from client to remote */
				else if(c->state == 3)
				{
					if(c->remote == NULL)
					{
						printf("client -> remote, but remote is NULL.\n");
						continue;
					}

					/* 判断一下remote的write_buf还能不能写得下 */
					int remote_left = BUFFER_SIZE - c->remote->write_length; 
					if(remote_left == 0)
					{
						printf("remote write buf has no space left.\n");
						continue;
					}

					int min = remote_left < c->read_length-c->read_base ? remote_left : c->read_length-c->read_base;

					xorencode(c->read_buf+c->read_base, min);

					memcpy(c->remote->write_buf+c->remote->write_length, c->read_buf+c->read_base, min);
					
					c->remote->write_length += min;
					c->read_base += min;

					int size = c->read_length - c->read_base;
					if(size == 0)
					{
						c->read_length = c->read_base = 0;
					}
					else
					{
						if(c->read_base > 0)
						{
							int i=0;
							for( ; i<size; i++)
							{
								c->read_buf[i] = c->read_buf[c->read_base + i];
							}
							c->read_base = 0;
							c->read_length = size;
						}
					}
				}
			}
		}/* end of  recv data from client  */

		/* send data to client */
		it = clients.begin();
		for(; it != clients.end(); it++)
		{
			SOCKET client_fd = it->first;
			client_ctx *c = it->second;

			if(FD_ISSET(client_fd, &writefds))
			{
				int len = send(client_fd, c->write_buf+c->write_base, (c->write_length - c->write_base), 0);
				if(len <= 0)
				{
					printf("send data to client failed.%d\n", len);
					client_to_remove.push_back(client_fd);
				}
				else
				{
					c->write_base += len;

					if(c->state == 1 && c->write_base == c->write_length)
					{
						/* 接收请求 */
						c->state = 2;
					}
					else if(c->state == 2 && c->write_base == c->write_length)
					{
						/* 转发数据 */
						c->read_base = c->read_length = 0;
						
						c->state = 3;
					}

					if(c->write_base == c->write_length)
					{
						c->write_base = c->write_length = 0;
					}
					else
					{
						int size = c->write_length - c->write_base;
						if(c->write_base > 0)
						{
							int i=0;
							for( ; i<size; i++)
							{
								c->write_buf[i] = c->write_buf[c->write_base + i];
							}
							c->write_base = 0;
							c->write_length = size;
						}
					}
				}
			}
		}

		it2 = remotes.begin();
		for(; it2 != remotes.end(); it2++)
		{
			SOCKET remote_fd = it2->first;
			remote_ctx *r = it2->second;

			if(FD_ISSET(remote_fd, &readfds))
			{
				if(r->client == NULL)
				{
					printf("remote -> client, but client is NULL.\n");
					continue;
				}

				char *buf = (r->client->write_buf + r->client->write_length);

				int len = recv(remote_fd, buf, (BUFFER_SIZE - r->client->write_length), 0);

				if(len <= 0)
				{
					//printf("recv data from remote:%d\n", len);
					remote_to_remove.push_back(remote_fd);
				}
				else
				{
					//printf("recv %d bytes data from remote.\n", len);
					xorencode( buf, len );
					r->client->write_length += len;
				}
			}
		}

		it2 = remotes.begin();
		for(; it2 != remotes.end(); it2++)
		{
			SOCKET remote_fd = it2->first;
			remote_ctx *r = it2->second;

			if(FD_ISSET(remote_fd, &writefds))
			{
				/* 连接服务器 */
				if(r->connected == 0)
				{
					char optval;
					int optlen = sizeof(optval);

					getsockopt( remote_fd, SOL_SOCKET, SO_ERROR, &optval, &optlen);
					//printf("optval:%d\n", optval);

					if(optval == 0)
					{
						/* 响应 */
						char response[10] = {0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

						memcpy(r->client->write_buf + r->client->write_length, response, 10);
						r->client->write_length += 10;

						/* 告诉服务器账号和dst信息 */
						char username[10] = {0};
						memcpy(username, "gaoshijie", 9);
						char password[9] = {0};
						memcpy(password, "password", 8);

						char ulen = strlen(username);
						char plen = strlen(password);

						memcpy( (r->write_buf + r->write_length), xorencode(&ulen, 1), 1);
						r->write_length += 1;

						xorencode(&ulen, 1);
						memcpy( (r->write_buf + r->write_length), xorencode(username, ulen), ulen);
						r->write_length += ulen;

						memcpy(r->write_buf+r->write_length, xorencode(&plen, 1), 1);
						r->write_length += 1;
						
						xorencode(&plen, 1);
						memcpy(r->write_buf+r->write_length, xorencode(password, plen), plen);
						r->write_length += plen;

						/* dst信息 */
						char *dst = (r->client->read_buf + r->client->read_base + 3);
						int dstlen = (r->client->read_length - r->client->read_base - 3);
						xorencode( dst, dstlen);
						memcpy( (r->write_buf + r->write_length), dst, dstlen );
						r->write_length += dstlen;

						r->client->read_base = r->client->read_length = 0;

						r->connected = 1;
					}
					else
					{
						printf("conncet to server failed.\n");

						char response[4] = {0x05, 0x01, 0x00, 0x01};
						memcpy(r->client->write_buf+r->client->write_length, response, 4);
						r->client->write_length += 4;
						
						remote_to_remove.push_back(remote_fd);
					}	
				}
				/* send data to remote */
				else
				{
					int len = send(remote_fd, r->write_buf + r->write_base, (r->write_length - r->write_base), 0);
					if(len <= 0)
					{
						printf("send data to remote failed.\n");
						remote_to_remove.push_back(remote_fd);
					}
					else
					{
						r->write_base += len;
						
						if(r->write_base == r->write_length)
						{
							r->write_base = r->write_length = 0;
						}
						else
						{
							int size = r->write_length - r->write_base;
							if(r->write_base > 0)
							{
								int i=0;
								for( ; i<size; i++)
								{
									r->write_buf[i] = r->write_buf[r->write_base + i];
								}
								r->write_base = 0;
								r->write_length = size;
							}
						}
					}
				}
			}
		}

		//std::list<SOCKET>::iterator temp = client_to_remove.begin();
		//for(; temp != client_to_remove.end(); temp++)
		//{
		//	SOCKET client_fd = *temp;

		//	std::map<SOCKET, client_ctx*>::iterator i = clients.find(client_fd);
		//	
		//	if(i != clients.end())
		//	{
		//		client_ctx *c = i->second;
		//		remote_ctx *r = i->second->remote;

		//		clients.erase(i);
		//	}
		//}

		//temp = remote_to_remove.begin();
		//for(; temp != remote_to_remove.end(); temp++)
		//{
		//	/* 关闭连接之前看看有没有要发送的数据了。 todo */
		//	SOCKET remote_fd = *temp;

		//	std::map<SOCKET, remote_ctx*>::iterator i = remotes.find(remote_fd);
		//	
		//	if(i != remotes.end())
		//	{
		//		client_ctx *c = i->second->client;
		//		remote_ctx *r = i->second;

		//		remotes.erase(i);
		//	}
		//}

		/* remove SOCKET */
		std::list<SOCKET>::iterator remove_it = client_to_remove.begin();
		for(; remove_it != client_to_remove.end(); remove_it++)
		{
			/* 关闭连接之前看看有没有要发送的数据了。 todo */
			SOCKET client_fd = *remove_it;

			std::map<SOCKET, client_ctx*>::iterator i = clients.find(client_fd);
			
			if(i != clients.end())
			{
				client_ctx *c = i->second;
				remote_ctx *r = i->second->remote;

				shutdown(client_fd, SD_BOTH);
				closesocket(client_fd);

				free(c);
				c = NULL;

				clients.erase(client_fd);

				if(r != NULL)
				{
					r->client = NULL;

					if(r->write_length - r->write_base > 0)
					{
						printf("close remote. but remote has data to send.\n");
						continue;
					}

					SOCKET remote_fd = r->remote_fd;
					shutdown(remote_fd, SD_BOTH);
					closesocket(remote_fd);

					std::map<SOCKET, remote_ctx*>::iterator j = remotes.find(remote_fd);
					if(j != remotes.end())
					{
						remotes.erase(j);
					}

					remote_to_remove.remove(remote_fd);
					
					free(r);
					r = NULL;
				}
			}
		}

		remove_it = remote_to_remove.begin();
		for(; remove_it != remote_to_remove.end(); remove_it++)
		{
			/* 关闭连接之前看看有没有要发送的数据了。 todo */
			SOCKET remote_fd = *remove_it;

			std::map<SOCKET, remote_ctx*>::iterator i = remotes.find(remote_fd);

			if( i != remotes.end() )
			{
				remote_ctx *r = i->second;
				client_ctx *c = i->second->client;

				shutdown(remote_fd, SD_BOTH);
				closesocket(remote_fd);

				free(r);
				r = NULL;

				remotes.erase(remote_fd);

				if(c != NULL)
				{
					c->remote = NULL;

					if(c->write_length - c->write_base > 0)
					{
						printf("close remote. but client has data to send.\n");
						continue;
					}

					SOCKET client_fd = c->client_fd;
					shutdown(client_fd, SD_BOTH);
					closesocket(client_fd);

					std::map<SOCKET, client_ctx*>::iterator j = clients.find(client_fd);
					if(j != clients.end())
					{
						clients.erase(j);
					}

					client_to_remove.remove(client_fd);

					free(c);
					c = NULL;
				}
			}
		}

	} /* end of for loop */
	
	freeaddrinfo(result2);
	return 0;
}