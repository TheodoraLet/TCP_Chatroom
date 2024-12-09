#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/poll.h>
#include <fcntl.h>

#define PORT "3490"  // the port users will be connecting to

#define BACKLOG 10   // how many pending connections queue will hold

#define MAXDATASIZE 100

#define max_chat_users 100


void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    while(waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}


int main(void)
{
    int listen_fd=-1; int numbytes;  // listen on sock_fd, new connection on new_fd
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; // connector's address information
    socklen_t sin_size;
    struct sigaction sa;
    int yes=1;
    char s[INET6_ADDRSTRLEN];
    int rv;
    char buf[MAXDATASIZE];
    //new_fd* stack=(new_fd*)malloc(sizeof(new_fd)*max_chat_users);
    //int head=0; int tail=0;
    struct pollfd fds[200];
    int new_fd=-1;
    struct addrinfo* con_info=(struct addrinfo*)malloc(sizeof(struct addrinfo)*200);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((listen_fd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes,
                sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(listen_fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(listen_fd);
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo); // all done with this structure

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(listen_fd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    fcntl(listen_fd,F_SETFL,O_NONBLOCK);

    // sa.sa_handler = sigchld_handler; // reap all dead processes
    // sigemptyset(&sa.sa_mask);
    // sa.sa_flags = SA_RESTART;
    // if (sigaction(SIGCHLD, &sa, NULL) == -1) {
    //     perror("sigaction");
    //     exit(1);
    // }


    memset(fds,0,sizeof(fds));
    fds[0].fd=listen_fd;
    fds[0].events=POLLIN;
    int timeout=-10;
    int nfds=1;
    int cfds=1;
    /////////////////////////////////////////
    printf("server waiting for connections\n");

    while(1)
    {
        int rc=poll(fds,nfds,timeout);

        if(rc<0) {perror("poll failed"); break;}
        
        int currentsize=nfds;

        for(int i=0;i<currentsize;i++)
        {
            //printf("current size is %d\n",currentsize);
            if(fds[i].revents==0)
            {
                continue;
            
            }else if(fds[i].revents!=POLLIN)
            {
                printf("Error revents= %d \n",fds[i].revents);
                break;

            }else if(fds[i].fd==listen_fd)
            {
                //printf("got inside listen\n");
                
                do{
                    socklen_t sin_size=sizeof(struct sockaddr_storage);
                    con_info[cfds].ai_addr=(struct sockaddr*)malloc(sizeof(struct sockaddr));
                    con_info[cfds].ai_family=AF_INET;
                    con_info[cfds].ai_socktype=SOCK_STREAM;
                    new_fd=accept(listen_fd,(struct sockaddr*)con_info[cfds].ai_addr,&sin_size);

                    if(new_fd==-1)
                    {
                        if(errno!=EWOULDBLOCK)
                        {
                            perror("accept failed");
                        }

                        printf("got out of accept\n");
                        break;
                    }

                    if(!(inet_ntop(con_info[cfds].ai_family,get_in_addr(con_info[cfds].ai_addr),s, sizeof s)))
                    printf("Error: %s \n",strerror(errno));

                    printf("IP added : %s \n",s);
                    cfds++;
                    fds[nfds].fd=new_fd;
                    fds[nfds].events=POLLIN;
                    fcntl(fds[nfds].fd,F_SETFL,O_NONBLOCK);
                    nfds++;

                }while(new_fd!=-1);

            }else{
                numbytes=recv(fds[i].fd,buf,MAXDATASIZE,0);
                buf[numbytes]='\0';
                printf("received %s\n",buf);

                if(numbytes<0)
                {
                    perror("recv error");
                    break;
                }else if(numbytes==0)
                {
                    printf("client closed connection\n");
                    close(fds[i].fd);
                    fds[i].fd=-1;
                    break;
                }else{
                    //printf("got inside send\n");
                    for(int j=1;j<nfds;j++)
                    {
                        if(i==j) continue;

                        rc=send(fds[j].fd,buf,numbytes,0);
                        if(rc<0)
                        {
                           perror("recv");
                           printf("error: %d\n",errno);
                        }else if(rc==0)
                        {
                           printf("client has closed\n");
                        }
                    }
                }
            }
            memset(buf,'\0',sizeof(char)*(MAXDATASIZE));
        }

    }

    return 0;
}