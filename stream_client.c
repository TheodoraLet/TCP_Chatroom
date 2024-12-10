#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <fcntl.h>

#include <arpa/inet.h>

#define PORT "3490" // the port client will be connecting to 

#define MAXDATASIZE 100 // max number of bytes we can get at once 

int max_phrase_size=100;

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}


int main(int argc, char *argv[])
{
    int sockfd, numbytes, r_numbytes;
    //char* buf=(char*)malloc(sizeof(char)*MAXDATASIZE);
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];
    char buf[MAXDATASIZE];
    char rbuf[MAXDATASIZE];
    struct pollfd fds[2];

    if (argc != 2) {
        fprintf(stderr,"usage: client hostname\n");
        exit(1);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(argv[1], PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("client: socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("client: connect");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "client: failed to connect\n");
        return 2;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
            s, sizeof s);
    printf("client: connecting to %s\n", s);

    freeaddrinfo(servinfo); // all done with this structure

    fds[0].fd=STDIN_FILENO;
    fds[0].events=POLLIN;

    fds[1].fd=sockfd;
    fds[1].events= POLLIN;
    

    while(1)
    {
        int rc=poll(fds,2,-10);
        if(rc<0)
        {
         perror("poll failed");
         break;
        }

        if(fds[1].revents & POLLIN)
        {
            r_numbytes=recv(sockfd,rbuf,MAXDATASIZE-1,0);
            if(r_numbytes>=0)
            printf("%s\n",rbuf);
            memset(rbuf,'\0',sizeof(char)*(MAXDATASIZE));
        
        }else if(fds[0].revents & POLLIN)
        {
            fgets(buf,MAXDATASIZE,stdin);
            //printf("fgets got %s\n",buf);
            if(numbytes=send(sockfd,buf,strlen(buf),0)==-1)
            {
                perror("send");
                exit(1);
            }
            memset(buf,'\0',sizeof(char)*(MAXDATASIZE));
        }
       
    }

    close(sockfd);

    return 0;
}