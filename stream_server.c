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
#include <stdbool.h>

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

typedef struct sock_info{
    struct pollfd* fds;
    struct addrinfo* con_info;
    bool* verified;
    char** login_cred;
    bool* pending;
    bool * registered;

}sock_info;

typedef struct passwords
{
    char* pass;
    bool used;
}passwords;

char* add_name(char* buf,char* login);
void login_user(int index,sock_info* sock,char* buf,passwords* pasw);
int password_storage(passwords* pasw);
void send_to_all(int index,char* buf,sock_info* sock,int nfds,passwords* pasw);
int check_registered(char* buf,sock_info* sock,passwords* pasw);
void register_user(int i,char* buf,sock_info* sock,passwords* pasw);

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
    char* buf=(char*)malloc(sizeof(char)*MAXDATASIZE);
    sock_info* sock=(sock_info*)malloc(sizeof(sock_info));
    sock->fds=(struct pollfd*)malloc(sizeof(struct pollfd)*200);
    int new_fd=-1;
    sock->con_info=(struct addrinfo*)malloc(sizeof(struct addrinfo)*200);
    sock->verified=(bool*)malloc(sizeof(bool)*200);
    sock->login_cred=(char**)malloc(sizeof(char*)*200);
    sock->pending=(bool*)malloc(sizeof(bool)*200);
    sock->registered=(bool*)malloc(sizeof(bool)*200);
    memset(sock->verified,false,sizeof(sock->verified));
    memset(sock->pending,false,sizeof(sock->pending));
    memset(sock->registered,false,sizeof(sock->registered));
    passwords* pasw=(passwords*)malloc(sizeof(passwords)*200);
    password_storage(pasw);
    for(int i=0;i<200;i++)
    {
        if(pasw[i].pass==NULL)
        continue;

        printf("%s\n",pasw[i].pass);
    }
   

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


    memset(sock->fds,0,sizeof(sock->fds));
    sock->fds[0].fd=listen_fd;
    sock->fds[0].events=POLLIN;
    int timeout=-10;
    int nfds=1;
    
    /////////////////////////////////////////
    printf("server waiting for connections\n");

    while(1)
    {
        int rc=poll(sock->fds,nfds,timeout);

        if(rc<0) {perror("poll failed"); break;}
        
        int currentsize=nfds;

        for(int i=0;i<currentsize;i++)
        {
            //printf("current size is %d\n",currentsize);
            if(sock->fds[i].revents==0)
            {
                continue;
            
            }else if(sock->fds[i].revents!=POLLIN)
            {
                printf("Error revents= %d \n",sock->fds[i].revents);
                break;

            }else if(sock->fds[i].fd==listen_fd)
            {
                //printf("got inside listen\n");
                
                do{
                    socklen_t sin_size=sizeof(struct sockaddr_storage);
                    sock->con_info[nfds].ai_addr=(struct sockaddr*)malloc(sizeof(struct sockaddr));
                    sock->con_info[nfds].ai_family=AF_INET;
                    sock->con_info[nfds].ai_socktype=SOCK_STREAM;
                    new_fd=accept(listen_fd,(struct sockaddr*)sock->con_info[nfds].ai_addr,&sin_size);

                    if(new_fd==-1)
                    {
                        if(errno!=EWOULDBLOCK)
                        {
                            perror("accept failed");
                        }

                        printf("got out of accept\n");
                        break;
                    }

                    char* login_buf;
                    login_buf="type login or register and then give user,password";
                    numbytes=send(new_fd,login_buf,strlen(login_buf)+1,0);
                    if(numbytes!=0)
                    printf("Sent access verification\n");

                    if(!(inet_ntop(sock->con_info[nfds].ai_family,get_in_addr(sock->con_info[nfds].ai_addr),s, sizeof s)))
                    printf("Error: %s \n",strerror(errno));
                    printf("IP added : %s \n",s);
                    sock->fds[nfds].fd=new_fd;
                    sock->fds[nfds].events=POLLIN;
                    fcntl(sock->fds[nfds].fd,F_SETFL,O_NONBLOCK);
                    nfds++;

                }while(new_fd!=-1);

            }else{
                numbytes=recv(sock->fds[i].fd,buf,MAXDATASIZE,0);
                buf[numbytes]='\0';
                printf("received %s\n",buf);

                if(numbytes<0)
                {
                    perror("recv error");
                    break;
                }else if(numbytes==0)
                {
                    printf("client closed connection\n");
                    close(sock->fds[i].fd);
                    sock->fds[i].fd=-1;
                    break;
                }else{

                    if(sock->pending[i]==true)
                        {
                            printf("got inside pending\n");
                            printf("with buf is %s\n",buf);
                            login_user(i,sock,buf,pasw);
                            sock->pending[i]=false;
                            printf("called login\n");
                        }else if(sock->registered[i]==true)
                        {
                            register_user(i,buf,sock,pasw);
                        }else if(sock->verified[i]==false)
                        {
                            printf("got inside verified\n");
                            if( memcmp(buf,"login",strlen("login"))==0)
                            {
                                sock->pending[i]=true;
                            }
                            else if(memcmp(buf,"register",strlen("register"))==0)
                            {
                                printf("register\n");
                                sock->registered[i]=true;
                            }

                        }else{
                        send_to_all(i,buf,sock,nfds,pasw);
                    }
                }
            }
        }

    }

    return 0;
}

char* add_name(char* buf,char* login)
{
    char* temp=(char*)malloc(sizeof(char)*(strlen(login)+strlen(buf)+1));
    strcpy(temp,login);
    temp=strtok(temp,",");
    strcat(temp,":");
    strcat(temp,buf);
    strcpy(buf,temp);
    free(temp);

    return buf;
}

void login_user(int index,sock_info* sock,char* buf,passwords* pasw)
{
    int numbytes;
    for(int k=0;k<200;k++)
    {
        if(pasw[k].pass==NULL)
        continue;

        if(memcmp(buf,pasw[k].pass,strlen(pasw[k].pass))==0 && pasw[k].used==false)
        {
            printf("found the right password\n");
            sock->verified[index]=true;
            if((numbytes=send(sock->fds[index].fd,"Access Provided",15,0))<=0)
            printf("error :%s\n",strerror(errno));

            pasw[k].used=true;
            sock->login_cred[index]=(char*)malloc(sizeof(char)*(strlen(pasw[k].pass)+1));
            strcpy(sock->login_cred[index],pasw[k].pass);
            printf("made it till here\n");
            break;
        }else if(memcmp(buf,pasw[k].pass,strlen(pasw[k].pass))==0 && pasw[k].used==true)
        {
            numbytes=send(sock->fds[index].fd,"Password already used",21,0);
            break;
        }
    }
    if(sock->verified[index]==false)
    {
       if((numbytes=send(sock->fds[index].fd,"Wrong Password",14,0))<=0)
       printf("error: %s\n",strerror(errno));
       //sock->fds[index].fd=-1;
       //close(sock->fds[i].fd);
    }
    
}

int password_storage(passwords* pasw)
{
    pasw[0].pass=(char*)malloc(sizeof(char)*(strlen("user1,123")+1));
    strcpy(pasw[0].pass,"user1,123");
    pasw[0].used=false;
    pasw[1].pass=(char*)malloc(sizeof(char)*(strlen("user2,345")+1));
    strcpy(pasw[1].pass,"user2,345");
    pasw[1].used=false;
    pasw[2].pass=(char*)malloc(sizeof(char)*(strlen("user3,123")+1));
    strcpy(pasw[2].pass,"user3,123");
    pasw[2].used=false;

    return 3;
}

void send_to_all(int index,char* buf,sock_info* sock,int nfds,passwords* pasw)
{
    strcpy(buf,add_name(buf,sock->login_cred[index]));
    for(int j=1;j<nfds;j++)
    {
    if(index==j) continue;

    if(sock->verified[j])
    {
        // strcpy(buf,add_name(buf,sock->login_cred[i]));
        int rc=send(sock->fds[j].fd,buf,strlen(buf)+1,0);
        if(rc<0)
        {
           perror("recv");
           printf("error: %d\n",errno);
        }else if(rc==0)
        {
           printf("client has closed\n");
           for(int k=0;k<200;k++)
           {
            if(strcmp(sock->login_cred[j],pasw[k].pass)==0)
            {
                pasw[k].used=false;
                break;
            }
           }
        }
    }
    }
    memset(buf,'\0',sizeof(char)*(MAXDATASIZE));
}


int check_registered(char* buf,sock_info* sock,passwords* pasw)
{
    char* temp=(char*)malloc(sizeof(char)*strlen(buf)+1);
    strcpy(temp,buf);
    char* token=strtok(temp,",");
    int k=0;
    while(token!=NULL)
    {
        k++;
        token=strtok(NULL,",");
    }

    if(k!=2)
    {
        free(temp);
        return -1;
    }

    printf("temp is %s\n",temp);
    int numbytes=0;
    for(int i=0;i<200;i++)
    {
        if(pasw[i].pass==NULL)
        continue;

        if(memcmp(temp,pasw[i].pass,strlen(temp))==0)
        {
            return -2;
        }
    }

    return 0;
}

void register_user(int i,char* buf,sock_info* sock,passwords* pasw)
{
    int numbytes=0;
    if(check_registered(buf,sock,pasw)==0)
    {
        printf("got inside the check 0\n");
        sock->login_cred[i]=(char*)malloc(sizeof(char)*(strlen(buf)+1));
        strcpy(sock->login_cred[i],buf);
        sock->registered[i]=false;
        sock->verified[i]=true;
        int index=password_storage(pasw);
        pasw[index].pass=(char*)malloc(sizeof(char)*(strlen(buf)+1));
        strcpy(pasw[index].pass,buf);
        pasw[index].used=true;
        if((numbytes=send(sock->fds[i].fd,"Access Provided",15,0))<=0)
        printf("error :%s\n",strerror(errno));
    }else if(check_registered(buf,sock,pasw)==-1){
        if((numbytes=send(sock->fds[i].fd,"Type the format user,password",29,0))<=0)
        printf("error: %s\n",strerror(errno));
    }else if(check_registered(buf,sock,pasw)==-2){
        if((numbytes=send(sock->fds[i].fd,"username is already used",24,0))<=0)
        printf("error: %s\n",strerror(errno));
    }
}