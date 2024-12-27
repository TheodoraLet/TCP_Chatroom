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
void login_user(int index,sock_info* sock,char* buf,passwords* pasw,int nfds);
void password_storage(passwords* pasw);
void send_to_all(int index,char* buf,sock_info* sock,int nfds,passwords* pasw);
int check_registered(char* buf,sock_info* sock,passwords* pasw);
void register_user(int i,char* buf,sock_info* sock,passwords* pasw,int nfds);
void compress_array(sock_info* sock,int* nfds);
void active_users(sock_info* sock, int nfds,int index);
void new_user_enter(int i, sock_info* sock,int nfds);
void user_left(int i,sock_info* sock,int nfds);

int max_users;
int users=0;
bool compress_aray=false;
int login_users=3;

int main(void)
{
    printf("enter the number of people the chat can have\n");
    char b_user[20];

    fgets(b_user,20,stdin);

    max_users=atoi(b_user);
    printf("max_users are %d\n",max_users);
    if(max_users<login_users)
    {
        printf("login users >max users, Change settings\n");
        exit(1);

    }

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
    sock->fds=(struct pollfd*)malloc(sizeof(struct pollfd)*(max_users+BACKLOG+1));
    int new_fd=-1;
    sock->con_info=(struct addrinfo*)malloc(sizeof(struct addrinfo)*(max_users+BACKLOG+1));
    sock->verified=(bool*)malloc(sizeof(bool)*(max_users+BACKLOG+1));
    sock->login_cred=(char**)malloc(sizeof(char*)*(max_users+BACKLOG+1));
    sock->pending=(bool*)malloc(sizeof(bool)*(max_users+BACKLOG+1));
    sock->registered=(bool*)malloc(sizeof(bool)*(max_users+BACKLOG+1));
    memset(sock->verified,false,sizeof(sock->verified));
    memset(sock->pending,false,sizeof(sock->pending));
    memset(sock->registered,false,sizeof(sock->registered));
    passwords* pasw=(passwords*)malloc(sizeof(passwords)*(login_users));
    password_storage(pasw);
    if(users!=login_users-1)
    {
        printf("login users number different from storage, check password_storage function\n");
        exit(1);
    }

    for(int i=0;i<max_users+BACKLOG+1;i++)
    {
        sock->con_info[i].ai_addr=NULL;
        sock->login_cred[i]=NULL;
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
                    socklen_t sin_size=sizeof(struct sockaddr); //sizeof(struct sockaddr_storage);
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

                        free(sock->con_info[nfds].ai_addr);
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
                    compress_aray=true;
                    //sock->verified[i]=false;
                    //sock->pending[i]=false;
                    printf("sock pending is false\n");
                    if(sock->login_cred[i]==NULL)
                    {
                        users--;
                        break;
                    }else{
                    bool flag=false;
                    for(int k=0;k<login_users;k++)
                    {
                        if(strcmp(sock->login_cred[i],pasw[k].pass)==0)
                        {
                            flag=true;
                            pasw[k].used=false;
                            printf("a login user closed\n");
                            break;
                        }
                    }

                    if(!flag)
                    {
                        users--;
                    }

                    //break;
                    }
                    
                }else{
                    if(sock->pending[i]==true)
                       {
                           printf("got inside pending\n");
                           printf("with buf is %s\n",buf);
                           login_user(i,sock,buf,pasw,nfds);
                           sock->pending[i]=false;
                           printf("called login\n");
                           printf("users are %d\n",users);
                       }else if(sock->registered[i]==true)
                       {
                           register_user(i,buf,sock,pasw,nfds);
                           printf("users are %d\n",users);
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
                           }else{
                            sock->fds[i].fd=-1;
                            compress_aray=true;
                            printf("neither login nor register\n");
                           }
                       }else{
                        printf("Inside the send all if\n");
                        printf("sock->verified is %d\n",sock->verified[i]);
                       send_to_all(i,buf,sock,nfds,pasw);
                    }
                }
            }
        }

        compress_array(sock,&nfds);

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

void login_user(int index,sock_info* sock,char* buf,passwords* pasw,int nfds)
{
    int numbytes;
    for(int k=0;k<login_users;k++)
    {
        if(pasw[k].pass==NULL)
        continue;

        if(memcmp(buf,pasw[k].pass,strlen(pasw[k].pass))==0 && pasw[k].used==false)
        {
            printf("found the right password\n");
            sock->verified[index]=true;
            if((numbytes=send(sock->fds[index].fd,"Access Provided",15,0))<=0)
            printf("error :%s\n",strerror(errno));

            int rc;
            if((rc=send(sock->fds[index].fd," ",1,0))!=1)
            printf("error :%s\n",strerror(errno));


            pasw[k].used=true;
            sock->login_cred[index]=(char*)malloc(sizeof(char)*(strlen(pasw[k].pass))+1);
            memcpy(sock->login_cred[index],pasw[k].pass,strlen(pasw[k].pass)+1);
            printf("made it till here\n");
            printf("sizeof paws[k].pass is %ld\n",strlen(pasw[k].pass));
            active_users(sock,nfds,index);
            new_user_enter(index,sock,nfds);
            break;
        }else if(memcmp(buf,pasw[k].pass,strlen(pasw[k].pass))==0 && pasw[k].used==true)
        {
            numbytes=send(sock->fds[index].fd,"Password already used",21,0);
            break;
        }
    }
    if(sock->verified[index]==false)
    {
        printf("buf is %s\n",buf);
       if((numbytes=send(sock->fds[index].fd,"Wrong Password",14,0))<=0)
       printf("error: %s\n",strerror(errno));
       sock->fds[index].fd=-1;
       compress_aray=true;
       sock->pending[index]=false;
       //close(sock->fds[i].fd);
    }
    
}

void password_storage(passwords* pasw)
{
    pasw[users].pass=(char*)malloc(sizeof(char)*(strlen("user1,123")+1));
    memcpy(pasw[users].pass,"user1,123",strlen("user1,123")+1);
    pasw[(users)++].used=false;
    pasw[users].pass=(char*)malloc(sizeof(char)*(strlen("user2,345")+1));
    memcpy(pasw[users].pass,"user2,345",strlen("user2,345")+1);
    pasw[(users)++].used=false;
    pasw[users].pass=(char*)malloc(sizeof(char)*(strlen("user3,123")+1));
    memcpy(pasw[users].pass,"user3,123",strlen("user3,123")+1);
    pasw[(users)].used=false;
}

void send_to_all(int index,char* buf,sock_info* sock,int nfds,passwords* pasw)
{
    char* res=add_name(buf,sock->login_cred[index]);
    memcpy(buf,res,strlen(res));
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
           sock->fds[index].fd=-1;
           compress_aray=true;
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

    for(int i=0;i<login_users;i++)
    {
        printf("inside first if of check\n");
        if(pasw[i].pass==NULL)
        continue;

        if(memcmp(temp,pasw[i].pass,strlen(temp))==0)
        {
            free(temp);
            return -2;
        }
    }

    if(users>=login_users)
    {
        printf("inside 2nd if of check register\n");
        for(int i=login_users;i<=users+1;i++)
        {
            if(sock->login_cred[i]==NULL)
            continue;

            //printf("sock login is %s\n",sock->login_cred[i]);
            if((memcmp(temp,sock->login_cred[i],strlen(temp))==0))
            {
                printf("found the same registered user\n");
                free(temp);
                return -2;
            }
        }
    }
    //printf("first sock login is %s\n",sock->login_cred[1]);
    free(temp);

    return 0;
}

void register_user(int i,char* buf,sock_info* sock,passwords* pasw,int nfds)
{
    int numbytes=0;
    static bool first_user=true;
    if(users+1>=(max_users) && users!=0)
    {
        printf("first if of register\n");
        if((numbytes=send(sock->fds[i].fd,"Max number of chat users",24,0))<=0)
        printf("error: %s\n",strerror(errno));
        //close(sock->fds[i].fd);
        sock->fds[i].fd=-1;
        compress_aray=true;
        return;
    }

    if(check_registered(buf,sock,pasw)==0)
    {
        printf("got inside the check 0\n");
        sock->login_cred[i]=(char*)malloc(sizeof(char)*(strlen(buf)+1));
        strcpy(sock->login_cred[i],buf);
        sock->registered[i]=false;
        sock->verified[i]=true;

        if(users!=0 || max_users==1 || !first_user) 
        users++;

        if(login_users==0 && users==0)
        first_user=false;

        if((numbytes=send(sock->fds[i].fd,"Access Provided",15,0))<=0)
        printf("error :%s\n",strerror(errno));

        int rc;
        if((rc=send(sock->fds[i].fd," ",1,0))!=1)
        printf("error :%s\n",strerror(errno));

        active_users(sock,nfds,i);
        new_user_enter(i,sock,nfds);

    }else if(check_registered(buf,sock,pasw)==-1){
        if((numbytes=send(sock->fds[i].fd,"Type the format user,password",29,0))<=0)
        printf("error: %s\n",strerror(errno));
        sock->fds[i].fd=-1;
        compress_aray=true;
    }else if(check_registered(buf,sock,pasw)==-2){
        if((numbytes=send(sock->fds[i].fd,"username is already used",24,0))<=0)
        printf("error: %s\n",strerror(errno));
        sock->fds[i].fd=-1;
        compress_aray=true;
    }
}

void compress_array(sock_info* sock,int* nfds)
{
    if(compress_aray)
    {
        printf("got inside compress array\n");
        compress_aray=false;
        int initial_nfds=*nfds;
        for(int i=0;i<*nfds;i++)
        {
            int last_index=0;
            if(sock->fds[i].fd==-1)
            {
                user_left(i,sock,*nfds);

                    free(sock->con_info[i].ai_addr);
                    free(sock->login_cred[i]);
                    sock->pending[i]=false;
                    sock->verified[i]=false;
                    sock->registered[i]=false;
                    printf("inside compress array first if\n");

                for(int j=i;j<=*nfds-1;j++)
                {
                    sock->con_info[j]=sock->con_info[j+1];
                    sock->fds[j].fd=sock->fds[j+1].fd;
                    sock->verified[j]=sock->verified[j+1];
                    sock->login_cred[j]=sock->login_cred[j+1];
                    sock->pending[j]=sock->pending[j+1];
                    sock->registered[j]=sock->registered[j+1];
                    last_index=j+1;
                }
                
                if(last_index!=0)
                {
                    sock->con_info[last_index].ai_addr=NULL;
                    sock->login_cred[last_index]=NULL;
                    sock->pending[last_index]=false;
                    sock->verified[last_index]=false;
                    sock->registered[last_index]=false;
                }
                i--;
                (*nfds)--;
            }
        }
        
        printf("nfds is %d\n",*nfds);
    }
}

void active_users(sock_info* sock, int nfds,int index)
{
    char** status=(char**)malloc(sizeof(char*)*max_users);
    int k=0;
    for(int j=1;j<nfds;j++)
    {
        char* temp=(char*)malloc(sizeof(char)*(strlen(sock->login_cred[j])));
        memcpy(temp,sock->login_cred[j],strlen(sock->login_cred[j]));
        temp=strtok(temp,",");
        status[k]=(char*)malloc(sizeof(char)*(strlen(temp)+1));
        memcpy(status[k++],temp,strlen(temp));
        free(temp);
    }

   
    int rc=send(sock->fds[index].fd,"active users are:",17,0);
    if(rc<0)
    {
       perror("recv");
       printf("error: %d\n",errno);
    }else if(rc==0)
    {
       printf("client has closed\n");
       sock->fds[index].fd=-1;
       compress_aray=true;
    }   int i=0;
    while(i<k)
    {
        rc=send(sock->fds[index].fd,status[i++],strlen(status[i]),0);
        rc=send(sock->fds[index].fd," ",1,0);
        if(rc<0)
        {
           perror("recv");
           printf("error: %d\n",errno);
        }else if(rc==0)
        {
           printf("client has closed\n");
           sock->fds[index].fd=-1;
           compress_aray=true;
        }
    }

    for(int w=0;w<k;w++)
    free(status[w]);

    free(status);

}

void new_user_enter(int i, sock_info* sock,int nfds)
{
    char* t=" has entered the chat";
    char* temp=(char*)malloc(sizeof(char)*(strlen(sock->login_cred[i])+strlen(t)+1));
    strcpy(temp,sock->login_cred[i]);
    temp=strtok(temp,",");
    strcat(temp,t);

    for(int j=1;j<nfds;j++)
    {
        if(i==j)
        continue;

        int numbytes=send(sock->fds[j].fd,temp,strlen(temp)+1,0);
        if(numbytes<0)
        {
           perror("recv");
           printf("error: %d\n",errno);
        }else if(numbytes==0)
        {
           printf("client has closed\n");
           sock->fds[j].fd=-1;
           compress_aray=true;
        }
    }

    free(temp);

}

void user_left(int i,sock_info* sock,int nfds)
{
    if(sock->verified[i]==true)
    {
        char* t=" has left the chat";
        char* temp=(char*)malloc(sizeof(char)*(strlen(sock->login_cred[i])+strlen(t)+1));
        strcpy(temp,sock->login_cred[i]);
        temp=strtok(temp,",");
        strcat(temp,t);

        for(int j=1;j<nfds;j++)
        {
            if(i==j)
            {
                continue;
            }

            int numbytes=send(sock->fds[j].fd,temp,strlen(temp)+1,0);
            if(numbytes<0)
            {
                perror("recv");
               printf("error: %d\n",errno);
            }else if(numbytes==0)
            {
               printf("client has closed\n");
               sock->fds[j].fd=-1;
               compress_aray=true;
            }
        }

        free(temp);
    }

}