/*********************************************************************
    PA-03:  Sockets

    FILE:   myNetLib.h

    Modified by ABOUTABL from original UNP's code 

    Updated on:   March 2025
**********************************************************************/

#include    <stdio.h>
#include	<sys/types.h>	/* basic system data types */
#include	<sys/socket.h>	/* basic socket definitions */
#include	<netinet/in.h>	/* sockaddr_in{} and other Internet defns */
#include	<arpa/inet.h>	/* inet(3) functions */
#include	<errno.h>
#include	<stdlib.h>
#include    <unistd.h>
#include    <fcntl.h>
#include	<sys/stat.h>	/* for S_xxx file mode constants */
#include    <string.h>      /* for memxxx() functions */
#include    <signal.h>
#include    <sys/wait.h>

typedef struct sockaddr SA ;  /* Short cut*/

//------------------------------------------------------------

pid_t   Fork(void);

typedef void Sigfunc( int ) ;
Sigfunc * sigactionWrapper( int signo, Sigfunc *func ) ;

void    err_sys( const char* x) ;
void    err_quit( const char* x) ;
int     Listen(int sockfd, int backlog) ;
int     Accept( int fd, struct sockaddr *sa, socklen_t *salenptr) ;
void    Close( int fd) ;
ssize_t Read( int fd, void *buff, size_t n ) ;
ssize_t readn( int fd, void *vptr, size_t n) ;
ssize_t Readn( int fd, void *vptr, size_t n) ;
ssize_t writen( int fd, const void *vptr, size_t n) ;
int     socketTCP( uint16_t s_port , const char *remoteIP, uint16_t d_port ) ;
