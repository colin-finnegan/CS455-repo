/* ------------------------------------------------------------------------
TCP Daytime Lab:   the Client
------------------------------------------------------------------------ */

#include "myNetLib.h"

#include <stdio.h>

#define MAXLINE 200

int main(int argc, char **argv)
{
    int     sockfd, localport , len , n ;
    char    recvline[ MAXLINE + 1 ]  ;
    struct  sockaddr_in  servaddr , clntaddr ;
    char    remoteIP[ INET_ADDRSTRLEN+1 ] = "127.0.0.1" , 
            localIP[ INET_ADDRSTRLEN+1 ] ;

    unsigned short srvPort = 13 ;

	switch (argc) 
	{
      case 1:
        break;

      case 3:
        srvPort = atoi( argv[2] ) ;
        // no break ... move through next case
        
      case 2:
        strncpy( remoteIP , argv[1] , INET_ADDRSTRLEN ) ;
        remoteIP[INET_ADDRSTRLEN] = '\0' ; /* gurantee null character */
        break;

      default:
        err_quit("usage: command [srvPort/name_of_service]\n");
    }

    printf("\nServer IP %s , srvPort=%hu\n" , remoteIP , srvPort );

    /* Allocate a TCP socket */
    sockfd = socketTCP( 0 , remoteIP , srvPort ) ;

    /* This is optional: Get & Print my local IP address and port */

    len = sizeof( clntaddr ) ;
    if( getsockname( sockfd , (SA *) &clntaddr, &len ) < 0 )
        err_quit("getsockname error");

    if ( ! inet_ntop( AF_INET, &clntaddr.sin_addr, localIP, sizeof(localIP) ) ) 
        err_quit("inet_ntop error");

    localport = ntohs( clntaddr.sin_port ) ;

    printf("\nMy local IP address & port are: %s:%d\n" , localIP , localport );

    // Now, read whatever the sarver sends to me till it closes the connection
    while ( ( n = Read( sockfd, recvline, MAXLINE ) ) > 0 ) 
    {
        recvline[n-1] = 0 ;	/* null terminate */
        printf( "\nI received \"%s\"\n" ,  recvline ) ;
    }

    if ( n == 0 )
        printf("\nConnection was closed by the server\n\n");

    Close( sockfd ) ;
}
