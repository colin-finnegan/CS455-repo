/******************************************************************
    Lab-03:  TCP DayTime

    FILE:   myNetLib.c

    Modified by ABOUTABL from original UNP's code 

    Updated on:   March 2025
**********************************************************************/

#include    "myNetLib.h"
#define     MAXSTRLEN    256

//------------------------------------------------------------
// To be called after a function that sets errno 

void err_sys( const char* x ) 
{ 
    fflush( stderr ) ;
    perror(x); 
    exit(1); 
}

//------------------------------------------------------------
// To be called after a function that DOES NOT set errno 

void err_quit( const char* x ) 
{ 
    fflush( stderr ) ;
    fputs( x , stderr ) ; 
    exit(1); 
}

//------------------------------------------------------------
// Wrapper for fork() 

pid_t Fork( void )
{
    pid_t n;
    n = fork() ;
    if ( n < 0 )      
        err_sys( "Fork failed" );

    return n ;
}

//------------------------------------------------------------
//  Wrapper for sigaction() 

Sigfunc * sigactionWrapper( int signo, Sigfunc *func )
// 'signo' specifies the signal and can be any valid signal 
//  except SIGKILL and SIGSTOP.

{
	struct sigaction	act, oact;

	act.sa_handler = func;
	sigemptyset( &act.sa_mask );
	act.sa_flags   = 0;

	if( sigaction( signo, &act, &oact ) < 0 )
		return( SIG_ERR );

	return( oact.sa_handler );
}

//------------------------------------------------------------
/* Wrapper for listen() */

int Listen(int sockfd, int backlog)
{
    int     errCode ;
    char    str[ MAXSTRLEN ] ;

    errCode = listen( sockfd , backlog ) ;

    if (  errCode < 0 )
    {
        snprintf( str , MAXSTRLEN , "\nFailed to listen() on socket %d" , 
                  sockfd );
        err_sys( str ) ;
    }
}

//------------------------------------------------------------
/*   A wrapper for the accept() slow system call. 
   If interrupted by a signal then retry, otherwise error   */

int Accept( int fd, struct sockaddr *sa, socklen_t *salenptr )
{
	int		n;
	while ( ( n = accept(fd, sa, salenptr) ) < 0 ) 
	{
		if ( errno == EINTR  /*|| errno == EPROTO || errno == ECONNABORTED*/ )
        { 
            puts("\n*** accept() interrupted by a signal. Retrying"); 
            continue ; 
        }
		else
			err_sys("Accept() error");
	}
	return( n );
}

//------------------------------------------------------------
/* Wrapper for close() */

void Close( int fd )
{
	if ( close( fd ) == -1 )
		err_sys("Close() error");
}

//-------------------------------------------------------------
/* A wrapper for the read() slow system call. 
   If interrupted by a signal then retry, otherwise error
   It's OK to short count even if no EOF encountered         */

ssize_t Read( int fd, void *buff, size_t maxBufSz )
{
    int nread ;
    
    while ( ( nread = read( fd, buff , maxBufSz ) ) < 0 ) 
    {
        if ( errno == EINTR )
        { 
            puts("\n*** read() interrupted by a signal. Retrying"); 
            continue ; 
        }
        else 
            err_sys("Read() error");
    }

    return nread ;
}

//-------------------------------------------------------------
/* A wrapper for the read() slow system call. 
   Keep reading until exactly "n" bytes are from a descriptor. 
   Short-counts only if EOF, otherwise error                 */

ssize_t readn( int fd, void *vptr, size_t n )
{
	size_t	nleft;
	ssize_t	nread;
	char	*ptr;

	ptr   = vptr;
	nleft = n;

    while ( nleft > 0 ) 
	{
		if ( ( nread = read(fd, ptr, nleft)) < 0 ) 
		{
			if (errno == EINTR)
				nread = 0;		/* and call read() again */
			else
			    err_sys("readn() error") ;  // exit due to communication error
		} 
        else if ( nread == 0 )		/* EOF */
			break;		// Short-Counted due to closure by source of data

		nleft -= nread;
		ptr   += nread;
	}

    return(n - nleft);		/* return >= 0 */
}

/*-------------------------------------------------------------------*/
/* A wrapper for the above readn()
/* Insist on reading exactly n bytes from fd, otherwise fail */

ssize_t Readn( int fd, void *vptr, size_t n )
{
	if ( readn( fd, vptr, n) != n )
		err_quit("\nReadn short-count , encountered EOF too soon.");

}

/*-------------------------------------------------------------------*/
/* A wrapper for the write() sometimes-slow system call. 
/* Insist on writing exactly nbytes to fd, otherwise fail */

ssize_t	writen( int fd, const void *vptr, size_t n )
{
	size_t		nleft;
	ssize_t		nwritten;
	const char	*ptr;

	ptr = vptr;
	nleft = n;

    while ( nleft > 0 ) 
	{
		// Were less than 'n' bytes written?

        if ( ( nwritten = write( fd, ptr, nleft ) ) <= 0 ) 
        {
            // Was this due to an incoming signal while blocked?
			if ( nwritten < 0 && errno == EINTR )
				nwritten = 0;		/* then call write() again */
			else
			    err_sys( "writen() error" ) ; // exit due to communication error 
        }
        
		nleft -= nwritten;
		ptr   += nwritten;
	}

    return( n );
}

/*------------------------------------------------------------------------
 * socketTCP - allocate & connect a socket using TCP
 *------------------------------------------------------------------------
 * Arguments:
 *      s_port    - If not zero, the local source port to bind to. 
 *                  Usually set by a server, but a client can optionally do it, too.
 *      remoteIP  - IP (in dotted-decimal) of remote host
 *      d_port    - the destination port at remote host
 *                  To connect if-and-only-if remoteIP != NULL  &&  d_port != 0
 */

int socketTCP( uint16_t s_port , const char *remoteIP, uint16_t d_port ) 
{
	int	   sd ;	    /* socket descriptor */
	char   buff[ MAXSTRLEN ] , ipStr[20] ;

    /* Allocate a TCP socket */
	sd   = socket( AF_INET, SOCK_STREAM , IPPROTO_TCP ) ;
	if( sd < 0)
		err_sys( "\nsocketTCP() can't create a socket" ) ;
    
    // If desired by caller, bind to the provided s_port
    // Usually a server does this, but a client may also do it
    if( s_port > 0 )
    {
        struct sockaddr_in  localAddr;
        
        memset( &localAddr , 0 , sizeof( struct sockaddr_in ) ) ;
        localAddr.sin_family      = AF_INET ;
        localAddr.sin_addr.s_addr = htonl( INADDR_ANY ) ;
        localAddr.sin_port        = htons( s_port ) ;
        inet_ntop( AF_INET, (void *) &localAddr.sin_addr.s_addr , ipStr , 20 ) ;

        if( bind( sd , (SA *) &localAddr , sizeof( struct sockaddr_in ) ) < 0 )
        {
            snprintf( buff , MAXSTRLEN , "\n### socketTCP(): socket %d can't bind to local %s : %hu", 
                      sd, ipStr , ntohs(localAddr.sin_port) ) ;
            err_sys( buff ) ;    
        }
        
        printf("\n### socketTCP(): TCP socket %u is bound to local %s : %hu\n" , sd, 
                ipStr, ntohs(localAddr.sin_port) );
    }

    // If desired, connect to remoteIP:port
    // Usually a client does this
    if( remoteIP != NULL  && d_port != 0 )
    {
        struct sockaddr_in	remoteAddr ;
        memset( &remoteAddr , 0 , sizeof( struct sockaddr_in ) ) ;
        remoteAddr.sin_family = AF_INET;
        remoteAddr.sin_port   = htons( d_port );

        if( inet_pton( AF_INET, remoteIP , &remoteAddr.sin_addr ) <= 0)
        {
            snprintf( buff , MAXSTRLEN , "\ninet_pton error in '%s'" , remoteIP);
            err_quit( buff );
        }
   
        inet_ntop( AF_INET, (void *) &remoteAddr.sin_addr.s_addr , ipStr , 20 ) ;

        if( connect( sd , (SA *) &remoteAddr , sizeof( struct sockaddr_in ) ) < 0 )
        {
            snprintf( buff , MAXSTRLEN , "\n### socketTCP():  can't connect socket %d to remote %s : %hu" ,
                      sd , ipStr , ntohs(remoteAddr.sin_port) ) ;
            
            err_sys( buff ) ;    
        }

        printf( "\n### socketTCP(): TCP socket %u is connected to remote %s : %hu\n" 
                , sd , ipStr , ntohs( remoteAddr.sin_port ) 
              );
    }

	return sd;
}

