/* ------------------------------------------------------------------------
    CS-455  Advanced Computer Networking
    Simplified Packet Analysis Programming Projects
    Designed By:        Dr. Mohamed Aboutabl  (c) 2026
    
    Implemented By:     Colin Finnegan
    File Name:          mypcap.c

---------------------------------------------------------------------------*/

#include "mypcap.h"

/*-----------------   GLOBAL   VARIABLES   --------------------------------*/
FILE       *pcapInput  =  NULL ;        // The input PCAP file
bool        bytesOK ;   // Does the capturer's byte ordering same as mine?
                        // Affects the global PCAP header and each packet's header

bool        microSec ;  // is the time stamp in Sec + microSec ?  or in Sec + nanoSec ?

double      baseTime ;  // capturing time (in seconds ) of the very 1st packet in this file
bool        baseTimeSet = false ;

/* ***************************** */
/*          PROJECT 1            */
/* ***************************** */

/*-------------------------------------------------------------------------*/
void errorExit( char *str )
{
    if (str) puts(str) ;
    if ( pcapInput  )  fclose ( pcapInput  ) ;
    exit( EXIT_FAILURE );
}

/*-------------------------------------------------------------------------*/
void cleanUp( )
{
    if ( pcapInput  )  fclose ( pcapInput  ) ;
}

/*-------------------------------------------------------------------------*/
/*  Open the input PCAP file 'fname' 
    and read its global header into buffer 'p'
    Side effects:    
        - Set the global FILE *pcapInput to the just-opened file
        - Properly set the global flags: bytesOK  and   microSec
        - If necessary, reorder the bytes of all globap PCAP header 
          fields except for the magic_number

    Remember to check for incuming NULL pointers

    Returns:  0 on success
             -1 on failure  */

int readPCAPhdr( char *fname , pcap_hdr_t *p)
{
	// Always check for incoming NULL poiters
	if ( fname == NULL || p == NULL )
	{
		return -1;
	}
	// Successfully open the input 'fname'
	pcapInput = fopen( fname, "rb");
	if (pcapInput == NULL)
	{
		return -1;
	}
    //read input into the golbal header
	if (fread( p, sizeof(pcap_hdr_t), 1, pcapInput ) != 1)
	{
		return -1;
	}
	if (p->magic_number == 0xa1b23c4D)
	{
		bytesOK = true;
		microSec = false;
	}
	else if (p->magic_number == 0x4D3cb2a1)
	{
		bytesOK = false;
		microSec = false;
		p->version_major = ntohs(p->version_major);
		p->version_minor = ntohs(p->version_minor);
		p->thiszone = ntohl(p->thiszone);
		p->sigfigs = ntohl(p->sigfigs);
		p->snaplen = ntohl(p->snaplen);
		p->network = ntohl(p->network);
	}
	else if (p->magic_number == 0xD4C3B2A1)
	{
		bytesOK = false;
		microSec = true;
		p->version_major = ntohs(p->version_major);
		p->version_minor = ntohs(p->version_minor);
		p->thiszone = ntohl(p->thiszone);
		p->sigfigs = ntohl(p->sigfigs);
		p->snaplen = ntohl(p->snaplen);
		p->network = ntohl(p->network);
	}
	else if (p->magic_number == 0xA1B2C3D4)
	{
		bytesOK = true;
		microSec = true;
	}
	else
	{
		return -1;
	}
	
	return 0;
	
    // Determine the capturer's byte ordering
    // Issue: magic_number could also be 0xa1b23c4D to indicate nano-second 
    // resolution instead of microseconds. This affects the interpretation
    // of the ts_usec field in each packet's header.

}

/*-------------------------------------------------------------------------*/
/* Print the global header of the PCAP file from buffer 'p'                */
void printPCAPhdr( const pcap_hdr_t *p ) 
{
    printf("magic number %X\n"                           , p->magic_number );    
    printf("major version %X\n"							 , p->version_major );
	printf("minor version %X\n"							 , p->version_minor );
	printf("GMT to local correction %d seconds\n"		 , p->thiszone );
	printf("accuracy of timestamps %X\n"				 , p->sigfigs );
	printf("Cut-off max length of captured packets %u\n" , p->snaplen );
	printf("data link type %X\n"						 , p->network );
}

/*-------------------------------------------------------------------------*/
/*  Read the next packet (Header and entire ethernet frame) 
    from the previously-opened input  PCAP file 'pcapInput'
    Must check for incoming NULL pointers and incomplete frame payload
    
    If this is the very first packet from the PCAP file, set the baseTime 
    
    Returns true on success, or false on failure for any reason */

bool getNextPacket( packetHdr_t *p , uint8_t  ethFrame[]  )
{
    // Check for incoming NULL pointers
	if ( p == NULL || ethFrame == NULL )
	{
		return false;
	}
	
	
	// Read the header of the next paket in the PCAP file
	if (fread( p, sizeof(packetHdr_t), 1, pcapInput ) != 1)
	{
		return false;
	}

    // Did the capturer use a different 
    // byte-ordering than mine (as determined by the magic number)?
    if( ! bytesOK )   
    {
        p->incl_len = ntohl(p->incl_len);
		p->orig_len = ntohl(p->orig_len);
		p->ts_sec = ntohl(p->ts_sec);
		p->ts_usec = ntohl(p->ts_usec);
    }
    
    // Read 'incl_len' bytes from the PCAP file into the ethFrame[]
	size_t bytesRead = fread( ethFrame, 1, p->incl_len, pcapInput);
	if (bytesRead < p->incl_len)
	{
		return false;
	}
    // If necessary, set the baseTime .. Pay attention to possibility of nano second 
    // time precision (instead of micro seconds )
	if ( baseTimeSet == false)
	{
		if (microSec == true)
		{
			baseTime = p->ts_sec + (p->ts_usec / 1000000.0);
		}
		else
		{
			baseTime = p->ts_sec + (p->ts_usec / 1000000000.0);
		}
		baseTimeSet = true;
	}
    
    return true ;
}


/*-------------------------------------------------------------------------*/
/* print packet's capture time (realative to the base time),
   the priginal packet's length in bytes, and the included length */
   
void printPacketMetaData( const packetHdr_t *p  )
{
	double captureTime;
	if (microSec == true)
	{
		captureTime = p->ts_sec + (p->ts_usec / 1000000.0);
	}
	else
	{
		captureTime = p->ts_sec + (p->ts_usec / 1000000000.0);
	}
	printf("%.6f     ", captureTime - baseTime);
	printf("%u /     ", p->orig_len);
	printf("%u ", p->incl_len);
}

/*-------------------------------------------------------------------------*/
/* Print the packet's captured data starting with its ethernet frame header
   and moving up the protocol hierarchy */ 

void printPacket( const etherHdr_t *frPtr )
{

    // Missing Code Here
	char srcBuf[MAXMACADDRLEN];
	char dstBuf[MAXMACADDRLEN];
	
	macToStr(frPtr->eth_srcMAC, srcBuf);
	macToStr(frPtr->eth_dstMAC, dstBuf);
	
	printf("%s    ", srcBuf);
	printf("%s    \n", dstBuf);
    // print Source/Destination MAC addresses

}


/*-------------------------------------------------------------------------*/
/*               Suggested Utility Functions                               */
/*-------------------------------------------------------------------------*/


/*-------------------------------------------------------------------------*/
/*  Convert a MAC address to the format xx:xx:xx:xx:xx:xx 
    in the caller-provided 'buf' whose maximum 'size' is given
    Returns 'buf'  */

char *macToStr( const uint8_t *p , char *buf )
{
	snprintf(buf, MAXMACADDRLEN, "%02x:%02x:%02x:%02x:%02x:%02x", p[0], p[1], p[2], p[3], p[4], p[5]);
	return buf;
}


