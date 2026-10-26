/* ------------------------------------------------------------------------
    CS-455  Advanced Computer Networking
    Simplified Packet Analysis Programming Projects
    Designed By:        Dr. Mohamed Aboutabl  (c) 2026

    Assignment      : PA3
    Date            : 4/14/2026

    Implemented By  : Colin Finnegan  finnegcw@dukes.jmu.edu

    File Name       : mypcap.c
---------------------------------------------------------------------------*/

#include "mypcap.h"

/*-----------------   GLOBAL   VARIABLES   --------------------------------*/
FILE *pcapInput = NULL; // The input PCAP file
FILE *pcapOutput = NULL;
unsigned countMine = 0;
arpmap_t myARPmap[MAXARPMAP];
int mapSize = 0;
bool bytesOK;           // Does the capturer's byte ordering same as mine?
              // Affects the global PCAP header and each packet's header
			  
static uint16_t nextIPid = 1000;
static int frameCounter = 0;

bool microSec; // is the time stamp in Sec + microSec ?  or in Sec + nanoSec ?

double baseTime; // capturing time (in seconds ) of the very 1st packet in this
                 // file
bool baseTimeSet = false;

/* ***************************** */
/*          PROJECT 1            */
/* ***************************** */

/*-------------------------------------------------------------------------*/
void
errorExit (char *str)
{
  if (str)
    puts (str);
  if (pcapInput)
    fclose (pcapInput);
  exit (EXIT_FAILURE);
}

/*-------------------------------------------------------------------------*/
void
cleanUp ()
{
  if (pcapInput)
    fclose (pcapInput);
  
  if (pcapOutput) 
	fclose(pcapOutput);
}

/*-------------------------------------------------------------------------*/
/*  Open the input PCAP file 'fname'
    and read its global header into buffer 'p'
    Side effects:
        - Set the global FILE *pcapInput to the just-opened file
        - Properly set the global flags: bytesOK  and   microSec
        - If necessary, reorder the bytes of all global PCAP header
          fields except for the magic_number

    Remember to check for incuming NULL pointers

    Returns:  0 on success
             -1 on failure  */

int
readPCAPhdr (char *fname, pcap_hdr_t *p)
{
  // Always check for incoming NULL poiters
  if (fname == NULL || p == NULL)
    {
      return -1;
    }

  // Successfully open the input 'fname'
  pcapInput = fopen (fname, "r");
  if (pcapInput == NULL)
    {

      return -1;
    }

  // read input into the global header
  if (fread (p, sizeof (pcap_hdr_t), 1, pcapInput) != 1)
    {

      return -1;
    }

  // Determine the capturer's byte ordering
  // Issue: magic_number could also be 0xa1b23c4D to indicate nano-second
  // resolution instead of microseconds. This affects the interpretation
  // of the ts_usec field in each packet's header.
  if (p->magic_number == 0xa1b23c4d)
    {
      bytesOK = true;
      microSec = false;
    }
  else if (p->magic_number == 0xA1B2C3D4)
    {
      bytesOK = true;
      microSec = true;
    }
  else if (p->magic_number == 0x4d3cb2a1)
    {
      bytesOK = false;
      microSec = false;
    }
  else if (p->magic_number == 0xD4C3B2A1)
    {
      bytesOK = false;
      microSec = true;
    }
  else
    {
      return -1;
    }

  if (!bytesOK)
    {
      p->version_major = ntohs (p->version_major);
      p->version_minor = ntohs (p->version_minor);
      p->thiszone = (int32_t)ntohl ((uint32_t)p->thiszone);
      p->sigfigs = ntohl (p->sigfigs);
      p->snaplen = ntohl (p->snaplen);
      p->network = ntohl (p->network);
    }

  return 0;
}

/*-------------------------------------------------------------------------*/
/* Print the global header of the PCAP file from buffer 'p'                */
void
printPCAPhdr (const pcap_hdr_t *p)
{
  printf ("magic number %X\n", p->magic_number);
  printf ("major version %u\n", p->version_major);
  printf ("minor version %u\n", p->version_minor);
  printf ("GMT to local correction %d seconds\n", p->thiszone);
  printf ("accuracy of timestamps %u\n", p->sigfigs);
  printf ("Cut-off max length of captured packets %u\n", p->snaplen);
  printf ("data link type %u\n", p->network);
}

/*-------------------------------------------------------------------------*/
/*  Read the next packet (Header and entire ethernet frame)
    from the previously-opened input  PCAP file 'pcapInput'
    Must check for incoming NULL pointers and incomplete frame payload

    If this is the very first packet from the PCAP file, set the baseTime

    Returns true on success, or false on failure for any reason */

bool
getNextPacket (packetHdr_t *p, uint8_t ethFrame[])
{
  // Check for incoming NULL pointers
  if (p == NULL || ethFrame == NULL)
    {
      return false;
    }

  // Read the header of the next packet in the PCAP file
  if (fread (p, sizeof (packetHdr_t), 1, pcapInput) != 1)
    {
      return false;
    }

  // Did the capturer use a different byte-ordering than mine (as determined by
  // the magic number)?
  if (!bytesOK)
    {
      // reorder the bytes of the fields in this packet header
      p->ts_sec = ntohl (p->ts_sec);
      p->ts_usec = ntohl (p->ts_usec);
      p->incl_len = ntohl (p->incl_len);
      p->orig_len = ntohl (p->orig_len);
    }

  // Read 'incl_len' bytes from the PCAP file into the ethFrame[]
  if (fread (ethFrame, sizeof (uint8_t), p->incl_len, pcapInput)
      != p->incl_len)
    {
      return false;
    }

  // If necessary, set the baseTime .. Pay attention to possibility of nano
  // second time precision (instead of micro seconds )
  if (!baseTimeSet)
    {
      if (microSec)
        {
          baseTime = (double)(p->ts_sec) + (double)(p->ts_usec) / 1000000;
        }
      else
        {
          baseTime = (double)(p->ts_sec) + (double)(p->ts_usec) / 1000000000;
        }

      baseTimeSet = true;
    }

  return true;
}

/*-------------------------------------------------------------------------*/
/* print packet's capture time (relative to the base time),
   the original packet's length in bytes, and the included length */

void
printPacketMetaData (const packetHdr_t *p)
{
  double capTime;
  if (microSec)
    {
      capTime = (double)p->ts_sec + (double)(p->ts_usec) / 1000000;
    }
  else
    {
      capTime = (double)p->ts_sec + (double)(p->ts_usec) / 1000000000;
    }

  capTime = capTime - baseTime;
  printf ("%14f ", capTime);
  printf ("%6u / %6u ", p->orig_len, p->incl_len);
}

/*-------------------------------------------------------------------------*/
/* Print the packet's captured data starting with its ethernet frame header
   and moving up the protocol hierarchy */

void
printPacket (const etherHdr_t *frPtr, uint32_t capLen)
{
  const uint8_t *hdr_start = (const uint8_t *)frPtr + sizeof (etherHdr_t);
  switch (ntohs (frPtr->eth_type))
    {
    case PROTO_IPv4: // Eth Packet contains IPv4, could be UDP/TCP or ICMP
		if (capLen < sizeof(etherHdr_t) + sizeof(ipv4Hdr_t)) return; 
        {
            const ipv4Hdr_t *iphdr = (const ipv4Hdr_t *)(hdr_start);
            printIPinfo (iphdr);
        }
        break;

    case PROTO_ARP: // Eth Packet contains ARP
	{
      char mac_src[MAXMACADDRLEN];
      char mac_dest[MAXMACADDRLEN];
      macToStr (frPtr->eth_dstMAC, mac_dest);
      macToStr (frPtr->eth_srcMAC, mac_src);

      // print Source/Destination MAC addresses
      printf ("%-20s ", mac_src);
      printf ("%-20s ", mac_dest);

      const arpMsg_t *arp = (const arpMsg_t *)(hdr_start);
      printARPinfo (arp);
	}
      break;

    default:
	{
		char mac_src[MAXMACADDRLEN];
        char mac_dest[MAXMACADDRLEN];
        macToStr (frPtr->eth_srcMAC, mac_src);  // Get Source MAC
        macToStr (frPtr->eth_dstMAC, mac_dest); // Get Dest MAC

        // If "Protocol" needs to be in the 7th column (Protocol column):
		printf ("%-20s %-20s Protocol %d Not Supported Yet", 
        mac_src, mac_dest, ntohs(frPtr->eth_type));
	}	
      break;
    }
}

/* -------------------------------------------
New for pa1
*/

// Print ARP info
void
printARPinfo (const arpMsg_t *arp)
{

  printf ("%-8s ", "ARP"); // Print protocol

  switch (ntohs (arp->arp_oper))
    {
    case ARPREQUEST:
      char sender[MAXIPv4ADDRLEN];
      char target[MAXIPv4ADDRLEN];
      ipToStr (arp->arp_spa, sender);
      ipToStr (arp->arp_tpa, target);

      printf ("Who has %s ? Tell %s", target, sender);
      break;

    case ARPREPLY:
      char senderIP[MAXIPv4ADDRLEN];
      char senderMAC[MAXMACADDRLEN];
      ipToStr (arp->arp_spa, senderIP);
      macToStr (arp->arp_sha, senderMAC);

      printf ("%s is at %s", senderIP, senderMAC);
      break;

    default:
      errorExit ("Bad ARP Operation Field");
    }
}

// Print IP info
void
printIPinfo (const ipv4Hdr_t *iphdr)
{
  char ip_src[MAXIPv4ADDRLEN];
  char ip_dst[MAXIPv4ADDRLEN];
  ipToStr (iphdr->ip_srcIP, ip_src);
  ipToStr (iphdr->ip_dstIP, ip_dst);

  // Adjusted spacing to match the Destination/Protocol columns
  printf ("%-20s %-20s ", ip_src, ip_dst);

  uint8_t header_bytes = (iphdr->ip_verHlen & 0x0f) * 4;
  if (header_bytes < 20 || header_bytes > 60) {
    printf("Invalid IP Header ");
    return; 
	}
  uint8_t options_len = header_bytes - 20;

  switch (iphdr->ip_proto)
    {
    case PROTO_ICMP:
      printf ("%-8s ", "ICMP");
      printf ("IP_HDR{ Len=%d incl. %d options bytes} ", header_bytes, options_len);
      const icmpHdr_t *icmphdr = (const icmpHdr_t *)(iphdr->options + options_len);
      printICMPinfo (icmphdr);
      printf ("AppData=%5ld", (long)(ntohs (iphdr->ip_totLen) - header_bytes - sizeof (icmpHdr_t)));
      break;

    case PROTO_TCP:
      printf ("%-8s ", "TCP");
      printf ("IP_HDR{ Len=%d incl. %d options bytes} ", header_bytes, options_len);
      {
        const tcpHdr_t *tcphdr = (const tcpHdr_t *)(iphdr->options + options_len);
        unsigned tcp_hdr_len = printTCPinfo(tcphdr);
        // Note the spacing before AppData to match the single-line requirement
        printf ("AppData=%5d", ntohs(iphdr->ip_totLen) - header_bytes - tcp_hdr_len );
      }
      break;

    case PROTO_UDP:
      printf ("%-8s ", "UDP");
      printf ("IP_HDR{ Len=%2d incl. %d options bytes} ", header_bytes, options_len);
      {
        const udpHdr_t *udphdr = (const udpHdr_t *)(iphdr->options + options_len);
        unsigned udp_hdr_len = printUDPinfo(udphdr);
        printf ("AppData=%5d", ntohs(iphdr->ip_totLen) - header_bytes - udp_hdr_len );
      }
      break;

    default:
      printf ("Protocol %d (Unsupported) ", iphdr->ip_proto);
      break;
    }
}

unsigned
printICMPinfo (const icmpHdr_t *icmphdr)
{
  printf ("ICMP_HDR{ ");
  switch (icmphdr->icmp_type)
    {
    case ICMP_ECHO_REPLY:
      printf ("%-12s :id=%5d, seq=%5d} ", "Echo Reply",
              ntohs (*(uint16_t *)icmphdr->icmp_line2),
              ntohs (*(uint16_t *)(icmphdr->icmp_line2 + 2)));
      break;

    case ICMP_ECHO_REQUEST:
      printf ("%-12s :id=%5d, seq=%5d} ", "Echo Request",
              ntohs (*(uint16_t *)icmphdr->icmp_line2),
              ntohs (*(uint16_t *)(icmphdr->icmp_line2 + 2)));
      break;

    default:
      errorExit ("Unknown or unhandled ICMP Type");
    }

  return 0;
}

/*-------------------------------------------------------------------------*/
/* PROJECT 2 FUNCTIONS                            */
/*-------------------------------------------------------------------------*/

unsigned printUDPinfo( const udpHdr_t *p ) 
{
    struct servent *sv;
    uint16_t srcP = ntohs(p->udp_srcPort);
    uint16_t dstP = ntohs(p->udp_dstPort);

    printf("UDP  %4u Bytes. Port %5u ", ntohs(p->udp_len), srcP);
    
    if ( (sv = getservbyport(p->udp_srcPort, "udp")) ) 
        printf("(%7s) -> ", sv->s_name);
    else 
        printf("(   *** ) -> ");

    printf("%5u ", dstP);
    if ( (sv = getservbyport(p->udp_dstPort, "udp")) ) 
        printf("(%7s)  ", sv->s_name);
    else 
        printf("(   *** )  ");

    return 8; // UDP Header is always 8 bytes
}

/*-------------------------------------------------------------------------*/

unsigned printTCPinfo( const tcpHdr_t *p ) 
{
    struct servent *sv;
    uint16_t srcP = ntohs(p->tcp_srcPort);
    uint16_t dstP = ntohs(p->tcp_dstPort);
    uint8_t hlen = (p->tcp_offRes >> 4) * 4;

    printf("TCPhdr=%2u (Options %2u bytes) Port %5u ", hlen, hlen-20, srcP);
    
    // Check Source Port
    sv = getservbyport(p->tcp_srcPort, "tcp");
    if (sv != NULL) 
        printf("(%7s) -> ", sv->s_name);
    else 
        printf("(   *** ) -> ");

    printf("%5u ", dstP);

    // Check Destination Port
    sv = getservbyport(p->tcp_dstPort, "tcp");
    if (sv != NULL) 
        printf("(%7s) ", sv->s_name);
    else 
        printf("(   *** ) ");

    // Flags in the exact order: [SYN PSH ACK FIN RST] 
    // Note: Spaces are important for empty slots
    printf("[");
    printf("%s", (p->tcp_flags & 0x02) ? "SYN " : "    ");
    printf("%s", (p->tcp_flags & 0x08) ? "PSH " : "    ");
    printf("%s", (p->tcp_flags & 0x10) ? "ACK " : "    ");
    printf("%s", (p->tcp_flags & 0x01) ? "FIN " : "    ");
    printf("%s", (p->tcp_flags & 0x04) ? "RST " : "    ");
    printf("] ");

    printf("Seq=%10u ", ntohl(p->tcp_seq));
    if (p->tcp_flags & 0x10) // Only print Ack if ACK flag is set
        printf("Ack=%10u ", ntohl(p->tcp_ack));
    else
        printf("               "); // 15 spaces to align if no Ack

    printf("Rwnd=%5u ", ntohs(p->tcp_win));

    return hlen;
}


/* ***************************** */
/*          PROJECT 3            */
/* ***************************** */

int writePCAPhdr( char *fname , pcap_hdr_t *p) {
	pcapOutput = fopen(fname, "w");
	if (!pcapOutput) {
		return -1;
	}
	
	if (fwrite(p, sizeof(pcap_hdr_t), 1, pcapOutput) != 1) {
		return -1;
	}
	
	return 0;
}


int readARPmap( char *arpDB ) {

	FILE *fp = fopen(arpDB, "r");
    if (!fp) return -1;

    char ipStr[20], macStr[20];
    mapSize = 0;

    while (mapSize < MAXARPMAP && fscanf(fp, "%s %s", ipStr, macStr) == 2) {
        // Convert string IP to numeric
        myARPmap[mapSize].ip = inet_addr(ipStr);
        
        // Convert string MAC (XX:XX:XX...) to bytes
        unsigned int m[6];
        sscanf(macStr, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
        for(int i = 0; i < 6; i++) myARPmap[mapSize].mac[i] = (uint8_t)m[i];
        
        mapSize++;
    }
    fclose(fp);

    // Print the map as required
    for (int i = 0; i < mapSize; i++) {
        struct in_addr addr;
        addr.s_addr = myARPmap[i].ip;
        printf(" %d:      %-15s%02x:%02x:%02x:%02x:%02x:%02x\n", 
               i,
			   inet_ntoa(addr),
               myARPmap[i].mac[0], myARPmap[i].mac[1], myARPmap[i].mac[2],
               myARPmap[i].mac[3], myARPmap[i].mac[4], myARPmap[i].mac[5]);
    }
    return mapSize;
}

uint16_t inet_checksum( void * data , uint16_t lenBytes ) {

	uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *)data;

    while (lenBytes > 1) {
        sum += *ptr++;
        lenBytes -= 2;
    }

    // Handle the odd byte if the length isn't even
    if (lenBytes == 1) {
        sum += *(uint8_t *)ptr;
    }

    // Fold 32-bit sum into 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}


bool myIP( IPv4addr someIP , uint8_t **ptr ){
    // Convert IPv4addr union/struct to a single uint32 for easier comparison
	uint32_t targetIP;
    memcpy(&targetIP, &someIP, 4);

    for (int i = 0; i < mapSize; i++) {
        if (myARPmap[i].ip == targetIP) {
            if (ptr != NULL) *ptr = myARPmap[i].mac;
            return true;
        }
    }
    if (ptr != NULL) *ptr = NULL;
    return false;
}


bool myMAC( uint8_t someMAC[] ) {
	// 1. Check if it's the Broadcast address (all FF's)
	bool isBroadcast = true;
	
	for (int i = 0; i < 6; i++ ) {
		if (someMAC[i] != 0xFF) isBroadcast = false;
	}
	if (isBroadcast) return true;
	
	// 2. Check if it matches any of your MACs in the map
	for (int i = 0; i < mapSize; i++) {
		if (memcmp(someMAC, myARPmap[i].mac, 6) == 0) return true;
	}
	
	return false;
}


void processRequestPacket( packetHdr_t *pktHdr, uint8_t ethFrame[] ){
    
	frameCounter++;
    etherHdr_t *eth = (etherHdr_t *)ethFrame;
    char macBuf[MAXMACADDRLEN];
    macToStr(eth->eth_dstMAC, macBuf);

    // Initial print for every frame
    printf("%8d )     %-20s", frameCounter, macBuf);

    // 1. Is it targeting my machine? (My MAC or Broadcast)
    if (!myMAC(eth->eth_dstMAC)) {
        printf("\n");
        return;
    }

    // Prepare response pointers
    uint8_t *myMacPtr = NULL;
    bool shouldRespond = false;
    uint16_t proto = ntohs(eth->eth_type);

    // 2. Identify if it's an ARP Request or ICMP Echo Request for ME
    if (proto == PROTO_ARP) {
        arpMsg_t *arp = (arpMsg_t *)(ethFrame + sizeof(etherHdr_t));
        if (ntohs(arp->arp_oper) == ARPREQUEST && myIP(arp->arp_tpa, &myMacPtr)) {
            printf("ARP Request for me\n");
            shouldRespond = true;
        }
    } 
    else if (proto == PROTO_IPv4) {
        ipv4Hdr_t *ip = (ipv4Hdr_t *)(ethFrame + sizeof(etherHdr_t));
        uint8_t ipHdrLen = (ip->ip_verHlen & 0x0F) * 4;
        
        if (ip->ip_proto == PROTO_ICMP && myIP(ip->ip_dstIP, &myMacPtr)) {
            icmpHdr_t *icmp = (icmpHdr_t *)((uint8_t *)ip + ipHdrLen);
            if (icmp->icmp_type == ICMP_ECHO_REQUEST) {
                printf("ICMP Echo Request for me\n");
                shouldRespond = true;
            }
        }
    }

    if (!shouldRespond) {
        printf("\n");
        return;
    }

    countMine++;

    // Step A: Duplicate original packet to output
    fwrite(pktHdr, sizeof(packetHdr_t), 1, pcapOutput);
    fwrite(ethFrame, 1, pktHdr->incl_len, pcapOutput);

    // Step B: Build the Reply
    packetHdr_t replyPktHdr = *pktHdr;
    
    if (microSec) {
		// File is in Microseconds: Add 30
		replyPktHdr.ts_usec += 30;
    
		// Carry over if we hit 1,000,000 microseconds
		if (replyPktHdr.ts_usec >= 1000000) {
			replyPktHdr.ts_usec -= 1000000;
			replyPktHdr.ts_sec++;
		}
	} else {
		// File is in Nanoseconds: Add 30,000
		replyPktHdr.ts_usec += 30000;
    
		// Carry over if we hit 1,000,000,000 nanoseconds
		if (replyPktHdr.ts_usec >= 1000000000) {
			replyPktHdr.ts_usec -= 1000000000;
			replyPktHdr.ts_sec++;
		}
	}

	// IMPORTANT: After math is done, if the file was swapped, 
	// we must swap the headers back to the file's original endianness
	if (!bytesOK) {
		replyPktHdr.ts_sec = htonl(replyPktHdr.ts_sec);
		replyPktHdr.ts_usec = htonl(replyPktHdr.ts_usec);
		replyPktHdr.incl_len = htonl(replyPktHdr.incl_len);
		replyPktHdr.orig_len = htonl(replyPktHdr.orig_len);
	}	

    // Create a buffer for the response frame
    uint8_t replyFrame[2000]; // Plenty of space
    memcpy(replyFrame, ethFrame, pktHdr->incl_len);
    etherHdr_t *rEth = (etherHdr_t *)replyFrame;

    // Swap MACs for the Ethernet Header
    memcpy(rEth->eth_dstMAC, eth->eth_srcMAC, 6);
    memcpy(rEth->eth_srcMAC, myMacPtr, 6);

    if (proto == PROTO_ARP) {
        arpMsg_t *rArp = (arpMsg_t *)(replyFrame + sizeof(etherHdr_t));
		arpMsg_t *reqArp = (arpMsg_t *)(ethFrame + sizeof(etherHdr_t));
		
        rArp->arp_oper = htons(ARPREPLY);
		// Sender of reply is ME
        memcpy(rArp->arp_sha, myMacPtr, 6);
        memcpy(rArp->arp_spa.byte, reqArp->arp_tpa.byte, 4);
        // Target of reply is the sender of request
        memcpy(rArp->arp_tha, reqArp->arp_sha, 6);
        memcpy(rArp->arp_tpa.byte, reqArp->arp_spa.byte, 4);
		
		if (!bytesOK) {
            rArp->arp_oper = ntohs(rArp->arp_oper); // Swap back to file endianness
            // Note: MACs and IPs are byte-arrays, so they don't need swapping
        }
    } 
    else { // IPv4 / ICMP
        ipv4Hdr_t *rIp = (ipv4Hdr_t *)(replyFrame + sizeof(etherHdr_t));
        uint8_t ipHdrLen = (rIp->ip_verHlen & 0x0F) * 4;
        icmpHdr_t *rIcmp = (icmpHdr_t *)((uint8_t *)rIp + ipHdrLen);

        // Swap IPs
        IPv4addr tmpIP = rIp->ip_srcIP;
        rIp->ip_srcIP = rIp->ip_dstIP;
        rIp->ip_dstIP = tmpIP;

        // Requirement: ID starts at 1000, DF bit set
        rIp->ip_id = htons(nextIPid++);
        rIp->ip_flagsFrag = htons(0x4000); // Binary 0100 0000... (Don't Fragment)

        // Reset and Recalculate IP Checksum
        rIp->ip_hdrChk = 0;
        rIp->ip_hdrChk = inet_checksum(rIp, ipHdrLen);

        // Modify ICMP to Reply
        rIcmp->icmp_type = ICMP_ECHO_REPLY;
        
        // Reset and Recalculate ICMP Checksum
        rIcmp->icmp_check = 0;
        uint16_t icmpLen = ntohs(rIp->ip_totLen) - ipHdrLen;
        rIcmp->icmp_check = inet_checksum(rIcmp, icmpLen);
		
		if (!bytesOK) {
            rIp->ip_totLen = ntohs(rIp->ip_totLen);
            rIp->ip_id = ntohs(rIp->ip_id);
            rIp->ip_flagsFrag = ntohs(rIp->ip_flagsFrag);
            rIp->ip_hdrChk = ntohs(rIp->ip_hdrChk);
            rIcmp->icmp_check = ntohs(rIcmp->icmp_check);
        }
    }
	
	if (!bytesOK) {
        replyPktHdr.ts_sec = htonl(replyPktHdr.ts_sec);
        replyPktHdr.ts_usec = htonl(replyPktHdr.ts_usec);
        replyPktHdr.incl_len = htonl(replyPktHdr.incl_len);
        replyPktHdr.orig_len = htonl(replyPktHdr.orig_len);
    }

    // Step C: Export the reply
    fwrite(&replyPktHdr, sizeof(packetHdr_t), 1, pcapOutput);
    fwrite(replyFrame, 1, replyPktHdr.incl_len, pcapOutput);
	
}


/*-------------------------------------------------------------------------*/
/*               Suggested Utility Functions                               */
/*-------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------*/
/*  Convert a MAC address to the format xx:xx:xx:xx:xx:xx
    in the caller-provided 'buf' whose maximum 'size' is given
    Returns 'buf'  */

char *
macToStr (const uint8_t *p, char *buf)
{
  if (p == NULL || buf == NULL)
    {
      errorExit ("Pointers in macToStr NULL");
    }

  snprintf (buf, MAXMACADDRLEN, "%02x:%02x:%02x:%02x:%02x:%02x", p[0], p[1],
            p[2], p[3], p[4], p[5]);

  return buf;
}

/* Convert an IP address to the format x.x.x.x in the provided 'ipStr' from the
 * numeric IPV4addr 'ip'. Returns 'ipStr' */
char *
ipToStr (const IPv4addr ip, char *ipStr)
{
  if (ipStr == NULL)
    {
      errorExit ("Pointers in ipToStr null");
    }

  snprintf (ipStr, MAXIPv4ADDRLEN, "%d.%d.%d.%d", ip.byte[0], ip.byte[1],
            ip.byte[2], ip.byte[3]);

  return ipStr;
}
