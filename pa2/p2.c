/* ------------------------------------------------------------------------
    CS-455  Advanced Computer Networking
    Simplified Packet Analysis Programming Projects
    Designed By:        Dr. Mohamed Aboutabl  (c) 2026


    Assignment      : PA2
    Date            : 3/24/2026

    Implemented By  : Colin Finnegan  finnegcw@dukes.jmu.edu

    File Name       : p2.c
---------------------------------------------------------------------------*/

#include "mypcap.h"

/*-------------------------------------------------------------------------*/
void
usage (char *cmd)
{
  printf ("Usage: %s PCAP_file_Name\n", cmd);
}

/*-------------------------------------------------------------------------*/

int
main (int argc, char *argv[])
{
  char *pcapIn;
  pcap_hdr_t pcapHdr;
  packetHdr_t pktHdr;
  uint8_t ethFrame[65535];
  etherHdr_t *frameHdrPtr = (etherHdr_t *)ethFrame;

  if (argc < 2)
    {
      usage (argv[0]);
      exit (EXIT_FAILURE);
    }

  pcapIn = argv[1];
  printf ("\nProcessing PCAP file '%s'\n\n", pcapIn);

  if (readPCAPhdr (pcapIn, &pcapHdr) == -1)
    {
      errorExit ("Failed to read global header from the PCAP file ");
    }

  printPCAPhdr (&pcapHdr);

  // STRICT COLUMN HEADERS FOR PA2
  puts ("");
  printf ("%6s %14s %6s / %6s %-20s %-20s %8s %s\n", 
          "PktNum", "Time Stamp", "OrgLen", "Captrd", 
          "Source", "Destination", "Protocol", "info");

  int packetNum = 0;
  while (getNextPacket (&pktHdr, ethFrame))
    {
      packetNum++;
      printf ("%6d ", packetNum);

      // Prints the timestamp and lengths
      printPacketMetaData (&pktHdr);

      // Prints the MACs, IPs, and now the TCP/UDP/ICMP details
      printPacket (frameHdrPtr, pktHdr.incl_len);

      // Important: Only one newline here to separate packets
      printf("\n"); 
    }

  printf ("\nReached end of PCAP file '%s'\n", pcapIn);
  cleanUp ();
  return 0;
}