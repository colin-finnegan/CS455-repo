/* ------------------------------------------------------------------------
    CS-455  Advanced Computer Networking
    Simplified Packet Analysis Programming Projects
    Designed By:        Dr. Mohamed Aboutabl  (c) 2026


    Assignment      : PA3
    Date            : 4/14/2026

    Implemented By  : Colin Finnegan  finnegcw@dukes.jmu.edu

    File Name       : p3.c
---------------------------------------------------------------------------*/

#include "mypcap.h"

// Externs to access variables in mypcap.c
extern unsigned countMine;
extern FILE *pcapOutput;

// Prototypes if not in your .h
int readARPmap(char *arpDB);
int writePCAPhdr(char *fname, pcap_hdr_t *p);
void processRequestPacket(packetHdr_t *pktHdr, uint8_t ethFrame[]);

/*-------------------------------------------------------------------------*/
void usage(char *cmd) {
    printf("Usage: %s <Input_PCAP> <Output_PCAP> <ARP_Data_File>\n", cmd);
}

/*-------------------------------------------------------------------------*/

int main(int argc, char *argv[]) {
    pcap_hdr_t pcapHdr;
    packetHdr_t pktHdr;
    uint8_t ethFrame[65535];
    
    // 1. Validate Command Line Arguments
    if (argc < 4) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    char *pcapInName  = argv[1];
    char *pcapOutName = argv[2];
    char *arpFileName = argv[3];
    

	printf("\nOutput PCAP file created and its global header set up\n");
	
	printf("\nHere is the listing of my ARP mapping database\n");
	
    // 1. Read the ARP map first
    if (readARPmap(arpFileName) == -1) {
        errorExit("Failed to read ARP mapping file.");
    }

    // 2. Open input PCAP and read header
    if (readPCAPhdr(pcapInName, &pcapHdr) == -1) {
        errorExit("Failed to read global header from the input PCAP file.");
    }

    // 3. Setup output PCAP with the same header
    if (writePCAPhdr(pcapOutName, &pcapHdr) == -1) {
        errorExit("Failed to create output PCAP file.");
    }

    // 4. Print the specific PA-03 table headers
    printf("\n%10s     %s\n", "Frame #", "Its Destination MAC");

    // 5. Main Loop
    while (getNextPacket(&pktHdr, ethFrame)) {
        // processRequestPacket handles printing, filtering, and generating replies
        processRequestPacket(&pktHdr, ethFrame);
    }

    // 6. Final Summary
    printf("\n%u packets targeted me\n", countMine);
    printf("\nReached end of PCAP file '%s'.\n\n", pcapInName);

    // Clean up
    cleanUp();

    return 0;
}