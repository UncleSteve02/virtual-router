//--------------------------------------------------------------------
//-------------------------------- Includes --------------------------
//--------------------------------------------------------------------
#include <sys/socket.h> 
#include <netpacket/packet.h> 
#include <net/ethernet.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <string>
#include <cstring>
#include <map>
#include <iostream>
#include <arpa/inet.h>


//--------------------------------------------------------------------
//------------------------ Declare Namespace -------------------------
//--------------------------------------------------------------------
using namespace std;


//--------------------------------------------------------------------
//----------------------- Function Prototypes ------------------------
//--------------------------------------------------------------------


//--------------------------------------------------------------------
//------------------------- Global Variables -------------------------
//--------------------------------------------------------------------
struct icmphdr {
  u_int8_t type; 
  u_int8_t code;
  u_int16_t checksum;
  u_int32_t data;
};

//--------------------------------------------------------------------
//------------------------ Declare Constants -------------------------
//--------------------------------------------------------------------
#define ICMP_PING 0;
#define ICMP_FWRD 1;
#define ICMP_TTLE 2;
#define ICMP_NETU 3;
#define ICMP_HSTU 4;

//--------------------------------------------------------------------
//------------------------- build_icmp_hdr ---------------------------
//--------------------------------------------------------------------
int build_icmp_hdr(int job, char *icmp_message){
  
  int ret = 0;
  
  switch(job){
  
  case ICMP_PING: // Build ping icmp
    break;
  case ICMP_FWRD: // Build forward icmp
    break;
  case ICMP_TTLE: // Build time exceeded icmp
    break;
  case ICMP_NETU: // Build network unreachable icmp
    break;
  case ICMP_HSTU: // Build host unreachable icmp
    break;

  }

  return ret;
}
