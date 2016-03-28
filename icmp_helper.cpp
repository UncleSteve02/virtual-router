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
    unsigned char data[4];
};

//--------------------------------------------------------------------
//------------------------ Declare Constants -------------------------
//--------------------------------------------------------------------
#define ICMP_PING 0
#define ICMP_PREQ 1
#define ICMP_TTLE 2
#define ICMP_NETU 3
#define ICMP_HSTU 4

//--------------------------------------------------------------------
//------------------------- build_icmp_hdr ---------------------------
//--------------------------------------------------------------------
int build_icmp_hdr(int job, char *buf) {
  int ret = 0;
  struct icmphdr icmp;

  switch(job){

  case ICMP_PING: // Build ping icmp
      icmp.type = 0;
      icmp.code = 0;
      memcpy(&buf[sizeof(struct ether_header)+sizeof(struct iphdr)], &icmp, sizeof(icmp.type) * 2);
      break;
  case ICMP_PREQ: // Build ping request icmp
      icmp.type = 8;
      icmp.code = 0;
      icmp.checksum = 0;
      memset(icmp.data, 0, sizeof(icmp.data));
      memcpy(&buf[sizeof(struct ether_header)+sizeof(struct iphdr)], &icmp, sizeof(struct icmphdr));
      // Add ip header plus 8 bytes of the data of the error message to the end of the icmp header
      memcpy(&buf[sizeof(struct ether_header)+sizeof(struct iphdr) + sizeof(struct icmphdr)], &buf[sizeof(struct ether_header)], sizeof(struct iphdr) + sizeof(char) * 8);
      break;
  case ICMP_TTLE: // Build time exceeded icmp
      icmp.type = 11;
      icmp.code = 0;
      icmp.checksum = 0;
      memset(icmp.data, 0, sizeof(icmp.data));
      memcpy(&buf[sizeof(struct ether_header)+sizeof(struct iphdr)], &icmp, sizeof(struct icmphdr));
      // Add ip header plus 8 bytes of the data of the error message to the end of the icmp header
      memcpy(&buf[sizeof(struct ether_header)+sizeof(struct iphdr) + sizeof(struct icmphdr)], &buf[sizeof(struct ether_header)], sizeof(struct iphdr) + sizeof(char) * 8);
      break;
  case ICMP_NETU: // Build network unreachable icmp
      icmp.type = 3;
      icmp.code = 0;
      icmp.checksum = 0;
      memset(icmp.data, 0, sizeof(icmp.data));
      memcpy(&buf[sizeof(struct ether_header)+sizeof(struct iphdr)], &icmp, sizeof(struct icmphdr));
      // Add ip header plus 8 bytes of the data of the error message to the end of the icmp header
      memcpy(&buf[sizeof(struct ether_header)+sizeof(struct iphdr) + sizeof(struct icmphdr)], &buf[sizeof(struct ether_header)], sizeof(struct iphdr) + sizeof(char) * 8);
      break;
  case ICMP_HSTU: // Build host unreachable icmp
      icmp.type = 3;
      icmp.code = 1;
      icmp.checksum = 0;
      memset(icmp.data, 0, sizeof(icmp.data));
      memcpy(&buf[sizeof(struct ether_header)+sizeof(struct iphdr)], &icmp, sizeof(struct icmphdr));
      // Add ip header plus 8 bytes of the data of the error message to the end of the icmp header
      memcpy(&buf[sizeof(struct ether_header)+sizeof(struct iphdr) + sizeof(struct icmphdr)], &buf[sizeof(struct ether_header)], sizeof(struct iphdr) + sizeof(char) * 8);
      break;

  } 

  return ret;
}
