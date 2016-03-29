/**********************************************************************
 *  ip_helper.cpp
 *********************************************************************/
#include <netinet/ip.h>

//--------------------------------------------------------------------
//-------------------------- get_send_iphdr --------------------------
//--------------------------------------------------------------------
// Updates the ip header to send to the next location.
void get_send_iphdr(char * buf) {
  int bufPos = sizeof(struct ether_header);

  struct iphdr send_iphdr;

  // Copy ip header from buf
  memcpy(&send_iphdr, &buf[bufPos], sizeof(struct iphdr));

  bufPos += sizeof(struct iphdr) - sizeof(send_iphdr.saddr) - sizeof(send_iphdr.daddr);

  // Update dest addr in ip header
  memcpy(&send_iphdr.daddr, &buf[bufPos], sizeof(send_iphdr.daddr));
  bufPos += sizeof(send_iphdr.daddr);

  // Update src addr in ip header
  memcpy(&send_iphdr.saddr, &buf[bufPos], sizeof(send_iphdr.saddr));
  bufPos += sizeof(send_iphdr.saddr);

  // Copy send_iphdr into buf
  memcpy(&buf[sizeof(struct ether_header)], &send_iphdr, sizeof(struct iphdr));

  // Update icmp type in icmp header
  unsigned short int echo_reply = 0x0000;
  memcpy(&buf[bufPos], &echo_reply, sizeof(echo_reply));
}