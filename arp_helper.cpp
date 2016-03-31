/**********************************************************************
 *  arp_helper.cpp
 *********************************************************************/
#include <net/if_arp.h>
#include <arpa/inet.h>

//--------------------------------------------------------------------
//------------------------- get_send_arphdr --------------------------
//--------------------------------------------------------------------
void get_send_arphdr(char * buf, const char * mac_addr) {
  int bufPos = sizeof(struct ether_header);
  struct arphdr arp_hdr;
  char senderMac[ETH_ALEN] = {0};
  char senderIp[4] = {0};
  char targetMac[ETH_ALEN] = {0};
  char targetIp[4] = {0};

  // Get data from arp header
  memcpy(&arp_hdr, &buf[bufPos], sizeof(arp_hdr));
  bufPos += sizeof(struct arphdr);
  memcpy(senderMac, &buf[bufPos], arp_hdr.ar_hln);
  bufPos += arp_hdr.ar_hln;
  memcpy(senderIp, &buf[bufPos], arp_hdr.ar_pln);
  bufPos += arp_hdr.ar_pln;
  memcpy(targetMac, &buf[bufPos], arp_hdr.ar_hln);
  bufPos += arp_hdr.ar_hln;
  memcpy(targetIp, &buf[bufPos], arp_hdr.ar_pln);
  bufPos += arp_hdr.ar_pln;

  // Update arp type in arp header
  unsigned short int reply = 0x0200;
  arp_hdr.ar_op = reply;

  bufPos = sizeof(struct ether_header);

  memcpy(&buf[bufPos], &arp_hdr, sizeof(arp_hdr));

  // Update data to arp header
  bufPos += sizeof(struct arphdr);
  memcpy(&buf[bufPos], mac_addr, arp_hdr.ar_hln);
  bufPos += arp_hdr.ar_hln;
  memcpy(&buf[bufPos], targetIp, arp_hdr.ar_pln);
  bufPos += arp_hdr.ar_pln;
  memcpy(&buf[bufPos], senderMac, arp_hdr.ar_hln);
  bufPos += arp_hdr.ar_hln;
  memcpy(&buf[bufPos], senderIp, arp_hdr.ar_pln);
}