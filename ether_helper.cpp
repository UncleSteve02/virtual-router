/**********************************************************************
 *  ether_helper.cpp
 *********************************************************************/
#include <net/ethernet.h>

struct ether_header switch_hosts(struct ether_header receive, const char * mac_addr) {
  struct ether_header send_ethhdr;

  memcpy(send_ethhdr.ether_dhost, receive.ether_shost, sizeof(send_ethhdr.ether_dhost));
  memcpy(send_ethhdr.ether_shost, mac_addr, sizeof(send_ethhdr.ether_shost));
  send_ethhdr.ether_type = receive.ether_type;

  return send_ethhdr;
}

void set_eth_addrs(char *buf, const char * dst_addr, const char * src_addr) {
  struct ether_header eth_hdr;

  memcpy(&eth_hdr, &buf, sizeof(struct ether_header));

  // eth_hdr.ether_dhost = dst_addr;
  // eth_hdr.ether_shost = src_addr;

  memcpy(eth_hdr.ether_dhost, dst_addr, sizeof(eth_hdr.ether_dhost));
  memcpy(eth_hdr.ether_shost, src_addr, sizeof(eth_hdr.ether_shost));

  memcpy(&buf, &eth_hdr, sizeof(struct ether_header));
}

void get_src_addr(char *buf, char *dst_addr) {
  memcpy(&dst_addr, &buf[sizeof(dst_addr)], sizeof(dst_addr));
}