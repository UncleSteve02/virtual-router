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