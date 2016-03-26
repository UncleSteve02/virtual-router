/**********************************************************************
 *  ip_helper.cpp
 *********************************************************************/


//--------------------------------------------------------------------
//-------------------------------- Includes --------------------------
//--------------------------------------------------------------------
#include <stdio.h>
#include <netinet/ip.h>
#include <bitset>
// #include <bool.h>


//--------------------------------------------------------------------
//------------------------ Declare Namespace -------------------------
//--------------------------------------------------------------------
 using namespace std;


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
}

bool check_checksum(char * buf) {
 	struct iphdr ipv4_hdr;
  memcpy(&ipv4_hdr, &buf[sizeof(struct ether_header)], sizeof(ipv4_hdr));
  
  u_int16_t checksum = ipv4_hdr.check;
  ipv4_hdr.check = 0;

  memcpy(&buf[sizeof(struct ether_header)], &ipv4_hdr, sizeof(ipv4_hdr));

  u_int32_t temp_sum = 0;
  u_int16_t op1 = 0;
  u_int16_t overflow = 0;
  u_int16_t calculated_cs = 0;

  int ipv4_area = sizeof(struct ether_header) + sizeof(ipv4_hdr);
  // Add all bits in ip header
  for (int i = sizeof(struct ether_header); i < ipv4_area; i+=2) {
  	op1 = (u_int8_t) buf[i] << 8;
  	op1 += (u_int8_t) buf[i+1];
  	temp_sum += op1;
	  
	  // Set overflow
		overflow = (u_int16_t) (temp_sum >> 16);
  	
	  // Add overflow
	  temp_sum = temp_sum & 0x0000FFFF;
	  temp_sum += overflow;
  }

  // Set sum to one's compliment 
  calculated_cs = (u_int8_t) (~temp_sum >> 8) + (u_int16_t) (~temp_sum << 8);
	
	printf("calculated_cs 	<%x>\n", calculated_cs);
	printf("checksum 	<%x>\n", checksum);

	// Put correct checksum back into buffer
	ipv4_hdr.check = calculated_cs;
  memcpy(&buf[sizeof(struct ether_header)], &ipv4_hdr, sizeof(ipv4_hdr));

  return (calculated_cs == checksum);
}

//--------------------------------------------------------------------
//---------------------------- update_ttl ----------------------------
//--------------------------------------------------------------------
void update_ttl(char * buf) {
  struct iphdr ipv4_hdr;
  memcpy(&ipv4_hdr, &buf[sizeof(struct ether_header)], sizeof(ipv4_hdr));

  ipv4_hdr.ttl--;
  memcpy(&buf[sizeof(struct ether_header)], &ipv4_hdr, sizeof(ipv4_hdr));
}

//--------------------------------------------------------------------
//----------------------------- get_ttl ------------------------------
//--------------------------------------------------------------------
u_int8_t get_ttl(char * buf) {
  struct iphdr ipv4_hdr;
  memcpy(&ipv4_hdr, &buf[sizeof(struct ether_header)], sizeof(ipv4_hdr));
  return ipv4_hdr.ttl;
}
