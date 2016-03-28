/**********************************************************************
 *  CS 457 Project 3 - Virtual Router
 *  Travis Page & Steven Demers
 *  4/1/16 - Part 3
 *
 *********************************************************************/


//--------------------------------------------------------------------
//-------------------------------- Includes --------------------------
//--------------------------------------------------------------------
#include <sys/socket.h> 
#include <netpacket/packet.h> 
#include <net/ethernet.h>
#include <stdio.h>
#include <unistd.h>
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
#include <thread>
#include <arpa/inet.h>
#include "ether_helper.cpp"
#include "arp_helper.cpp"
#include "ip_helper.cpp"
#include "icmp_helper.cpp"


//--------------------------------------------------------------------
//------------------------ Declare Namespace -------------------------
//--------------------------------------------------------------------
using namespace std;


//--------------------------------------------------------------------
//------------------------ Declare Constants -------------------------
//--------------------------------------------------------------------
#define ICMP_PING 0
#define ICMP_PREQ 1
#define ICMP_TTLE 2
#define ICMP_NETU 3
#define ICMP_HSTU 4


//--------------------------------------------------------------------
//----------------------- Function Prototypes ------------------------
//--------------------------------------------------------------------
string get_router_name(void);
bool is_for_me(string ip);
int get_routing_table_ref(char *router_name, char *dest_ip, char *interface_name, char *arp_ip);
int get_mac_addr(char *interface_name, char* arp_ip, u_int8_t *dest_mac);



//--------------------------------------------------------------------
//------------------------- Global Variables -------------------------
//--------------------------------------------------------------------
map<string, string> mac_addrs;
map<string, string> ip_addrs;
string interfaces[FD_SETSIZE];


//--------------------------------------------------------------------
//--------------------------- Main Function --------------------------
//--------------------------------------------------------------------
int main(){
  int packet_socket;
  fd_set sockets;	// Create a set of file descriptors
  FD_ZERO(&sockets);	// Initialize the to an empty set
  struct ether_header recv_ethhdr;
  struct ether_header send_ethhdr;
  int i = 0;
  int err = 0;

  //get list of interfaces (actually addresses)
  struct ifaddrs *ifaddr, *tmp;
  if(getifaddrs(&ifaddr)==-1){
    perror("getifaddrs");
    return 1;
  }

  //have the list, loop over the list
  for(tmp = ifaddr; tmp!=NULL; tmp=tmp->ifa_next){
    string sa_data = string(tmp->ifa_addr->sa_data);

    // Save off the ip address for each interface
    if(tmp->ifa_addr->sa_family==AF_INET){
      if( strstr(tmp->ifa_name, "eth")){ // we only want the ethernet interfaces

        struct sockaddr_in* new_sockaddr_in = (struct sockaddr_in*) tmp->ifa_addr;
        string sin_addr = string(inet_ntoa(new_sockaddr_in->sin_addr));
        ip_addrs.insert(pair<string, string>(tmp->ifa_name, sin_addr));
      }
    }


    //Check if this is a packet address, there will be one per
    //interface.  There are IPv4 and IPv6 as well, but we don't care
    //about those for the purpose of enumerating interfaces. We can
    //use the AF_INET addresses in this list for example to get a list
    //of our own IP addresses
    if(tmp->ifa_addr->sa_family==AF_PACKET){
      if( strstr(tmp->ifa_name, "eth")){ // we only want the ethernet interfaces
        printf("Interface: %s\n",tmp->ifa_name);

        printf("Creating Socket on interface %s\n",tmp->ifa_name);

        //create a packet socket
        //AF_PACKET makes it a packet socket
        //SOCK_RAW makes it so we get the entire packet
        //could also use SOCK_DGRAM to cut off link layer header
        //ETH_P_ALL indicates we want all (upper layer) protocols
        //we could specify just a specific one
        packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if(packet_socket<0){
          perror("socket");
          return 2;
        }

        //Bind the socket to the address, so we only get packets
        //recieved on this specific interface. For packet sockets, the
        //address structure is a struct sockaddr_ll (see the man page
        //for "packet"), but of course bind takes a struct sockaddr.
        //Here, we can use the sockaddr we got from getifaddrs (which
        //we could convert to sockaddr_ll if we needed to)
        if(bind(packet_socket,tmp->ifa_addr,sizeof(struct sockaddr_ll))==-1){
          perror("bind");
        }

        FD_SET(packet_socket, &sockets); // Add a file descriptor to the set

        // Save so there is a reference between the socket number and the interface
        interfaces[packet_socket] = tmp->ifa_name;   

        // Save off the mac address of each interface
        struct sockaddr_ll* new_sockaddr_ll = (struct sockaddr_ll*) tmp->ifa_addr;
        string sll_addr = string((const char*)new_sockaddr_ll->sll_addr);
        mac_addrs.insert(pair<string, string>(tmp->ifa_name, sll_addr));
      }
    }
  }

  //free the interface list when we don't need it anymore
  freeifaddrs(ifaddr);

  for (map<string, string>::iterator it=mac_addrs.begin(); it!=mac_addrs.end(); ++it)
    cout << it->first << " => " << it->second << '\n';

  for(int i = 0; i < 6; i++)
    printf("%02x:", mac_addrs["r1-eth1"].c_str()[i]);



  //loop and recieve packets. We are only looking at one interface,
  //for the project you will probably want to look at more (to do so,
  //a good way is to have one socket per interface and use select to
  //see which ones have data)
  printf("\nReady to recieve now\n");
  while(1){
    char buf[1500];
    char arp_ip[32];
    struct sockaddr_ll recvaddr;
    int recvaddrlen=sizeof(struct sockaddr_ll);  
    fd_set tempSetRead = sockets; // Variable to hold ready to read sockets
    fd_set tempSetWrite = sockets;// Variable to hold ready to write to sockets
    char interface_name[64];
    u_int8_t dest_mac[ETH_ALEN];
    struct iphdr tmp_iphdr;


    // See what sockets are ready for read/write
    select(FD_SETSIZE, &tempSetRead, &tempSetWrite, NULL, NULL);

    // File through the open sockets
    for (i = 0; i < FD_SETSIZE; i++){

      // If index in tempSetRead is not empty the socket is ready to read
      if (FD_ISSET(i, &tempSetRead)){
        packet_socket = i;

        //we can use recv, since the addresses are in the packet, but we
        //use recvfrom because it gives us an easy way to determine if
        //this packet is incoming or outgoing (when using ETH_P_ALL, we
        //see packets in both directions. Only outgoing can be seen when
        //using a packet socket with some specific protocol)
        int n = recvfrom(packet_socket, buf, 1500, 0, (struct sockaddr*)&recvaddr, (socklen_t*)&recvaddrlen);

        //ignore outgoing packets (we can't disable some from being sent
        //by the OS automatically, for example ICMP port unreachable
        //messages, so we will just ignore them here)
        if(recvaddr.sll_pkttype==PACKET_OUTGOING)
          continue;

        //start processing all others
        printf("Got a %d byte packet\n", n);

        memcpy(&recv_ethhdr, &buf, sizeof(recv_ethhdr));
        send_ethhdr = switch_hosts(recv_ethhdr, mac_addrs[interfaces[packet_socket]].c_str());
        memcpy(&buf, &send_ethhdr, sizeof(send_ethhdr));

        // If it is a ARP type
        if (recv_ethhdr.ether_type == 0x608) {
          printf("ethernet type: ARP\n");

          get_send_arphdr(buf, mac_addrs[interfaces[packet_socket]].c_str());

          send(packet_socket, buf, n, 0);
        } 
        else if (recv_ethhdr.ether_type == 0x0008) { // IP
          printf("ethernet type: IP\n");

          // Verify the IP checksum in the recieved packet. If incorrect, drop the packet.
          if (check_checksum(buf)) {
            // Decrement the TTL.
            update_ttl(buf);

            // If the TTL becomes zero
            if (get_ttl(buf) == 0) {
              // send back a ICMP time exceeded (TTL exceeded) message and drop the original packet
              build_icmp_hdr(ICMP_TTLE, buf);

            } else { // Otherwise, you must recompute the IP checksum due to the changed TTL.
              if (is_for_me(get_dst_ip(buf))) {
<<<<<<< HEAD
                printf("its all mine!\n");
		memcpy(&tmp_iphdr, &buf[sizeof(struct ether_header)], sizeof(struct iphdr)); 
		// ckeck to see if it is a ping if not then do nothing 
		if( tmp_iphdr.protocol != 0x01 ||  buf[sizeof(struct ether_header)+sizeof(struct iphdr)] != 0x08){
		    continue;
		}
		// If it is a ping reformate the ip head and icmp header 
		build_icmp_hdr(ICMP_PING, buf);
              	get_send_iphdr(buf);
		strcpy(interface_name, interfaces[packet_socket].c_str());
=======
                memcpy(&tmp_iphdr, &buf[sizeof(struct ether_header)], sizeof(struct iphdr)); 
                // ckeck to see if it is a ping if not then do nothing 
                if( tmp_iphdr.protocol != 0x01){
                  continue;
                }
                // If it is a ping reformate the ip head and icmp header 
                build_icmp_hdr(ICMP_PING, buf);
                get_send_iphdr(buf);
                strcpy(interface_name, interfaces[packet_socket].c_str());
>>>>>>> 2bcab123354f91846b1b8c6314ff87300c650ddc
              } else {
                // Check routing table and get interface and ip 
                err = get_routing_table_ref((char *)get_router_name().c_str(), (char *)get_dst_ip(buf).c_str(), interface_name, arp_ip);
                if (err == 0) {
                  // Build ARP packet to get mac address of next location
                  err = get_mac_addr(interface_name, arp_ip, dest_mac);
                  if (err == 0) {
                    // Up ethernet header to contain the found mac address
                    set_eth_addrs(buf, dest_mac, mac_addrs[interface_name].c_str());
                  } else { // If there was an error send the proper icmp message
                    build_icmp_hdr(ICMP_HSTU, buf);
                  }

                } else { // If there was an error send the proper icmp message
                  printf("Got an error from the routing table\n");
                  build_icmp_hdr(ICMP_NETU, buf);
                  printf("%x\n", buf[sizeof(struct ether_header)+sizeof(struct iphdr)]);
                }
              }

              check_checksum(buf);

              // Send  message 
              for( int i = 0; i < FD_SETSIZE; i++){

                if( strlen(interfaces[i].c_str()) > 0){

                  if(! strcmp(interfaces[i].c_str(), interface_name)){
                    send(i, buf, n, 0);
                    break;
                  }
                }
              }
            }	
          }
        }
      }
    }
  }
  //exit
  return 0;
}

string get_router_name(void) {
  for (const string &interface : interfaces) {
    if (!interface.empty()) {
      return interface.substr(0, interface.find("-"));
    }
  }
  return NULL;
}

bool is_for_me(string ip) {
  for (map<string, string>::iterator it = ip_addrs.begin(); it != ip_addrs.end(); ++it) {
    if (ip.compare(it->second) == 0) {
      return true;
    }
  }
  return false;
}

int get_routing_table_ref(char *router_name, char *dest_ip, char *interface_name, char *arp_ip){

  int ret = 0;
  int found = 0;
  int ip1, ip2, ip3, ip4, prfx_len;
  int ip5, ip6, ip7, ip8;
  FILE *fp;
  char temp_str[512];
  char ip_prefix[32];
  char ip_addr[32];
  char interface[32];
  char *ptr;
  char *temp_ptr;

  // Open the correct routing table file
  sprintf(temp_str, "%s-table.txt", router_name);
  fp = fopen(temp_str, "r");
  if (fp != NULL) {

    // Parse through the routing table file
    while(fgets( temp_str, 512, fp) != NULL){

      // Parse through each line
      ptr = strstr(temp_str, " ");
      strncpy(ip_prefix, temp_str, strlen(temp_str) - strlen(ptr));
      ip_prefix[strlen(temp_str) - strlen(ptr)] = 0;

      temp_ptr = strstr(ptr + 1, " ");
      strncpy(ip_addr, ptr + 1, strlen(ptr + 1) - strlen(temp_ptr));
      ip_addr[strlen(ptr + 1) - strlen(temp_ptr)] = 0;

      strcpy(interface, temp_ptr + 1);

      // Replace new line character
      ptr = strstr(interface, "\n");
      ptr[0] = 0;

      // Get the ip numbers out of each ip addrs
      sscanf(ip_prefix,"%d.%d.%d.%d/%d", &ip1, &ip2, &ip3, &ip4, &prfx_len);
      sscanf(dest_ip,"%d.%d.%d.%d", &ip5, &ip6, &ip7, &ip8);
      printf("%s %s %s\n", ip_prefix, ip_addr, interface);

      // Check if the dest_ip matches the ip_prefix if it does break out of loop
      if( ip1 == ip5 && ip2 ==  ip6 && ip3 == ip7){
        found = 1;
        break;
      }
      found = 0;

    }

    fclose(fp);
  } else {
    ret = -1;
  }

  if( found == 1){
    strcpy(interface_name, interface);

    // If no ip address was found then use the dest_ip
    if( !strcmp(ip_addr, "-")){
      strcpy(arp_ip, dest_ip);
    }
    // If a ip address was found then use that 
    else{
      strcpy(arp_ip, ip_addr);
    }

  }
  else{
    ret = -1;
  }

  return ret;
}

void receive_packet(int *n, int i, char *buf) {
  struct sockaddr_ll recvaddr;
  int recvaddrlen=sizeof(struct sockaddr_ll);  

  int temp_n = recvfrom(i, buf, 1500, 0, (struct sockaddr*)&recvaddr, (socklen_t*)&recvaddrlen);

  memcpy(n, &temp_n, sizeof(temp_n));
}

int get_mac_addr(char *interface_name, char* arp_ip, u_int8_t *dest_mac){
  int ret = 0;
  int bufPos = 0;
  struct ether_header send_ethhdr;
  struct arphdr arp_hdr;
  char buf[1500];
  struct sockaddr_in ipaddr;

  // Build ethernet header
  unsigned char mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  memcpy(send_ethhdr.ether_dhost, mac, sizeof(send_ethhdr.ether_dhost));
  memcpy(send_ethhdr.ether_shost, mac_addrs[interface_name].c_str(), sizeof(send_ethhdr.ether_shost));
  send_ethhdr.ether_type = 0x608;
  memcpy(buf, &send_ethhdr, sizeof(struct ether_header));
  bufPos = sizeof(struct ether_header);

  // Build arp header
  arp_hdr.ar_hrd = 0x0100;
  arp_hdr.ar_pro = 0x0008;
  arp_hdr.ar_hln = 0x06;
  arp_hdr.ar_pln = 0x04;
  arp_hdr.ar_op = 0x0100;
  memcpy(&buf[bufPos], &arp_hdr, sizeof(struct arphdr));

  unsigned char target_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  // Add arp Data
  bufPos += sizeof(struct arphdr);
  memcpy(&buf[bufPos], mac_addrs[interface_name].c_str(), arp_hdr.ar_hln);
  bufPos += arp_hdr.ar_hln;
  ipaddr.sin_addr.s_addr = inet_addr(ip_addrs[interface_name].c_str());
  memcpy(&buf[bufPos], &ipaddr.sin_addr.s_addr, sizeof(ipaddr.sin_addr.s_addr));
  bufPos += arp_hdr.ar_pln;
  memcpy(&buf[bufPos], target_mac, arp_hdr.ar_hln);
  bufPos += arp_hdr.ar_hln;
  ipaddr.sin_addr.s_addr = inet_addr(arp_ip);
  memcpy(&buf[bufPos], &ipaddr.sin_addr.s_addr, sizeof(ipaddr.sin_addr.s_addr));
  bufPos += arp_hdr.ar_pln;

  // Send arp message 
  int i;
  for (i = 0; i < FD_SETSIZE; i++) {
    if (strlen(interfaces[i].c_str()) > 0) {
      if (!strcmp(interfaces[i].c_str(), interface_name)) {
        ret = send(i, buf, bufPos, 0);
        break;
      }
    }
  }

  // Wait one second if nothing is recieved return error
  int n = 0;
  clock_t one_sec_from_now;
  one_sec_from_now = clock() + CLOCKS_PER_SEC; // Set to one second from now

  thread receive (receive_packet, &n, i, buf);
  while (clock() < one_sec_from_now && n == 0);
  receive.detach();

  if (n > 0) {
    ret = 0;
  } else {
    ret = -1;
  }

  // Read arp reply and get mac address
  memcpy(dest_mac, &buf[ETH_ALEN], ETH_ALEN);

  return ret;
}
