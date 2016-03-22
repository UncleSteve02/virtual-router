/*
 *  CS 457 Project 3 - Virtual Router
 *  Travis Page & Steven Demers
 *  3/22/16 - Part 1
 *
 */

#include <sys/socket.h> 
#include <netpacket/packet.h> 
#include <net/ethernet.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <string>
#include <cstring>
#include <map>
#include <iostream>

using namespace std;

int main(){
  int packet_socket;

  map<string, string> mac_addrs;

  struct arphdr recv_arphdr;
  struct ether_header recv_ethhdr;
  struct ether_header send_ethhdr;
  //get list of interfaces (actually addresses)
  struct ifaddrs *ifaddr, *tmp;
  if(getifaddrs(&ifaddr)==-1){
    perror("getifaddrs");
    return 1;
  }
  //have the list, loop over the list
  for(tmp = ifaddr; tmp!=NULL; tmp=tmp->ifa_next){
    string sa_data = string(tmp->ifa_addr->sa_data);

    struct sockaddr_in* new_sockaddr_in = (struct sockaddr_in*) tmp->ifa_addr;

    struct sockaddr_ll* new_sockaddr_ll = (struct sockaddr_ll*) tmp->ifa_addr;

    string sll_addr = string((const char*)new_sockaddr_ll->sll_addr);

    mac_addrs.insert(pair<string, string>(tmp->ifa_name, sll_addr));

    //Check if this is a packet address, there will be one per
    //interface.  There are IPv4 and IPv6 as well, but we don't care
    //about those for the purpose of enumerating interfaces. We can
    //use the AF_INET addresses in this list for example to get a list
    //of our own IP addresses
    if(tmp->ifa_addr->sa_family==AF_PACKET){
      printf("Interface: %s\n",tmp->ifa_name);
      //create a packet socket on interface r?-eth1
      if(!strncmp(&(tmp->ifa_name[3]),"eth1",4)){
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
  printf("Ready to recieve now\n");
  while(1){
    char buf[1500];
    char senderMac[ETH_ALEN] = {0};
    char senderIp[4] = {0};
    char targetMac[ETH_ALEN] = {0};
    char targetIp[4] = {0};
    struct sockaddr_ll recvaddr;
    int recvaddrlen=sizeof(struct sockaddr_ll);
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

    memcpy(send_ethhdr.ether_dhost, recv_ethhdr.ether_shost, sizeof(send_ethhdr.ether_dhost));
    memcpy(send_ethhdr.ether_shost, mac_addrs["r1-eth1"].c_str(), sizeof(send_ethhdr.ether_shost));
    send_ethhdr.ether_type = recv_ethhdr.ether_type;
    memcpy(&buf, &send_ethhdr, sizeof(send_ethhdr));

    // If it is a ARP type
    if (recv_ethhdr.ether_type == 0x608) {
      int bufPos;
     
      // Get data from arp header
      memcpy(&recv_arphdr, &buf[sizeof(recv_ethhdr)], sizeof(recv_arphdr));
      bufPos = sizeof(struct ether_header) + sizeof(struct arphdr);
      memcpy(senderMac, &buf[bufPos], recv_arphdr.ar_hln);
      bufPos += recv_arphdr.ar_hln;
      memcpy(senderIp, &buf[bufPos], recv_arphdr.ar_pln);
      bufPos += recv_arphdr.ar_pln;
      memcpy(targetMac, &buf[bufPos], recv_arphdr.ar_hln);
      bufPos += recv_arphdr.ar_hln;
      memcpy(targetIp, &buf[bufPos], recv_arphdr.ar_pln);
      bufPos += recv_arphdr.ar_pln;
     
      // Update arp type in arp header
      unsigned short int reply = 0x0200;
      recv_arphdr.ar_op = reply;

      memcpy(&buf[sizeof(recv_ethhdr)], &recv_arphdr, sizeof(recv_arphdr));

      // Update data to arp header
      bufPos = sizeof(struct ether_header) + sizeof(struct arphdr);
      memcpy(&buf[bufPos], mac_addrs["r1-eth1"].c_str(), recv_arphdr.ar_hln);
      bufPos += recv_arphdr.ar_hln;
      memcpy(&buf[bufPos], targetIp, recv_arphdr.ar_pln);
      bufPos += recv_arphdr.ar_pln;
      memcpy(&buf[bufPos], senderMac, recv_arphdr.ar_hln);
      bufPos += recv_arphdr.ar_hln;
      memcpy(&buf[bufPos], senderIp, recv_arphdr.ar_pln);

      send(packet_socket, buf, n, 0);
    } else if (recv_ethhdr.ether_type == 0x0008) { // IP
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

      send(packet_socket, buf, n, 0);
    }

    //what else to do is up to you, you can send packets with send,
    //just like we used for TCP sockets (or you can use sendto, but it
    //is not necessary, since the headers, including all addresses,
    //need to be in the buffer you are sending)

  }
  //exit
  return 0;
}
