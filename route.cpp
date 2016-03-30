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
#include "ether_helper.cpp"
#include "arp_helper.cpp"
#include "ip_helper.cpp"


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
    struct sockaddr_ll recvaddr;
    int recvaddrlen=sizeof(struct sockaddr_ll);  
    fd_set tempSetRead = sockets; // Variable to hold ready to read sockets
    fd_set tempSetWrite = sockets;// Variable to hold ready to write to sockets

    // See what sockets are ready for read/write
    select(FD_SETSIZE, &tempSetRead, &tempSetWrite, NULL, NULL);

    // File through the open sockets
    for( i = 0; i < FD_SETSIZE; i++){

      // If index in tempSetRead is not empty the socket is ready to read
      if( FD_ISSET(i, &tempSetRead)){
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
        send_ethhdr = switch_hosts(recv_ethhdr, mac_addrs["r1-eth1"].c_str());
        memcpy(&buf, &send_ethhdr, sizeof(send_ethhdr));

        // If it is a ARP type
        if (recv_ethhdr.ether_type == 0x608) {
          printf("ethernet type: ARP\n");

          get_send_arphdr(buf, mac_addrs["r1-eth1"].c_str());

          send(packet_socket, buf, n, 0);
        } 
        else if (recv_ethhdr.ether_type == 0x0008) { // IP
          printf("ethernet type: IP\n");

          // Verify the IP checksum in the recieved packet. If incorrect, drop the packet.
	        if (check_checksum(buf)) {
	        	// Decrement the TTL.
            update_ttl(buf);

            // If the TTL becomes zero
          	if (get_ttl(buf) == 1) {
          		// send back a ICMP time exceeded (TTL exceeded) message and drop the original packet
			        
			    	} else { // Otherwise, you must recompute the IP checksum due to the changed TTL.
		        	check_checksum(buf);
	            get_send_iphdr(buf);

	            send(packet_socket, buf, n, 0);
		        }	
	        }
        }
      }
    }
  }
  //exit
  return 0;
}
