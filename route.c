#include <sys/socket.h> 
#include <netpacket/packet.h> 
#include <net/ethernet.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/ip.h>
#include <net/if_arp.h>

int main(){
  int packet_socket;

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

  //loop and recieve packets. We are only looking at one interface,
  //for the project you will probably want to look at more (to do so,
  //a good way is to have one socket per interface and use select to
  //see which ones have data)
  printf("Ready to recieve now\n");
  while(1){
    char buf[1500];
    struct sockaddr_ll recvaddr;
    int recvaddrlen=sizeof(struct sockaddr_ll);
    //we can use recv, since the addresses are in the packet, but we
    //use recvfrom because it gives us an easy way to determine if
    //this packet is incoming or outgoing (when using ETH_P_ALL, we
    //see packets in both directions. Only outgoing can be seen when
    //using a packet socket with some specific protocol)
    int n = recvfrom(packet_socket, buf, 1500,0,(struct sockaddr*)&recvaddr, &recvaddrlen);
    //ignore outgoing packets (we can't disable some from being sent
    //by the OS automatically, for example ICMP port unreachable
    //messages, so we will just ignore them here)
    if(recvaddr.sll_pkttype==PACKET_OUTGOING)
      continue;
    //start processing all others
    printf("Got a %d byte packet\n", n);

    printf("sll_addr <%s>\n", recvaddr.sll_addr);
    printf("sll_protocol <%x>\n\n", recvaddr.sll_protocol);
    
    memcpy(&recv_ethhdr, &buf, sizeof(recv_ethhdr));
    printf("ether_dhost <%x>\n", recv_ethhdr.ether_dhost);
    printf("ether_shost <%x>\n", recv_ethhdr.ether_shost);
    printf("ether_type  <%x>\n\n", recv_ethhdr.ether_type);

    memcpy(send_ethhdr.ether_dhost, recv_ethhdr.ether_shost, sizeof(send_ethhdr.ether_dhost));
    memcpy(send_ethhdr.ether_shost, recv_ethhdr.ether_dhost, sizeof(send_ethhdr.ether_shost));
    send_ethhdr.ether_type = recv_ethhdr.ether_type;
    memcpy(&buf, &send_ethhdr, sizeof(send_ethhdr));

    memcpy(&recv_arphdr, &buf[sizeof(recv_ethhdr)], sizeof(recv_arphdr));
    printf("ar_hrd <%x>\n", recv_arphdr.ar_hrd);
    printf("ar_pro <%x>\n", recv_arphdr.ar_pro);
    printf("ar_hln <%x>\n", recv_arphdr.ar_hln);
    printf("ar_pln <%x>\n", recv_arphdr.ar_pln);
    printf("ar_op  <%x>\n\n", recv_arphdr.ar_op);

    unsigned short int reply = 0x0200;
    printf("reply <%x>\n\n", reply);
    recv_arphdr.ar_op = reply;

    memcpy(&buf[sizeof(recv_ethhdr)], &recv_arphdr, sizeof(recv_arphdr));

    sendto(packet_socket, buf, n,0,(struct sockaddr*)&recvaddr, sizeof(recvaddr));


    //what else to do is up to you, you can send packets with send,
    //just like we used for TCP sockets (or you can use sendto, but it
    //is not necessary, since the headers, including all addresses,
    //need to be in the buffer you are sending)

  }
  //exit
  return 0;
}
