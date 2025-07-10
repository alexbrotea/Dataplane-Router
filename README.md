# Dataplane Router

---

**main**  
In `main`, the router starts by validating the arguments, reading the routing table,  
and initializing the interfaces. Then, it sets up the queue for packets that are  
waiting for ARP resolution. After initialization, it enters the main loop, where it  
processes incoming packets on each interface.

---

**get_best_route**  
The `get_best_route` function is used to determine the best route using the  
Longest Prefix Match algorithm. It checks each entry in the routing table and  
returns the one with the longest matching prefix for the destination IP.

---

**get_arp_entry**  
The `get_arp_entry` function looks for a MAC address associated with a given IP  
in the dynamic ARP table. If the MAC is not found, it triggers the need for  
an ARP request.

---

**send_arp_request**  
This function builds and sends a broadcast ARP request to resolve the MAC address  
for a specific IP. Meanwhile, the current packet is added to the waiting queue  
so it can be sent later when the MAC is known.

---

**send_arp_reply**  
When the router receives an ARP request for its own IP, this function constructs  
a reply by reversing the IP and MAC addresses and sending the packet on the  
correct interface.

---

**packet_wait**  
The `packet_wait` structure is used to save packets that cannot yet be sent because  
the destination MAC address is unknown. These packets are stored in the  
`waiting_queue`.

---

**send_icmp_echo_reply**  
When an ICMP Echo Request is received and the destination IP is one of the router's,  
this function creates an ICMP Echo Reply by reversing addresses and recalculating  
checksums.

---

**send_icmp_error**  
This function constructs an ICMP error message such as Time Exceeded or Destination  
Unreachable. It includes the original IP header and the first 8 bytes of the payload.

---

**forward_packet**  
In `forward_packet`, the MAC addresses in the Ethernet header are updated and  
the packet is sent out on the correct interface if the destination MAC is known.

---

**try_sending_waiting_packets**  
After receiving an ARP reply and updating the ARP table, this function checks  
the waiting queue for packets addressed to that IP. If found, it sends them  
using `forward_packet`. If not, they remain in the queue.
