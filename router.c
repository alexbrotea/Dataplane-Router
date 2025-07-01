#include "protocols.h"
#include "queue.h"
#include "lib.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define MAX_RT_ENTRIES 100000
#define MAX_ARP_ENTRIES 10000

#define ICMP_ECHO_REQUEST 8
#define ICMP_DEST_UNREACH 3
#define ICMP_TIME_EXCEEDED 11
#define ETHER_ADDR_LEN 6

#define MAX_PACHET_ATTEMPTS 1000000

static struct route_table_entry rtable[MAX_RT_ENTRIES];
static int rtable_len;

struct arp_dynamic {
    uint32_t ip;
    uint8_t  mac[6];
}; // am definit aceasta structura pentru intrarea ARP-ului, fara fisier pentru ARP

static struct arp_dynamic arp_table[MAX_ARP_ENTRIES];
static int arp_table_len = 0;

struct packet_wait {
    char buf[MAX_PACKET_LEN];
    size_t len;
    int iface;
    uint32_t next_hop;
}; // aceasta structura am creat-o special pentru a astepta ARP-ul

static queue waiting_queue; // coada pentru pachetele ce asteapta ARP-ul

static struct arp_dynamic *get_arp_entry(uint32_t ip) {
    for (int i = 0; i < arp_table_len; i++) {
        if (arp_table[i].ip == ip) { // aici am prelucrat din laboratorul 4 de la PCom, cel cu router,
            return &arp_table[i]; // transformand ARP-ul static intr-unul dinamic si ii fac citirea
        }
    }
    return NULL;
}

static void add_arp_entry(uint32_t ip, const uint8_t mac[6]) {
    int found_index = -1;

    for (int i = 0; i < arp_table_len; i++) {
        if (arp_table[i].ip == ip) {
            found_index = i; // aici caut in tabel intrarea existenta
            break;
        }
    }

    if (found_index != -1) {
        memcpy(arp_table[found_index].mac, mac, 6); // daca am gasit intrarea, actualizez MAC-ul
    } else if (arp_table_len < MAX_ARP_ENTRIES) {
        arp_table[arp_table_len].ip = ip;
        memcpy(arp_table[arp_table_len].mac, mac, 6); // daca nu gasesc, adaug o noua intrare
        arp_table_len++;
    }
}

static struct route_table_entry *get_best_route(uint32_t dest_ip) {
    struct route_table_entry *best = NULL;
    uint32_t longest_prefix = 0; // realizez procesul de cautare prin best route cu ajutorul algoritmului LPM

    for (int i = 0; i < rtable_len; i++) {
        uint32_t mask = rtable[i].mask;
        uint32_t prefix = rtable[i].prefix; // iterez prin toata tabela de rutare

        if ((dest_ip & mask) != prefix) {
            continue;
        } // verific daca adresa se potriveste cu prefixul

        if (ntohl(mask) <= ntohl(longest_prefix)) {
            continue;
        } // altfel, deja exista un prefix mai lung sau egal

        longest_prefix = mask;
        best = &rtable[i]; // daca s-a gasit un prefix mai lung, actualizez ruta
    }
    return best; // in final, se returneaza cea mai buna ruta gasita
}


static void send_arp_request(uint32_t next_hop_ip, int out_iface) {
    char packet[MAX_PACKET_LEN];
    memset(packet, 0, MAX_PACKET_LEN); // trimit requestul pentru ARP

    struct ether_hdr *eth = (struct ether_hdr *)packet;
    memset(eth->ethr_dhost, 0xFF, 6);
    get_interface_mac(out_iface, eth->ethr_shost);
    eth->ethr_type = htons(0x0806); // initializez pachetul si il setez ca ARP

    uint8_t *hdr_ptr = (uint8_t *)packet + sizeof(struct ether_hdr);
    struct arp_hdr *arph = (struct arp_hdr *)hdr_ptr; // calculez offestul catre headerul ARP

    memset(arph, 0, sizeof(struct arp_hdr));

    arph->hw_type = htons(1);
    arph->proto_type = htons(0x0800);
    arph->hw_len = ETHER_ADDR_LEN; // initializarea campurilor pentru header
    arph->proto_len = sizeof(uint32_t);
    arph->opcode = htons(1);

    get_interface_mac(out_iface, arph->shwa);

    const char *iface_ip = get_interface_ip(out_iface); // obtin adresa IP de la interfata
    arph->sprotoa = inet_addr(iface_ip); // realizez atribuirea catre campul sursa

    memset(arph->thwa, 0, sizeof(arph->thwa));

    arph->tprotoa = next_hop_ip; // salvez intr-o noua variabila adresa IP

    size_t len = sizeof(struct ether_hdr) + sizeof(struct arp_hdr); // aflu lungimea finala a pachetului
    send_to_link(len, packet, out_iface); // trimit la legatura pentru out_iface
}

static void send_arp_reply(const char *old_buf, int in_iface) {
    const uint8_t *packet_data = (const uint8_t *)old_buf;
    const struct ether_hdr *old_eth = (const struct ether_hdr *)packet_data; // extrag headerul original

    packet_data += sizeof(struct ether_hdr);
    const struct arp_hdr *old_arp = (const struct arp_hdr *)packet_data; // ajung la headerul de la ARP

    char packet[MAX_PACKET_LEN];
    memset(packet, 0, MAX_PACKET_LEN); // construiesc un nou buffer pentru reply

    struct ether_hdr *eth = (struct ether_hdr *)packet;
    memcpy(eth->ethr_dhost, old_eth->ethr_shost, 6);
    get_interface_mac(in_iface, eth->ethr_shost); // initializari Ethernet
    eth->ethr_type = htons(0x0806);

    struct arp_hdr *arph = (struct arp_hdr *)(packet + sizeof(struct ether_hdr));
    arph->hw_type = htons(1); // initializari ARP
    uint16_t proto_ipv4 = 0x0800;
    arph->proto_type = htons(proto_ipv4);

    arph->hw_len = sizeof(arph->shwa);
    arph->proto_len = sizeof(uint32_t);
    uint16_t arp_reply_code = 2;
    arph->opcode = htons(arp_reply_code);

    uint8_t mac_buffer[6];
    get_interface_mac(in_iface, mac_buffer);
    memcpy(arph->shwa, mac_buffer, sizeof(mac_buffer)); // obtin adresa MAC a interfetei

    arph->sprotoa = inet_addr(get_interface_ip(in_iface));
    memcpy(arph->thwa, old_arp->shwa, 6); // copiez adresa in campul corespunzator
    arph->tprotoa = old_arp->sprotoa;

    size_t len = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
    send_to_link(len, packet, in_iface);
}

static void send_icmp_echo_reply(const char *old_buf, size_t old_len, int iface) {
    const uint8_t *data_ptr = (const uint8_t *)old_buf;
    const struct ether_hdr *old_eth = (const struct ether_hdr *)data_ptr; // fac din nou o extragere

    data_ptr += sizeof(struct ether_hdr);
    const struct ip_hdr *old_ip = (const struct ip_hdr *)data_ptr; // analog cu ARP, acum ajung la IP

    data_ptr += sizeof(struct ip_hdr);
    const struct icmp_hdr *old_icmp = (const struct icmp_hdr *)data_ptr; // la fel si cu ICMP

    size_t ip_len = ntohs(old_ip->tot_len); // dimensiunea IP
    size_t icmp_len = ip_len - sizeof(struct ip_hdr); // dimensiunea ICMP

    char packet[MAX_PACKET_LEN];
    memset(packet, 0, MAX_PACKET_LEN); // din nou, fac un buffer pentru reply

    struct ether_hdr *eth = (struct ether_hdr *)packet; // initializari Ethernet
    memcpy(eth->ethr_dhost, old_eth->ethr_shost, 6);
    get_interface_mac(iface, eth->ethr_shost);
    eth->ethr_type = htons(0x0800);

    struct ip_hdr *ip = (struct ip_hdr *)(packet + sizeof(struct ether_hdr));
    ip->ihl = 5;
    ip->ver = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct ip_hdr) + icmp_len);
    ip->id = old_ip->id;
    ip->frag = 0;
    ip->ttl = 64; // initializari IP
    ip->proto = 1;
    ip->checksum = 0;
    ip->source_addr = old_ip->dest_addr;
    ip->dest_addr = old_ip->source_addr;

    uint16_t ipchk = checksum((uint16_t *)ip, sizeof(struct ip_hdr)); // calculez checksumul pentru IP
    ip->checksum = htons(ipchk);

    struct icmp_hdr *icmp = (struct icmp_hdr *)((uint8_t *)ip + sizeof(struct ip_hdr));
    memcpy(icmp, old_icmp, icmp_len);
    icmp->mtype = 0;
    icmp->check = 0; // initializari ICMP
    uint16_t icmpchk = checksum((uint16_t *)icmp, icmp_len);
    icmp->check = htons(icmpchk);

    size_t send_len = sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + icmp_len;
    send_to_link(send_len, packet, iface);
}

static void send_icmp_error(const char *old_buf, size_t old_len, int iface, uint8_t type, uint8_t code) {
    const uint8_t *raw_ptr = (const uint8_t *)old_buf;
    const struct ether_hdr *old_eth = (const struct ether_hdr *)raw_ptr; // extrag Ethernet din bufferul vechi

    const struct ip_hdr *old_ip = (const struct ip_hdr *)(raw_ptr + sizeof(struct ether_hdr)); // calculare offset

    char packet[MAX_PACKET_LEN];
    memset(packet, 0, MAX_PACKET_LEN);

    struct ether_hdr *eth = (struct ether_hdr *)packet;
    memcpy(eth->ethr_dhost, old_eth->ethr_shost, 6);
    get_interface_mac(iface, eth->ethr_shost);
    eth->ethr_type = htons(0x0800);

    uint16_t ipv4_type = 0x0800;
    eth->ethr_type = htons(ipv4_type); // setez la IPv4

    uint8_t *ip_start = (uint8_t *)packet + sizeof(struct ether_hdr);
    struct ip_hdr *ip = (struct ip_hdr *)ip_start;

    memset(ip, 0, sizeof(struct ip_hdr));

    ip->ver = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(56);
    ip->id = 0;
    ip->frag = 0;
    ip->ttl = 64;
    ip->proto = 1;
    ip->checksum = 0;
    ip->source_addr = old_ip->dest_addr; 
    ip->dest_addr = old_ip->source_addr;

    uint16_t ipchk = checksum((uint16_t *)ip, sizeof(struct ip_hdr));
    ip->checksum = htons(ipchk);

    uint8_t *icmp_start = (uint8_t *)ip + sizeof(struct ip_hdr);
    struct icmp_hdr *icmp_hdr_ptr = (struct icmp_hdr *)icmp_start; // aflu adresa de start de la ICMP

    icmp_hdr_ptr->mtype = type;
    icmp_hdr_ptr->mcode = code;
    icmp_hdr_ptr->check = 0;

    icmp_hdr_ptr->un_t.echo_t.id = 0;
    icmp_hdr_ptr->un_t.echo_t.seq = 0;

    uint8_t *data_ptr = (uint8_t *)icmp_hdr_ptr + sizeof(struct icmp_hdr); // copiez headerul original si mai adaug 8 bytes
    size_t to_copy = 28;
    size_t old_ip_len = old_len - sizeof(struct ether_hdr);
    if (to_copy > old_ip_len) {
        to_copy = old_ip_len;
    }
    
    memcpy(data_ptr, old_ip, to_copy);

    uint16_t icmp_len = sizeof(struct icmp_hdr) + to_copy;
    uint16_t icmpchk = checksum((uint16_t *)icmp_hdr_ptr, icmp_len);
    icmp_hdr_ptr->check = htons(icmpchk); // calculez checksumul

    size_t send_len = sizeof(struct ether_hdr) + ntohs(ip->tot_len);
    send_to_link(send_len, packet, iface);
}

static void forward_packet(char *buf, size_t len, int out_iface, const uint8_t *dst_mac) {
    struct ether_hdr *eth = (struct ether_hdr *)buf;
    memcpy(eth->ethr_dhost, dst_mac, 6);
    get_interface_mac(out_iface, eth->ethr_shost); // dau forwarding pentru IP la Ethernet
    send_to_link(len, buf, out_iface);
}

static void try_sending_waiting_packets(uint32_t ip) {
    int cnt = 0;
    while (!queue_empty(waiting_queue) && cnt < MAX_PACHET_ATTEMPTS) {
        struct packet_wait *pw = (struct packet_wait *)queue_deq(waiting_queue); // cat timp nu e goala coada, ii scot primul pachet
        cnt++;
        if (pw->next_hop == ip) {
            struct arp_dynamic *ae = get_arp_entry(ip);
            forward_packet(pw->buf, pw->len, pw->iface, ae->mac); // verific daca pachetul are IP-ul asteptat si dupa il trimit mai departe
            free(pw);
        } else {
            queue_enq(waiting_queue, pw); // daca n-am gasit inca pachetul dorit, ma intorc
        }
    }
}

int main(int argc, char *argv[]) {
    void validate_args(int argc, char *argv[]) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s <rtable file> <interfaces>...\n", argv[0]); // validarea argumentelor
            exit(1);
        }
    }
    validate_args(argc, argv);
    
    rtable_len = read_rtable(argv[1], rtable);
    DIE(rtable_len <= 0, "Cannot read rtable");

    // Do not modify this line
    init(argv + 2, argc - 2);

    waiting_queue = create_queue();

    while (1) {
        char buf[MAX_PACKET_LEN];
        size_t len;

        int interface = recv_from_any_link(buf, &len);
        DIE(interface < 0, "recv_from_any_links");
    
    // TODO: Implement the router forwarding logic

    /* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

        struct ether_hdr *eth = (struct ether_hdr *)buf;
        uint16_t eth_type = ntohs(eth->ethr_type);

        if (eth_type == 0x0806) {
            struct arp_hdr *arph = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
            uint16_t op = ntohs(arph->opcode);
            if (op == 1) {
                uint32_t tip = arph->tprotoa;
                uint32_t my_ip = inet_addr(get_interface_ip(interface)); // request de la ARP, trimit raspuns
                if (tip == my_ip) {
                    send_arp_reply(buf, interface);
                }
            } else if (op == 2) {
                // reply de la ARP, salvez in tabela si trimit pachetele in asteptare
                add_arp_entry(arph->sprotoa, arph->shwa);
                try_sending_waiting_packets(arph->sprotoa);
            }
            continue; // si tot asa, trec la urmatorul pachet
        }

        if (eth_type == 0x0800) {
            struct ip_hdr *ip = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
            uint16_t old_cksum = ip->checksum;
            ip->checksum = 0; 
            uint16_t c = checksum((uint16_t *)ip, sizeof(struct ip_hdr)); // verific checksumul de la IP
            if (ntohs(old_cksum) != c) {
                continue;
            }
            ip->checksum = old_cksum; // pun ce era, daca e valid
        
            if (ip->ttl <= 1) {
                send_icmp_error(buf, len, interface, ICMP_TIME_EXCEEDED, 0); // verific TTL
                continue;
            }
        
            int routerTargetFound = 0;
            int ifaceIndex = 0;
        
            while (ifaceIndex < (argc - 2)) { // iterez prin toate interfetele de la router
                uint32_t ifaceIP = inet_addr(get_interface_ip(ifaceIndex));
                if (ifaceIP == ip->dest_addr) {
                    routerTargetFound = 1; // verific daca IP-ul destinatie din pachet corespunde cu IP-ul meu
                    break;
                }
                ifaceIndex++;
            }
        
            if (routerTargetFound != 0) {
                if (ip->proto == 1) {
                    const uint8_t *icmp_start = (const uint8_t *)ip + sizeof(struct ip_hdr); // trimit un echo reply
                    struct icmp_hdr *icmpPtr = (struct icmp_hdr *)icmp_start;
        
                    if (icmpPtr->mtype == ICMP_ECHO_REQUEST) {
                        send_icmp_echo_reply(buf, len, interface);
                    }
                }
                continue;
            }
            ip->ttl--;
            ip->checksum = 0;
            uint16_t csumf = checksum((uint16_t *)ip, sizeof(struct ip_hdr)); // recalculez checksum dupa ce am schimbat TTL
            ip->checksum = htons(csumf);
        
            struct route_table_entry *best = get_best_route(ip->dest_addr);
            if (!best) {
                send_icmp_error(buf, len, interface, ICMP_DEST_UNREACH, 0);
                continue;
            }
        
            uint32_t next_hop_ip = best->next_hop;
            if (next_hop_ip == 0) {
                next_hop_ip = ip->dest_addr; // determin IP-ul next-hop
            }
        
            struct arp_dynamic *ae = get_arp_entry(next_hop_ip);
            if (!ae) {
                send_arp_request(next_hop_ip, best->interface);
                struct packet_wait *pw = malloc(sizeof(struct packet_wait));
                pw->len = len;
                pw->iface = best->interface; // caut adresa MAC de la next-hop in tavela ARP
                pw->next_hop = next_hop_ip;
                memcpy(pw->buf, buf, len);
                queue_enq(waiting_queue, pw);
                continue;
            }
            forward_packet(buf, len, best->interface, ae->mac); // daca avem MAC-ul, facem forwarding
        }        
    }
    return 0;
}