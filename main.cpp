#include <iostream>

#include <spdlog/spdlog.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_launch.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

#include "arp-packet.h"
#include "icmp-packet.h"
#include "packet.h"
#include "ports.cpp"
#include "utils.cpp"

#define BURST_SIZE 32

int main(int argc, char** argv){
    struct rte_mempool *mbuf_pool = NULL;
    uint16_t port_id;

    check_is_sudo_or_exit();
    
    spdlog::info("Start EAL Initialization.");
    initialize_EAL(argc, argv);

    spdlog::info("Start mbuf_pool Initialization.");
    initialize_mbuf_pool(mbuf_pool);

    spdlog::info("Start Port Initialization.");
    initialize_port(port_id, mbuf_pool);

    spdlog::info("All Initialization step is completed. Start to capture the flag.");

    struct rte_mbuf *bufs[BURST_SIZE];
    while(1){
        uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, bufs, BURST_SIZE);

        if(nb_rx == 0){
            continue;
        }

        for(int i = 0; i < nb_rx; i++){
            struct rte_mbuf *mbuf = bufs[i];
            uint8_t* packet_data = rte_pktmbuf_mtod(mbuf, uint8_t*);
            uint16_t packet_len = rte_pktmbuf_pkt_len(mbuf);

            Packet::Packet packet(
                packet_data,
                packet_len
            );
            
            if(packet.get_protocol_type() == PROTOCOL_TYPE::ARP){
                MACAddress port_mac_address = fetch_mac_address_by_port(port_id);

                Packet::ARP arp(packet);
                spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [\033[32m%l\033[m] [\033[95mARP\033[m] %v");
                spdlog::info("Received ARP Packet. [Source IP={0}, Dest IP={1}, Source MAC Address={2}]", 
                    arp.get_source_ip_address().to_string(), 
                    arp.get_dest_ip_address().to_string(), 
                    arp.get_source_mac_address().to_string()
                );
                Packet::ReplyARP replyARP = arp.generate_resposne_packet(port_mac_address);
                spdlog::info("Reply ARP Packet. [Source IP={0}, Dest IP={1}, Source MAC Address={2}, Dest MAC Address={3}]", 
                    replyARP.get_sender_ip_address().to_string(), 
                    replyARP.get_target_ip_address().to_string(), 
                    replyARP.get_sender_mac_address().to_string(),
                    replyARP.get_target_mac_address().to_string()
                );
                send_data(port_id, replyARP.get_packet(), packet_len, mbuf_pool);
            }

            if(packet.get_protocol_type() == PROTOCOL_TYPE::ICMP){
                Packet::ICMP icmp(packet);
                spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [\033[32m%l\033[m] [\033[96mICMP\033[m] %v");
                spdlog::info("Received ICMP Packet. [Source IP={0}, Dest IP={1}, Source MAC Address={2}, Dest MAC Address={3}]", 
                    icmp.get_source_ip_address().to_string(), 
                    icmp.get_dest_ip_address().to_string(), 
                    icmp.get_source_mac_address().to_string(),
                    icmp.get_dest_mac_address().to_string()
                );
                Packet::ReplyICMP replyICMP = icmp.generate_resposne_packet();
                spdlog::info("Reply ICMP Packet. [Source IP={0}, Dest IP={1}, Source MAC Address={2}, Dest MAC Address={3}]", 
                    replyICMP.get_sender_ip_address().to_string(), 
                    replyICMP.get_target_ip_address().to_string(), 
                    replyICMP.get_sender_mac_address().to_string(),
                    replyICMP.get_target_mac_address().to_string()
                );
                send_data(port_id, replyICMP.get_packet(), packet_len, mbuf_pool);
            }

            rte_pktmbuf_free(mbuf);
        }
    }

    free(bufs);
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);
    rte_mempool_free(mbuf_pool);
    rte_eal_cleanup();
    return 0;
}