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

#include <memory>
#include <unistd.h>

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

bool is_sudo(){
    auto uid = getuid();
    if(uid == 0){
        return true;
    }else{
        return false;
    }
}

MACAddress fetch_mac_address_by_port(int port_id){
    struct rte_ether_addr mac_address;
    int retval = rte_eth_macaddr_get(port_id, &mac_address);
    if (retval != 0){
        spdlog::error("Cannot get MAC address of port {0}. \n", port_id);
        return MACAddress();
    }
    return MACAddress(mac_address.addr_bytes);
}


void check_is_sudo_or_exit(){
    if(!is_sudo()){
        spdlog::error("Should be root to execute this program. Exit.");
        exit(1);
    }
}

void initialize_EAL(int argc, char** argv){
    int ret = rte_eal_init(argc, argv);
    if(ret < 0){
        rte_panic("Error with EAL initialization\n");
    }
}

void initialize_mbuf_pool(struct rte_mempool* &mbuf_pool){
    unsigned nb_ports = rte_eth_dev_count_avail();
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
}

void initialize_port(uint16_t port_id, struct rte_mempool* mbuf_pool){
    int success = init_port(port_id, mbuf_pool);
    if(success != 0){
        spdlog::error("Cannot init port {}", port_id);
        exit(1);
    }
}

void send_data(uint16_t port_id, uint8_t *data, uint16_t data_len, struct rte_mempool *mbuf_pool) {
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (mbuf == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot allocate mbuf\n");
    }

    // Copy data into the mbuf
    uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
    rte_memcpy(pkt_data, data, data_len);

    // Set the mbuf packet length
    mbuf->data_len = data_len;
    mbuf->pkt_len = data_len;

    // Create a buffer for sending packets
    rte_eth_dev_tx_buffer* tx_buffer = static_cast<rte_eth_dev_tx_buffer*>(rte_zmalloc_socket("tx_buffer", RTE_ETH_TX_BUFFER_SIZE(BURST_SIZE), 0, rte_eth_dev_socket_id(port_id)));
    if (tx_buffer == NULL) {
        rte_pktmbuf_free(mbuf);
        rte_exit(EXIT_FAILURE, "Cannot allocate tx_buffer\n");
    }

    rte_eth_tx_buffer_init(tx_buffer, BURST_SIZE);

    // Enqueue the packet for transmission
    int sent = rte_eth_tx_buffer(port_id, 0, tx_buffer, mbuf);
    if (sent == 0) {
        // If the packet couldn't be sent, free the mbuf
        rte_pktmbuf_free(mbuf);
    }

    // Flush any remaining packets in the buffer
    rte_eth_tx_buffer_flush(port_id, 0, tx_buffer);

    // Free the allocated tx_buffer
    rte_free(tx_buffer);
}