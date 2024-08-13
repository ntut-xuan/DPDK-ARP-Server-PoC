#include <cstring>
#include <memory>

#include "ip_address.h"
#include "mac_address.h"
#include "packet.h"

namespace Packet {

class ReplyARP : public Packet {
public:
    ReplyARP(IPAddress source_ip_address, IPAddress dest_ip_address, MACAddress dest_mac_address, MACAddress source_mac_address, int packet_len){
        this->packet_data = new uint8_t[packet_len];
        this->packet_len = packet_len;

        fill_dest_mac_address(packet_data, dest_mac_address.get_address());
        fill_source_mac_address(packet_data, source_mac_address.get_address());
        fill_protocol(packet_data);
        fill_hardware_type(packet_data);
        fill_protocol_type(packet_data);
        fill_hardware_size(packet_data);
        fill_protocol_size(packet_data);
        fill_opcode(packet_data);
        fill_sender_mac_address(packet_data, source_mac_address.get_address());
        fill_sender_ip_address(packet_data, source_ip_address.get_address());
        fill_target_mac_address(packet_data, dest_mac_address.get_address());
        fill_target_ip_address(packet_data, dest_ip_address.get_address());
    }

    ~ReplyARP() = default;

    MACAddress get_sender_mac_address(){
        uint8_t* sender_mac_address = new uint8_t[6];
        memcpy(sender_mac_address, packet_data+22, 6);
        MACAddress address(sender_mac_address);
        delete[] sender_mac_address;
        return address;
    }

    MACAddress get_target_mac_address(){
        uint8_t* target_mac_address = new uint8_t[6];
        memcpy(target_mac_address, packet_data+32, 6);
        MACAddress address(target_mac_address);
        delete[] target_mac_address;
        return address;
    }

    IPAddress get_sender_ip_address(){
        uint8_t* sender_ip_address = new uint8_t[4];
        memcpy(sender_ip_address, packet_data+28, 4);
        IPAddress address(sender_ip_address);
        delete[] sender_ip_address;
        return address;
    }

    IPAddress get_target_ip_address(){
        uint8_t* target_ip_address = new uint8_t[4];
        memcpy(target_ip_address, packet_data+38, 4);
        IPAddress address(target_ip_address);
        delete[] target_ip_address;
        return address;
    }
private:
    void fill_byte(uint8_t* &packet, uint8_t* bytes, int length, int offset){
        for(int i = 0; i < length; i++){
            packet[offset+i] = bytes[i];
        }
    }

    void fill_dest_mac_address(uint8_t* &packet, uint8_t* dest_mac_address){
        fill_byte(packet, dest_mac_address, 6, 6);
    }

    void fill_source_mac_address(uint8_t* &packet, uint8_t* source_mac_address){
        fill_byte(packet, source_mac_address, 6, 0);
    }

    void fill_protocol(uint8_t* &packet){
        packet[12] = 8;
        packet[13] = 6;
    }

    void fill_hardware_type(uint8_t* &packet){
        packet[14] = 0;
        packet[15] = 1;
    }

    void fill_protocol_type(uint8_t* &packet){
        packet[16] = 8;
        packet[17] = 0;
    }

    void fill_hardware_size(uint8_t* &packet){
        packet[18] = 6;
    }

    void fill_protocol_size(uint8_t* &packet){
        packet[19] = 4;
    }

    void fill_opcode(uint8_t* &packet){
        packet[20] = 0;
        packet[21] = 2;
    }

    void fill_sender_mac_address(uint8_t* &packet, uint8_t* source_mac_address){
        fill_byte(packet, source_mac_address, 6, 32);
    }

    void fill_sender_ip_address(uint8_t* &packet, uint8_t* source_ip_address){
        fill_byte(packet, source_ip_address, 4, 38);
    }

    void fill_target_mac_address(uint8_t* &packet, uint8_t* target_mac_address){
        fill_byte(packet, target_mac_address, 6, 22);
    }

    void fill_target_ip_address(uint8_t* &packet, uint8_t* target_ip_address){
        fill_byte(packet, target_ip_address, 4, 28);
    }
};

class ARP : public Packet {
public:
    ARP(Packet packet) : Packet::Packet(packet){
    }

    ARP(uint8_t* packet_data, uint16_t packet_len){
        this->packet_data = packet_data;
        this->packet_len = packet_len;
    }

    ~ARP() = default;

    MACAddress get_source_mac_address(){
        uint8_t* source_mac_address = new uint8_t[6];
        memcpy(source_mac_address, packet_data+22, 6);
        MACAddress address(source_mac_address);
        delete[] source_mac_address;
        return address;
    }

    IPAddress get_source_ip_address(){
        uint8_t* source_ip_address = new uint8_t[4];
        memcpy(source_ip_address, packet_data+28, 4);
        IPAddress address(source_ip_address);
        delete[] source_ip_address;
        return address;
    }

    IPAddress get_dest_ip_address(){
        uint8_t* dest_ip_address = new uint8_t[4];
        memcpy(dest_ip_address, packet_data+38, 4);
        IPAddress address(dest_ip_address);
        delete[] dest_ip_address;
        return address;
    }

    ReplyARP generate_resposne_packet(std::vector<MACAddress> mac_addresses, int index = 0){
        IPAddress source_ip_address = get_source_ip_address();
        IPAddress dest_ip_address = get_dest_ip_address();
        MACAddress dest_mac_address = mac_addresses[index];
        MACAddress source_mac_address = get_source_mac_address();

        return ReplyARP(source_ip_address, dest_ip_address, dest_mac_address, source_mac_address, packet_len);
    }
};

}