#include "packet.h"
#include "mac_address.h"
#include "ip_address.h"

namespace Packet {

class ReplyICMP : public Packet {
public:
    ReplyICMP(uint8_t* packet_data, uint16_t packet_len){
        this->packet_data = new uint8_t[packet_len];
        memcpy(this->packet_data, packet_data, packet_len);

        uint8_t* source_ip_address = new uint8_t[4];
        uint8_t* source_mac_address = new uint8_t[6];
        uint8_t* dest_ip_address = new uint8_t[4];
        uint8_t* dest_mac_address = new uint8_t[6];

        memcpy(dest_mac_address, packet_data, 6);
        memcpy(source_mac_address, packet_data+6, 6);
        memcpy(source_ip_address, packet_data+26, 4);
        memcpy(dest_ip_address, packet_data+30, 4);

        fill_icmp_dest_ip_address(this->packet_data, source_ip_address);
        fill_icmp_source_ip_address(this->packet_data, dest_ip_address);
        fill_icmp_dest_mac_address(this->packet_data, source_mac_address);
        fill_icmp_source_mac_address(this->packet_data, dest_mac_address);

        this->packet_len = packet_len;

        delete[] source_ip_address;
        delete[] source_mac_address;
        delete[] dest_ip_address;
        delete[] dest_mac_address;
    }

    ~ReplyICMP() = default;
    
    MACAddress get_target_mac_address(){
        uint8_t* source_mac_address = new uint8_t[6];
        memcpy(source_mac_address, packet_data, 6);
        MACAddress address(source_mac_address);
        delete[] source_mac_address;
        return address;
    }

    MACAddress get_sender_mac_address(){
        uint8_t* source_mac_address = new uint8_t[6];
        memcpy(source_mac_address, packet_data+6, 6);
        MACAddress address(source_mac_address);
        delete[] source_mac_address;
        return address;
    }

    IPAddress get_sender_ip_address(){
        uint8_t* source_ip_address = new uint8_t[4];
        memcpy(source_ip_address, packet_data+26, 4);
        IPAddress address(source_ip_address);
        delete[] source_ip_address;
        return address;
    }

    IPAddress get_target_ip_address(){
        uint8_t* dest_ip_address = new uint8_t[4];
        memcpy(dest_ip_address, packet_data+30, 4);
        IPAddress address(dest_ip_address);
        delete[] dest_ip_address;
        return address;
    }

private:
    void fill_byte(uint8_t* &packet, uint8_t* bytes, int length, int offset){
        for(int i = 0; i < length; i++){
            packet[offset+i] = bytes[i];
        }
    }

    void fill_icmp_dest_mac_address(uint8_t* packet, uint8_t* dest_mac_address){
        fill_byte(packet, dest_mac_address, 6, 0);
    }

    void fill_icmp_source_mac_address(uint8_t* packet, uint8_t* source_mac_address){
        fill_byte(packet, source_mac_address, 6, 6);
    }

    void fill_icmp_source_ip_address(uint8_t* packet, uint8_t* source_ip_address){
        fill_byte(packet, source_ip_address, 4, 26);
    }

    void fill_icmp_dest_ip_address(uint8_t* packet, uint8_t* target_ip_address){
        fill_byte(packet, target_ip_address, 4, 30);
    }
};

class ICMP : public Packet {
public:
    ICMP(Packet packet) : Packet::Packet(packet){
    }

    ICMP(uint8_t* packet_data, uint16_t packet_len){
        this->packet_data = packet_data;
        this->packet_len = packet_len;
    }

    ~ICMP() = default;

    MACAddress get_dest_mac_address(){
        uint8_t* source_mac_address = new uint8_t[6];
        memcpy(source_mac_address, packet_data, 6);
        MACAddress address(source_mac_address);
        delete[] source_mac_address;
        return address;
    }

    MACAddress get_source_mac_address(){
        uint8_t* source_mac_address = new uint8_t[6];
        memcpy(source_mac_address, packet_data+6, 6);
        MACAddress address(source_mac_address);
        delete[] source_mac_address;
        return address;
    }

    IPAddress get_source_ip_address(){
        uint8_t* source_ip_address = new uint8_t[4];
        memcpy(source_ip_address, packet_data+26, 4);
        IPAddress address(source_ip_address);
        delete[] source_ip_address;
        return address;
    }

    IPAddress get_dest_ip_address(){
        uint8_t* dest_ip_address = new uint8_t[4];
        memcpy(dest_ip_address, packet_data+30, 4);
        IPAddress address(dest_ip_address);
        delete[] dest_ip_address;
        return address;
    }

    ReplyICMP generate_resposne_packet(){
        return ReplyICMP(packet_data, packet_len);
    }
};

}