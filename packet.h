#ifndef PACKET_H
#define PACKET_H

#include <cstdint>

enum PROTOCOL_TYPE {ARP, ICMP, UNKNOWN};

namespace Packet {

class Packet {
protected:
    uint8_t* packet_data = NULL;
    uint16_t packet_len = 0;

public:
    Packet() = default;

    Packet(uint8_t* packet_data, uint16_t packet_len){
        this->packet_data = new uint8_t[packet_len];
        memcpy(this->packet_data, packet_data, packet_len);
        this->packet_len = packet_len;
    }

    Packet(Packet& packet){
        this->packet_data = new uint8_t[packet.packet_len];
        memcpy(this->packet_data, packet.packet_data, packet.packet_len);
        this->packet_len = packet.packet_len;
    }

    ~Packet(){
        delete[] packet_data;
    };

    PROTOCOL_TYPE get_protocol_type(){
        if(packet_len < 13){
            return PROTOCOL_TYPE::UNKNOWN;
        }
        if(packet_data[12] == 8 && packet_data[13] == 6){
            return PROTOCOL_TYPE::ARP;
        }
        if(packet_len < 24){
            return PROTOCOL_TYPE::UNKNOWN;
        }
        if(packet_data[23] == 1){
            return PROTOCOL_TYPE::ICMP;
        }
        return PROTOCOL_TYPE::UNKNOWN;
    }

    uint8_t* get_packet(){
        return packet_data;
    }
};

}

#endif