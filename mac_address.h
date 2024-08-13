#ifndef MACAddress_H
#define MACAddress_H

#include <spdlog/spdlog.h>

#include <unistd.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <sstream>

class MACAddress {
private:
    uint8_t* address = new uint8_t[6];

    uint8_t convert_to_dec_uint8_t(std::string hex){
        uint8_t x = std::stoul(hex, nullptr, 16);
        return x;
    }

    std::vector<uint8_t> parse_mac_address(std::string mac_address){
        std::string tmp = "";
        std::vector<uint8_t> vec;
        for(int i = 0; i < mac_address.length(); i++){
            if(mac_address[i] == ':'){
                vec.push_back(convert_to_dec_uint8_t("0x" + tmp));
                tmp = "";
                continue;
            }
            tmp += mac_address[i];
        }
        vec.push_back(convert_to_dec_uint8_t("0x" + tmp));
        return vec;
    }
public:
    MACAddress(){
        for(int i = 0; i < 6; i++){
            address[i] = 0;
        }
    };
    MACAddress(uint8_t* address){
        memcpy(this->address, address, 6);
    }
    MACAddress(std::string mac_address_str){
        std::vector<uint8_t> mac_address = parse_mac_address(mac_address_str);
        for(int i = 0; i < 6; i++){
            address[i] = mac_address[i];
        }
    }
    MACAddress(const MACAddress &mac_address){
        memcpy(this->address, mac_address.get_address(), 6);
    }
    MACAddress operator=(const MACAddress &other){
        memcpy(this->address, other.address, 6);
        return *this;
    }
    ~MACAddress(){
        delete[] address;
    }
    uint8_t* get_address() const {
        return address;
    }
    std::string to_string(){
        char address_str[30];
        sprintf(address_str, "%02X:%02X:%02X:%02X:%02X:%02X", address[0], address[1], address[2], address[3], address[4], address[5]);
        return std::string(address_str);
    }
};

#endif