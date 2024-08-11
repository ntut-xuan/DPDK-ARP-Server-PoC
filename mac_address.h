#ifndef MACAddress_H
#define MACAddress_H

#include <unistd.h>
#include <cstdint>
#include <cstring>
#include <string>

class MACAddress {
private:
    uint8_t* address = new uint8_t[6];

public:
    MACAddress(){
        for(int i = 0; i < 6; i++){
            address[i] = 0;
        }
    };
    MACAddress(uint8_t* address){
        memcpy(this->address, address, 6);
    }
    MACAddress(MACAddress &mac_address){
        memcpy(this->address, mac_address.get_address(), 6);
    }
    ~MACAddress(){
        delete[] address;
    }
    uint8_t* get_address(){
        return address;
    }
    std::string to_string(){
        char address_str[30];
        sprintf(address_str, "%02X:%02X:%02X:%02X:%02X:%02X", address[0], address[1], address[2], address[3], address[4], address[5]);
        return std::string(address_str);
    }
};

#endif