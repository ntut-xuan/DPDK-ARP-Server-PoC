#ifndef IPADDRESS_H
#define IPADDRESS_H

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>

class IPAddress {
private:
    uint8_t* address = new uint8_t[4];

public:
    IPAddress(uint8_t* address){
        memcpy(this->address, address, 4);
    }
    IPAddress(IPAddress &ip_address){
        memcpy(this->address, ip_address.get_address(), 4);
    }
    ~IPAddress(){
        delete[] address;
    };

    uint8_t* get_address(){
        return address;
    }

    std::string to_string(){
        char address_str[30];
        sprintf(address_str, "%d.%d.%d.%d", address[0], address[1], address[2], address[3]);
        return std::string(address_str);
    }
};

#endif