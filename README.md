# ARP Server with DPDK PoC

In this implementation, I'm trying to make a ARP server to process the `ping` command between two VM.

We expect that when ARP server received ARP message, it will resposne its MAC address to client VM. Also, when it received ICMP message, it will response ICMP message to client VM.

The target of this project is make sure ARP server can handle the message and the response message can accept by Linux default network device.

## Build ARP Server

You should have DPDK environment first.

Go to the project root and use `make` command to build everything, the binary should appear in `./build` directory.

## Test the project

When the client VM use ping to ping some IP address in his network submask, it should been received by ARP Server and resposne ARP reply.

After the ARP reply accepted by client VM, it should start to process with `ping` command.

