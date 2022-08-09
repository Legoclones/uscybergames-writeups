#!/usr/bin/env python3

from scapy.all import rdpcap

def get_packets():
    return rdpcap('hidden_wisdom.pcap')

def solve(packets):
    # create variable to store previous packet time to calculate the time difference
    previous_packet_time = 0
    # create variable to store binary data as we decode the message
    message = ''
    # create variable to append flag characters to as we decode the message
    flag = ''

    for packet in packets:
        # calculate difference in time
        diff = packet.time - previous_packet_time
        # if packet time stamp is about 0.3 second, the bit is 1
        if (diff > .27) and (diff < .33):
            message += '1'

        # if packet time stamp is about 0.1 second, the bit is 0
        elif (diff > .07) and (diff < .13):
            message += '0'
            
        # set previous time stamp for next iteration of the loop
        previous_packet_time = packet.time

        if len(message) == 8:
            # convert message bits to a character and append to flag
            flag += chr(int(message, 2))
            # clear message bits
            message = ''
        
    return flag

def main():
    flag = solve(get_packets())
    print(f"Flag: {flag}")

if __name__ == '__main__':
    main()
