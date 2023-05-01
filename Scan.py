import dpkt, socket, sys
from dpkt.utils import mac_to_str, inet_to_str

# Setting and "anding" the tcp flags in order to filter them from the PCAP file
# Based on formatting of the tcp github file
# https://github.com/kbandla/dpkt/blob/master/dpkt/tcp.py 
def tcp_flags_to_str(tcp):
    ff = []
    if tcp.flags & dpkt.tcp.TH_SYN !=0:
        ff.append('SYN')
    if tcp.flags & dpkt.tcp.TH_ACK !=0:
        ff.append('ACK')
    return ','.join(ff)

# 3:1 ration requirement
ratio = 3

# Function for printing packets based on the print_packets.py
# https://github.com/kbandla/dpkt/blob/master/examples/print_packets.py

def print_packets(pcap):
    suspicious_ips = dict() # Instantiate an empty dictionary to hold ip address and their syn and acks 


    # Going through the PCAP file and getting the ethernet frame (has to be in a try, except block to work)
    for ts, buf in pcap:   
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except: 
            continue


        ip = eth.data

        # If any of the ethernet data is corrupted, move on to the next set of data and don't use the corrupted one
        if not ip:
           continue

    # Skip packets that are not TCP
        tcp = ip.data

        # Condition checking that the tcp type is correct
        if type(tcp) != dpkt.tcp.TCP:
            continue

        # Gets the tcp protocol flag
        tcpFlag = tcp_flags_to_str(tcp) 

        # Getting the source IP address
        srcIP = socket.inet_ntoa(ip.src)

        # Getting the destination IP address
        dstIP = socket.inet_ntoa(ip.dst)


        # If the tcp flag is SYN, and the source IP address is not a suspicious address, make it a suspicious address and increment its
        # SYN counter by 1
        if 'SYN' == tcpFlag:         
            if srcIP not in suspicious_ips: 
                suspicious_ips[srcIP] = {'SYN': 0, 'SYN-ACK': 0}

            suspicious_ips[srcIP]['SYN'] += 1
        

        # If the tcp flag is SYN,ACK, and the destination IP address is not a suspicious address, make it a suspicious address and increment
        # its SYN-ACK counter by 1        
        elif 'SYN,ACK' == tcpFlag:
            if dstIP not in suspicious_ips: 
                suspicious_ips[dstIP] = {'SYN': 0, 'SYN-ACK': 0}
            suspicious_ips[dstIP]['SYN-ACK'] += 1

    # Create new dict for the port scanners with the ratio parameter
    filtered_suspects = dict()
    
    for s in suspicious_ips.keys():

        # If the SYN values of an IP address is greater than its SYN-ACK values multiplied by the ratio (3), it's a suspicious scanner.
        # Add all the suspicious scanners that meet this condition to the filtered suspects dictionary. 
        if suspicious_ips[s]['SYN'] > (suspicious_ips[s]['SYN-ACK'] * ratio):
            filtered_suspects[s]={'SYN':suspicious_ips[s]['SYN'], 'SYN-ACK': suspicious_ips[s]['SYN-ACK']}

    # Iterating through the 
    for ips in filtered_suspects.keys():
        print(ips)
    
def test(file):
    
    # Reading in the PCAP file and running the print_packets function to see if there are suspicous scans
    with open(file, 'rb') as f: 
        pcap = dpkt.pcap.Reader(f)
        print_packets(pcap)


# Main function that takes in a 2nd command line argument (the PCAP file)
if __name__ == '__main__':
    import sys
    n = sys.argv
    test(sys.argv[1])
