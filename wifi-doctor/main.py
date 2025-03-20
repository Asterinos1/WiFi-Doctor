import pyshark

pcap_file = pyshark.FileCapture('goofy2.pcapng')
packet_count=0

def print_formatted_packet(index, packet):
    print("\n")
    print(f"Packet #{index}:")
    print(f"Length: {packet.length}")

for packet in pcap_file:
    packet_count+=1
    print_formatted_packet(packet_count, packet)
    
print(f"Total packets: {packet_count}")