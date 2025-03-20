import pyshark

pcap_file = pyshark.FileCapture('goofy.pcapng')
packet_count=0

for packet in pcap_file:
    packet_count+=1
    print(packet)

print(f"Total packets: {packet_count}")