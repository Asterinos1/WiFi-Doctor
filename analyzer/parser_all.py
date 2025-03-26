import pyshark
from tqdm import tqdm  # 'pip install tqdm' -> shows progress of packet analysis.

def extract_all_data(pcap_file: str) -> list:
    """
    Using pyshark this method applies no filter into the pcap file
    and tries to extract various information from those packets such as:
    ->BSSID
    ->Transmitter MAC address
    ->Receiver MAC address
    ->Type/subtype
    ->PHY Type
    ->MCS Index
    ->Bandwidth
    ->Spatial Streams
    ->Short GI
    ->Data Rate
    ->Rate Gap
    ->Channel
    ->Frequency
    ->Signal Strength 
    ->Signal/Noise Ratio (SNR)
    ->TSF Timestamp

    Args:
        pcap_file (str): path to the pcap file

    Returns:
       List: Contains a dictionary for each packet in the pcap_file
    """

    capture = pyshark.FileCapture(pcap_file)
    extracted_data_all = []
    total_packets = len(capture)

    for packet in tqdm(capture, total=total_packets, desc="Analyzing Packets"):
        packet_data_all = {
            'bssid': None,
            'transmitter_mac': None,
            'receiver_mac': None,
            'frame_type_subtype': None,
            'phy_type': None,
            'mcs_index': None,
            'bandwidth': None,
            'spatial_streams': None,
            'short_gi': None,
            'data_rate': None,
            'rate_gap' : None,
            'channel': None,
            'frequency': None,
            'signal_strength': None,
            'retry_flag': None,
            'snr': None,
            'ssid': None
        }

        if hasattr(packet, 'wlan'):
            packet_data_all['bssid'] = getattr(packet.wlan, 'bssid', None)
            
            packet_data_all['transmitter_mac'] = getattr(packet.wlan, 'ta', None)
            packet_data_all['receiver_mac'] = getattr(packet.wlan, 'ra', None)
            packet_data_all['frame_type_subtype'] = getattr(packet.wlan, 'fc_type_subtype', None)
            packet_data_all['retry_flag'] = getattr(packet.wlan, 'fc.retry', None)

        if hasattr(packet, 'wlan_radio'):
            packet_data_all['phy_type'] = getattr(packet.wlan_radio, 'phy', None)
            packet_data_all['mcs_index'] = getattr(packet.wlan_radio, '11n.mcs_index', None)
            bandwidth = getattr(packet.wlan_radio, '11n.bandwidth', None)
            packet_data_all['bandwidth'] = "20 MHz" if bandwidth == "0" else bandwidth
            packet_data_all['spatial_streams'] = getattr(packet.wlan_radio, '11n.num_sts', None)
            packet_data_all['short_gi'] = getattr(packet.wlan_radio, '11n.short_gi', None)
            packet_data_all['data_rate'] = getattr(packet.wlan_radio, 'data_rate', None)
            packet_data_all['channel'] = getattr(packet.wlan_radio, 'channel', None)
            packet_data_all['signal_strength'] = getattr(packet.wlan_radio, 'signal_dbm', None)
            packet_data_all['snr'] = getattr(packet.wlan_radio, 'snr', None)

        if hasattr(packet, 'radiotap'):
            packet_data_all['frequency'] = getattr(packet.radiotap, 'channel_freq', None)

        # this is for ssid eg TUC   
        if 'wlan.mgt' in packet:
            ssid_tag = packet['wlan.mgt'].get('wlan.tag', None)
            if ssid_tag and 'SSID parameter set:' in ssid_tag:
                packet_data_all['ssid'] = ssid_tag.split('SSID parameter set: ')[-1].strip('"')
            else:
                packet_data_all['ssid'] = None  

        extracted_data_all.append(packet_data_all)

    capture.close()
    return extracted_data_all


def filter_beacon_frames(data_all: list) -> list:
    """
    This Method takes the frame_type_subtype and checks if it is a beacon frame, then adds it
    to a diffrent list with only beacon frames (1.1)

    Args:
        data_all (list): list of dictionaries with the extracted data from extract_all_data()

    Returns:
        List: a new list with only beacon frames.
    """
    beacon_frames = []

    for packet in data_all:
        if "frame_type_subtype" in packet and packet["frame_type_subtype"] == "0x0008":  
            beacon_frames.append(packet)

    return beacon_frames


def find_spatial_streams(data_all: list) -> list:
    """
    If the spatial streams inforamtion is missing, find the spatial streams based on table[4]
    with MCS index.

    Args:
        data_all (list): list of dictionaries with the extracted data from extract_all_data()

    Returns:
        List: new list with assigned spatial stream values.
    """
    for packet in data_all:
        if packet.get('spatial_streams') is None and packet.get('mcs_index') is not None:
            try:
                mcs_index = int(packet['mcs_index'])  
                if 1 <= mcs_index <= 7:
                    packet['spatial_streams'] = 1
                elif 8 <= mcs_index <= 15:
                    packet['spatial_streams'] = 2
                elif 16 <= mcs_index <= 23:
                    packet['spatial_streams'] = 3
            except ValueError:
                pass  

    return data_all

def filter_for_1_2(data_all: list, source_mac: str, dest_mac: str, filter) -> list:
    """
    filters the packets with the corresponding sa mac and ta mac with a specific filter 

    Args:
        data_all (list): list of dictionaries with the extracted data from extract_all_data()
        source_mac (str): The sa MAC address to filter.
        dest_mac (str): The ta MAC address to filter.

    Returns:
        List: filtered list with only packets matching the source and destination MAC addresses.
    """
    filtered_packets = [
        packet for packet in data_all
        if packet.get("transmitter_mac") == source_mac and packet.get("receiver_mac") == dest_mac and packet.get("frame_type_subtype") == filter
    ]
    return filtered_packets


if __name__ == "__main__":
    pcap_file = 'analyzer/pcap_files/HowIWiFi_PCAP.pcap'  
    #pcap_file = 'analyzer\\pcap_files\\HowIWiFi_PCAP.pcap'

    #Debugging stuff
    print("Starting...")
    data = extract_all_data(pcap_file)

    #Debugging 
    print("Data succesfully extracted.")

    data = find_spatial_streams(data)

    print("Extracted spatial streams.")

    #filter beacon frames
    beacon_frame_data = filter_beacon_frames(data)

    print("Beacon frames filtered.")

    print("Proceeding to get the info for analyzer part:")
    communication_packets = filter_for_1_2(data, "2c:f8:9b:dd:06:a0", "00:20:a6:fc:b0:36", "0x0028")
    print("Done.")

    print("\nBeacon Frames:")
    print("** 5 billion frames spam here **")
    # for i, packet_info in enumerate(beacon_frame_data):
    #     print(f"Packet #{i+1}: {packet_info}")

