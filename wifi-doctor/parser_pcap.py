import pyshark

def extract_beacon_frame_data(pcap_file: str) -> list:
    """Using pyshark the method applies the filter for beacon frames into the pcap file
    and tries to extract specific information from those beacon frames such as:
    ->BSSID
    ->Transmitter MAC address
    ->PHY Type
    ->Channel
    ->Frequency
    ->Signal strength
    ->Signal/noise ratio

    Args:
        pcap_file (str): path to the pcap file

    Returns:
        List: Contains a dictionary for each packet in the pcap_file
    """
    capture = pyshark.FileCapture(pcap_file, display_filter='wlan.fc.type_subtype == 8')
    extracted_data = []

    for packet in capture:
        packet_data = {}

        if hasattr(packet, 'wlan') and hasattr(packet.wlan, 'bssid'):
            packet_data['bssid'] = getattr(packet.wlan, 'bssid', None)

        if 'wlan.mgt' in packet:
            ssid_tag = packet['wlan.mgt'].get('wlan.tag', None)
            if ssid_tag and 'SSID parameter set:' in ssid_tag:
                packet_data['ssid'] = ssid_tag.split('SSID parameter set: ')[-1].strip('"')
            else:
                packet_data['ssid'] = None  

        if hasattr(packet, 'wlan'):
            packet_data['transmitted_mac'] = getattr(packet.wlan, 'sa', None)

        if hasattr(packet, 'wlan_radio') and hasattr(packet.wlan_radio, 'phy'):
            packet_data['phy_type'] = getattr(packet.wlan_radio, 'phy', None)

        if hasattr(packet, 'wlan_radio') and hasattr(packet.wlan_radio, 'channel'):
            packet_data['channel'] = getattr(packet.wlan_radio, 'channel', None)

        if hasattr(packet, 'radiotap') and hasattr(packet.radiotap, 'channel_freq'):
            packet_data['frequency'] = getattr(packet.radiotap, 'channel_freq', None)

        if hasattr(packet, 'wlan_radio') and hasattr(packet.wlan_radio, 'signal_dbm'):
            packet_data['signal_strength'] = getattr(packet.wlan_radio, 'signal_dbm', None)  

        if hasattr(packet, 'wlan_radio') and hasattr(packet.wlan_radio, 'snr'):
            packet_data['snr'] = getattr(packet.wlan_radio, 'snr', None)
        if hasattr(packet, 'wlan_radio') and hasattr(packet.wlan_radio, 'rssi'):
            packet_data['rssi'] = getattr(packet.wlan_radio, 'rssi', None)

        extracted_data.append(packet_data)

    capture.close()
    return extracted_data

if __name__ == "__main__":
    pcap_file = 'pcap_files/faye2p4.pcap'
    beacon_data = extract_beacon_frame_data(pcap_file)

    for i, packet_info in enumerate(beacon_data):
        print(f"Packet #{i+1}: {packet_info}")
