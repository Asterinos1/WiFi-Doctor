import pyshark
from tqdm import tqdm
import pdf_data

def extract_all_data(pcap_file: str, packet_limit: int = 0) -> list:
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

    Args:
        pcap_file (str): path to the pcap file
        packet_limit (int): maximum number of packets to process. If 0, no limit is applied.

    Returns:
       List: Contains a dictionary for each packet in the pcap_file
    """

    capture = pyshark.FileCapture(pcap_file)
    extracted_data_all = []

    i = 0
    for packet in tqdm(capture, desc="Extracting Data", unit="packet"):
        if packet_limit != 0 and i >= packet_limit:
            break  # Stop the loop if the packet limit is reached

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
            'ssid': None,
            'timestamp': None
        }

        if hasattr(packet, 'wlan'):
            packet_data_all['bssid'] = getattr(packet.wlan, 'bssid', None)
            packet_data_all['transmitter_mac'] = getattr(packet.wlan, 'ta', None)
            packet_data_all['receiver_mac'] = getattr(packet.wlan, 'ra', None)
            packet_data_all['frame_type_subtype'] = getattr(packet.wlan, 'fc_type_subtype', None)
            packet_data_all['retry_flag'] = getattr(packet.wlan, 'fc.retry', None)

        # Small changes here regarding mcs index and short gi extraction.
        # Replacing possible capture of these attributes from the wlan_radio section
        # to radiotap section (found this on github <3)

        if hasattr(packet, 'wlan_radio'):
            packet_data_all['phy_type'] = getattr(packet.wlan_radio, 'phy', None)
            packet_data_all['mcs_index'] = getattr(packet.wlan_radio, '11ac.mcs_index', None)
            bandwidth = getattr(packet.wlan_radio, '11ac.bandwidth', None)
            packet_data_all['bandwidth'] = "20 MHz" if bandwidth == "0" else bandwidth
            packet_data_all['spatial_streams'] = getattr(packet.wlan_radio, '11ac.num_sts', None)
            packet_data_all['short_gi'] = getattr(packet.wlan_radio, '11ac.short_gi', None)
            packet_data_all['data_rate'] = getattr(packet.wlan_radio, 'data_rate', None)
            packet_data_all['channel'] = getattr(packet.wlan_radio, 'channel', None)
            packet_data_all['signal_strength'] = getattr(packet.wlan_radio, 'signal_dbm', None)
            packet_data_all['snr'] = getattr(packet.wlan_radio, 'snr', None)
            packet_data_all['timestamp'] = getattr(packet.wlan_radio, 'timestamp', None) 

        if hasattr(packet, 'radiotap'):
            if packet_data_all['mcs_index'] is None:
                packet_data_all['mcs_index'] = getattr(packet.radiotap, 'mcs_index', None)
            if packet_data_all['short_gi'] is None:
                packet_data_all['short_gi'] = getattr(packet.radiotap, 'mcs_short_gi', None)
            packet_data_all['frequency'] = getattr(packet.radiotap, 'channel_freq', None)

        #this is for ssid eg TUC   
        if 'wlan.mgt' in packet:
            ssid_tag = packet['wlan.mgt'].get('wlan.tag', None)
            timestamps =packet['wlan.mgt'].get('wlan_fixed_timestamp', None)
            #print(f"this is the {timestamps}\n\n")
            packet_data_all['timestamp'] = timestamps
            #print(f"\nFinal Extracted Data: {extracted_data_all}")
            #############################DES TO META ###########################################
            #packet_data_all['timestamp']  = packet['wlan.mgt'].get('wlan_fixed_timestamp', None)
            #############################DES TO META ###########################################
            if ssid_tag and 'SSID parameter set:' in ssid_tag:
                packet_data_all['ssid'] = ssid_tag.split('SSID parameter set: ')[-1].strip('"')
            else:
                packet_data_all['ssid'] = None  
        extracted_data_all.append(packet_data_all)
        i += 1  # Increment packet count

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

#briskei to expected mcs index basei to rssi tou pinaka
def find_expected_mcs_index(signal_strength, spatial_streams):

    if spatial_streams == 1:          
        if signal_strength >= -64:
            return 7  
        elif -65 <= signal_strength < -64:
            return 6 
        elif -66 <= signal_strength < -65:
            return 5
        elif -70 <= signal_strength < -66:
            return 4
        elif -74 <= signal_strength < -70:
            return 3
        elif -77 <= signal_strength < -74:
            return 2
        elif -79 <= signal_strength < -77:
            return 1
        else:
            return 0
    if spatial_streams == 2:
        if signal_strength >= -64:
            return 15   
        elif -65 <= signal_strength < -64:
            return 14 
        elif -66 <= signal_strength < -65:
            return 13
        elif -70 <= signal_strength < -66:
            return 12
        elif -74 <= signal_strength < -70:
            return 11
        elif -77 <= signal_strength < -74:
            return 10
        elif -79 <= signal_strength < -77:
            return 9
        else:
            return 8
    if spatial_streams == 3:
        if signal_strength >= -64:
            return 23  
        elif -65 <= signal_strength < -64:
            return 22 
        elif -66 <= signal_strength < -65:
            return 21
        elif -70 <= signal_strength < -66:
            return 20
        elif -74 <= signal_strength < -70:
            return 19
        elif -77 <= signal_strength < -74:
            return 18
        elif -79 <= signal_strength < -77:
            return 17
        else:
            return 16

def recover_missing_phy_info(packet, mcs_table):
    """
    Attempts to recover missing MCS Index and Spatial Stream information using the RSSI,
    data_rate, bandwidth, and short GI from the pdf_data table.
    Modifies the packet in-place.
    """
    try:
        # Extract required fields
        rssi = packet.get('signal_strength')
        data_rate = packet.get('data_rate')
        bandwidth = packet.get('bandwidth')
        short_gi = packet.get('short_gi')

        if None in (rssi, data_rate, bandwidth, short_gi):
            return  # Can't proceed

        rssi = float(rssi)
        data_rate = float(data_rate)
        gi_ns = 400 if str(short_gi).lower() in ['1', 'true', 'yes'] else 800
        bandwidth_mhz = int(bandwidth.split()[0])

        # Estimate spatial stream
        spatial_group = pdf_data.estimate_spatial_streams(rssi, bandwidth_mhz, gi_ns == 400, data_rate, mcs_table)
        if spatial_group:
            packet['spatial_streams'] = spatial_group

            # Estimate MCS index
            mcs_index = pdf_data.estimate_mcs_index(rssi, bandwidth_mhz, gi_ns == 400, data_rate, mcs_table)
            if mcs_index is not None:
                packet['mcs_index'] = mcs_index

    except Exception as e:
        print(f"[!] Error recovering PHY info: {e}")



#bazei rate gap sto data[dict]
def add_rate_gap(data_all: list) -> list:

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
                else:
                    packet['spatial_streams'] = None
            except ValueError:
                packet['spatial_streams'] = None
        
        if packet.get('signal_strength') is not None and packet.get('spatial_streams') is not None:
            try:
                signal_strength = int(packet['signal_strength'])
                spatial_streams = int(packet['spatial_streams'])
                expected_mcs_index = find_expected_mcs_index(signal_strength, spatial_streams)

                # Compute the rate gap
                actual_mcs_index = int(packet['mcs_index']) if packet.get('mcs_index') is not None else 0
                packet['rate_gap'] = find_rate_gap(expected_mcs_index, actual_mcs_index)

            except (ValueError, TypeError):
                packet['rate_gap'] = None  

    return data_all


## ORIZOUME EMEIS ENA BASELINE -> kinito dipla sto router einai to ideal
## MCS INDEX
def find_rate_gap(expected_mcs_index, actual_mcs_index):

    return expected_mcs_index-actual_mcs_index

def filter_for_1_2(data_all: list, source_mac: str, dest_mac: str, filter) -> list:
    """
    Filters the packets with the corresponding source MAC and destination MAC with a specific filter.
    
    Args:
        data_all (list): List of dictionaries with the extracted data from extract_all_data().
        source_mac (str): The source MAC address to filter.
        dest_mac (str): The destination MAC address to filter.
        filter: The filter to match on the "frame_type_subtype" field.

    Returns:
        list: A filtered list with only packets matching the source and destination MAC addresses and frame_type_subtype.
    """
    filtered_packets = [
        packet for packet in data_all
        if packet.get("transmitter_mac") == source_mac 
        and packet.get("receiver_mac") == dest_mac 
        and packet.get("frame_type_subtype") == filter
    ]
    
    print(f"Number of packets passing the filter: {len(filtered_packets)}")
    
    return filtered_packets

def annotate_performance(data_all: list) -> None:
    """
    Iterates over the packet list and prints diagnostic annotations for each packet:
    - Wi-Fi configuration status
    - Rate gap interpretation
    - Interference indicators

    This version does not modify or return the data — it only prints.
    """
    for i, packet in enumerate(data_all):
        print(f"\n--- Packet #{i+1} ---")

        # -- Wi-Fi Configuration Comments --
        config_issues = []
        phy = packet.get('phy_type', '').lower()
        bandwidth = packet.get('bandwidth')
        short_gi = packet.get('short_gi')

        if phy in ['802.11a', '802.11b', '802.11g']:
            config_issues.append("Legacy PHY type")
        if bandwidth == '20 MHz':
            config_issues.append("Low bandwidth")
        if short_gi in ['0', 'False', False]:
            config_issues.append("Short GI not enabled")

        config_comment = ", ".join(config_issues) if config_issues else "Good configuration"
        print(f"[Config] {config_comment}")

        # -- Rate Gap Analysis --
        rate_gap = packet.get('rate_gap')
        if rate_gap is not None:
            try:
                rg = int(rate_gap)
                if rg >= 3:
                    rate_gap_comment = "Significant underperformance"
                elif rg > 0:
                    rate_gap_comment = "Slight underperformance"
                elif rg == 0:
                    rate_gap_comment = "Expected performance"
                else:
                    rate_gap_comment = "Rate adaptation overshoot"
            except ValueError:
                rate_gap_comment = "Invalid rate_gap format"
        else:
            rate_gap_comment = "No rate gap info"
        print(f"[Rate Gap] {rate_gap_comment}")

        # -- Interference / Channel Comments --
        interference = []
        retry_flag = packet.get('retry_flag')
        snr = packet.get('snr')

        if retry_flag == '1':
            interference.append("High retry rate - possible interference")

        if snr is not None:
            try:
                snr_val = float(snr)
                if snr_val < 20:
                    interference.append("Low SNR - noisy channel")
            except ValueError:
                interference.append("Invalid SNR format")

        interference_comment = ", ".join(interference) if interference else "No interference signs"
        print(f"[Interference] {interference_comment}")

def filter_phy_info_packets(data_all: list) -> list:
    """
    Filters packets that contain at least one of the following PHY-layer fields:
    - bandwidth
    - mcs_index
    - short_gi

    Args:
        data_all (list): The list of packet dictionaries.

    Returns:
        list: A filtered list containing only packets with at least one of the PHY-layer fields.
    """
    filtered_packets = []
    counter=0
    for packet in data_all:
        if packet.get('bandwidth') is not None or \
           packet.get('mcs_index') is not None or \
           packet.get('short_gi') is not None:
            filtered_packets.append(packet)
            counter+=1

    print(f"Number of packets with PHY info (bandwidth, mcs_index, short_gi): {len(filtered_packets)}")
    return filtered_packets



def print_packet_data(data_all: list, limit: int = 0) -> None:
    """
    Prints the full contents of packets in the data list.
    
    Args:
        data_all (list): The list of packet dictionaries to print.
        limit (int): Optional maximum number of packets to print. 
                     If 0, all packets will be printed.
    """
    count = 0
    for i, packet in enumerate(data_all):
        if limit != 0 and count >= limit:
            break

        print(f"\n===== Packet #{i+1} =====")
        for key, value in packet.items():
            print(f"{key}: {value}")
        count += 1


if __name__ == "__main__":
    print("Starting parser...")

    print("Obtaining data for mcs index calculation.")
    mcs_table = pdf_data.initialize_data()

    pcap_file = 'analyzer/pcap_files/1_2_testing_pcap_files/1_2_test_pcap2.pcap'  

    print(f"Moving to extract data from {pcap_file}")
    data = extract_all_data(pcap_file)
    print("Calculating rate gap...")
    data = add_rate_gap(data)
    print("Rate gap calculation complete.\nData is ready for analysis.")    
    
    print("Calculating missing MCS indexs:")

    phy_packets = filter_phy_info_packets(data)

    for packet in phy_packets:
        recover_missing_phy_info(packet, mcs_table)

    # phy_packets = filter_phy_info_packets(data)

    print_packet_data(phy_packets)    

    # annotate_performance(data)

    #data = find_spatial_streams(data)
    #filter beacon frames
    #beacon_frame_data = filter_beacon_frames(data)

    # communication_packets = filter_for_1_2(data, "2c:f8:9b:dd:06:a0", "00:20:a6:fc:b0:36", "0x0028")
    # print_packet_data(communication_packets)

    # print("\nBeacon Frames:")
    # for i, packet_info in enumerate(communication_packets):
    #     #if((packet_info['mcs_index'] != '130') and (packet_info['short_gi'] == False)):
    #     print(f"Packet #{i+1}: {packet_info}")
