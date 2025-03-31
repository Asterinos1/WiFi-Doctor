import pyshark
from tqdm import tqdm
import pdf_data
import matplotlib.pyplot as plt
import os
import numpy as np
import pandas as pd

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
    counter=0

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
                counter+=1
            except (ValueError, TypeError):
                packet['rate_gap'] = None  

    print(f"Total rate_gap calculations: {counter}")
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
    
    print(f"Number of packets passing the filter (HowIWiFi_PCAP.pcap required): {len(filtered_packets)}")
    
    return filtered_packets

# modified the method to save the results to file rather than printing them.
def annotate_performance(data_all: list, file_writer) -> None:
    """
    Iterates over the packet list and prints diagnostic annotations for each packet:
    - [1] Wi-Fi configuration status: PHY type, bandwidth, and Short GI are interpreted.
    - [2] Rate gap interpretation: Shows how far the actual MCS index deviates from expected.
    - [3] Interference indicators: Applies inference rules from literature to detect channel issues.
    """
    PHY_TYPE_MAPPING = {
        "1": "FHSS (very old)",
        "2": "DSSS (very old)",
        "3": "IR Baseband",
        "4": "OFDM (802.11a/g)",
        "5": "HR/DSSS (802.11b)",
        "6": "ERP (802.11g)",
        "7": "HT (802.11n)",
        "8": "DMG (802.11ad)",
        "9": "VHT (802.11ac)",
        "10": "HE (802.11ax - Wi-Fi 6)",
        "11": "EHT (802.11be - Wi-Fi 7)"
    }

    for i, packet in enumerate(data_all):
        #print(f"\n--- Packet #{i+1} ---")
        file_writer.write(f"\n--- Packet #{i+1} ---")

        # === [1] Wi-Fi Configuration Status ===
        # This block interprets the PHY layer config of the packet:
        # - PHY type is mapped to standard name
        # - Bandwidth is translated and annotated
        # - Short GI (guard interval) is explained in terms of performance tradeoffs
        config_notes = []
        raw_phy = packet.get('phy_type', '').lower()
        bandwidth = packet.get('bandwidth')
        short_gi = packet.get('short_gi')

        # PHY Type
        if raw_phy.isdigit():
            phy_desc = PHY_TYPE_MAPPING.get(raw_phy, "Unknown PHY")
            config_notes.append(f"PHY Type {raw_phy} -> {phy_desc}")
        elif raw_phy:
            config_notes.append(f"PHY Type: {raw_phy}")
        else:
            config_notes.append("PHY Type: Unavailable")

        # Bandwidth Interpretation
        if isinstance(bandwidth, str):
            bw_clean = bandwidth.strip().lower()
            if "20" in bw_clean:
                config_notes.append("Bandwidth: 20 MHz (narrow channel, lower capacity, more robust to interference)")
            elif "40" in bw_clean:
                config_notes.append("Bandwidth: 40 MHz (moderate channel width, balanced capacity and interference risk)")
            elif "80" in bw_clean:
                config_notes.append("Bandwidth: 80 MHz (high-speed channel, higher throughput, more sensitive to noise)")
            elif "160" in bw_clean:
                config_notes.append("Bandwidth: 160 MHz (very wide channel, maximum speed, highly susceptible to interference)")
            else:
                config_notes.append(f"Bandwidth: {bandwidth} (unknown format)")
        else:
            config_notes.append("Bandwidth: Unavailable")

        # Short GI Interpretation
        if str(short_gi).lower() in ['0', 'false', 'none']:
            config_notes.append("Short GI: Disabled (lower error rate, but slightly reduced throughput)")
        elif str(short_gi).lower() in ['1', 'true', 'yes']:
            config_notes.append("Short GI: Enabled (higher throughput – but more sensitive to multipath interference)")
        elif short_gi is not None:
            config_notes.append(f"Short GI: {short_gi} (non-standard value)")
        else:
            config_notes.append("Short GI: Unknown")

        #print(f"[1] Config: {', '.join(config_notes)}")
        file_writer.write(f"\n[1] Config: {', '.join(config_notes)}")

        # === [2] Rate Gap Interpretation ===
        # We compare the expected MCS index (based on RSSI) with the actual one to detect underperformance.
        # A small rate gap is normal, but large deviations point to either interference or suboptimal rate adaptation.
        rate_gap = packet.get('rate_gap')
        if rate_gap is not None:
            try:
                rg = int(rate_gap)
                if rg == 0:
                    rate_gap_comment = "Expected performance (rate gap: 0)"
                elif 0 < rg <= 3:
                    rate_gap_comment = f"Slight performance drop - still below threshold (rate gap: {rg})"
                elif rg > 3:
                    rate_gap_comment = f"Performance getting poorer - surpassed threshold (rate gap: {rg})"
                elif rg < 0:
                    rate_gap_comment = f"Rate overshoot (rate gap: {rg})"
            except ValueError:
                rate_gap_comment = f"Invalid rate_gap format: {rate_gap}"
        else:
            rate_gap_comment = "No rate gap info"
        #print(f"[2] Rate Gap: {rate_gap_comment}")
        file_writer.write(f"\n[2] Rate Gap: {rate_gap_comment}")

        # === [3] Interference Indicators ===
        # This section applies multiple heuristic rules (based on the paper) to detect symptoms of interference:
        # - High RateGap despite good RSSI
        # - High retries with good SNR
        # - Low SNR in general
        # - Wide bandwidth links underperforming
        interference = []
        retry_flag = packet.get('retry_flag')
        snr = packet.get('snr')
        rssi = packet.get('signal_strength')
        rg = None
        try:
            rg = int(packet['rate_gap']) if packet.get('rate_gap') is not None else None
        except ValueError:
            rg = None

        # Retry flag-based
        if retry_flag == '1':
            interference.append("High retry rate , retransmissions suggest interference, contention or signal loss")

        # SNR-based
        if snr is not None:
            try:
                snr_val = float(snr)
                if snr_val < 20:
                    interference.append(f"Low SNR ({snr_val:.1f} dB) , poor signal quality or noise")
                else:
                    interference.append(f"SNR: {snr_val:.1f} dB , signal quality acceptable")
            except ValueError:
                interference.append("Invalid SNR format")

        # === Interference Detection Heuristics ===
        # Each condition below raises the probability that this packet suffered from interference.

        interference_detected = False

        # High RateGap + Good RSSI ⇒ likely interference or poor rate adaptation
        try:
            if rg is not None and rg > 3 and rssi is not None:
                rssi_val = int(rssi)
                if rssi_val > -70:
                    interference.append("Strong signal (RSSI > -70 dBm) but poor rate , interference likely")
                    interference_detected = True
        except ValueError:
            pass

        # Retry + Good SNR ⇒ hidden terminals or medium access contention
        try:
            if retry_flag == '1' and snr is not None and float(snr) >= 20:
                interference.append("Retries despite good SNR , possible hidden terminals or congested medium")
                interference_detected = True
        except ValueError:
            pass

        # Wide Bandwidth + RateGap ⇒ high sensitivity to interference
        try:
            bw_str = str(packet.get('bandwidth')).lower()
            if rg is not None and rg > 3 and any(x in bw_str for x in ['80', '160']):
                interference.append(f"Wide bandwidth ({bw_str}) with poor performance , likely interference or poor channel conditions")
                interference_detected = True
        except Exception:
            pass

        # Final result printing
        if not interference:
            interference_comment = "Little to none interference signs"
        else:
            interference_comment = ", ".join(interference)
            if not interference_detected:
                interference_comment += " , symptoms present but interference not strongly confirmed"

        #print(f"[3] Interference: {interference_comment}")
        file_writer.write(f"\n[3] Interference: {interference_comment}")


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

# on this visualizer part.
def plot_all_in_one(packets, pcap_file_name):
    # Process data
    timestamps = list(range(len(packets)))
    signal_values = [int(p['signal_strength']) for p in packets if p.get('signal_strength')]
    mcs_vals = [int(p['mcs_index']) for p in packets if p.get('mcs_index')]
    mcs_timestamps = [i for i, p in enumerate(packets) if p.get('mcs_index')]
    dr_vs_rssi = [(float(p['data_rate']), int(p['signal_strength']))
                  for p in packets if p.get('data_rate') and p.get('signal_strength')]
    
    retry_flags = []

    for p in packets:
        retry_raw = p.get('retry_flag')
        if retry_raw is not None:
            val = str(retry_raw).strip().lower()
            if val in ['1', 'true']:
                retry_flags.append(1)
            elif val in ['0', 'false']:
                retry_flags.append(0)


    # Create 2x2 subplots
    fig, axs = plt.subplots(2, 2, figsize=(12, 9))
    fig.suptitle(f"{pcap_file_name} Analysis", fontsize=16)

    # --- (1,1): Signal Strength Over Time
    axs[0, 0].plot(timestamps[:len(signal_values)], signal_values, marker='o')
    axs[0, 0].set_title("Signal Strength Over Time")
    axs[0, 0].set_xlabel("Packet #")
    axs[0, 0].set_ylabel("Signal Strength (dBm)")
    axs[0, 0].grid()

    # --- (1,2): Retry Distribution
    axs[0, 1].hist(retry_flags, bins=[-0.5, 0.5, 1.5], rwidth=0.6)
    axs[0, 1].set_xticks([0, 1])
    axs[0, 1].set_xticklabels(["No Retry", "Retry"])
    axs[0, 1].set_title("Retry Flag Distribution")
    axs[0, 1].set_xlabel("Retry Flag")
    axs[0, 1].set_ylabel("Count")
    axs[0, 1].grid()

    # --- (2,1): MCS Index Over Time
    axs[1, 0].plot(mcs_timestamps, mcs_vals, marker='.', color='purple')
    axs[1, 0].set_title("MCS Index Over Time")
    axs[1, 0].set_xlabel("Packet #")
    axs[1, 0].set_ylabel("MCS Index")
    axs[1, 0].grid()

    # --- (2,2): Data Rate vs Signal Strength
    if dr_vs_rssi:
        # Convert to DataFrame for grouping
        df = pd.DataFrame(dr_vs_rssi, columns=["data_rate", "signal_strength"])

        # Bin the signal strength (e.g., every 5 dBm)
        bin_width = 5
        df['rssi_bin'] = (df['signal_strength'] // bin_width) * bin_width  # floor binning

        # Compute average data rate per signal bin
        grouped = df.groupby('rssi_bin')['data_rate'].mean().reset_index()

        # Sort bins (optional, for correct bar order)
        grouped = grouped.sort_values('rssi_bin')

        # Plot bar chart
        axs[1, 1].bar(grouped['rssi_bin'].astype(str), grouped['data_rate'], width=0.8)
        axs[1, 1].set_title("Avg Data Rate per Signal Strength Bin")
        axs[1, 1].set_xlabel("Signal Strength (dBm bins)")
        axs[1, 1].set_ylabel("Average Data Rate (Mbps)")
        axs[1, 1].tick_params(axis='x', rotation=45)
        axs[1, 1].grid(axis='y')

    # Final layout
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])  # leave room for suptitle
    plt.show()



if __name__ == "__main__":

    pcap_file = 'analyzer/pcap_files/gotterdammerung/GOTTERDAMMERUNG_1.pcap' 

    # Extract filename without extension for analysis output
    pcap_base = os.path.splitext(os.path.basename(pcap_file))[0]

    # Create the output directory if it doesn't exist
    output_dir = "analysis results"
    os.makedirs(output_dir, exist_ok=True)

    # Path to the analysis output file
    analysis_file_path = os.path.join(output_dir, f"{pcap_base}_analysis.txt")

    print("Starting parser...")
    print("Obtaining data for mcs index calculation.")
    mcs_table = pdf_data.initialize_data() 

    print(f"Moving to extract data from {pcap_file}")
    data = extract_all_data(pcap_file)
    print("Calculating rate gap...")
    # data = add_rate_gap(data)
    print("Rate gap calculation complete.")    
    print("Calculating missing MCS indexs:")

    data = filter_phy_info_packets(data)

    for packet in data:
        recover_missing_phy_info(packet, mcs_table)

    data = add_rate_gap(data)

    # print("\n\t ** Calculation of MCS Index and Spatial group complete. **\n")
    print("Data is ready to be analyzed!.")

    # phy_packets = filter_phy_info_packets(data)

    with open(analysis_file_path, "w") as f:
        annotate_performance(data, f)

    print(f"Analysis written to: {analysis_file_path}")
    
    plot_all_in_one(data, pcap_file)

    # data = find_spatial_streams(data)
    # filter beacon frames
    # beacon_frame_data = filter_beacon_frames(data)

    communication_packets = filter_for_1_2(data, "2c:f8:9b:dd:06:a0", "00:20:a6:fc:b0:36", "0x0028")

    # # print_packet_data(communication_packets)

    # print("\nBeacon Frames:")
    # for i, packet_info in enumerate(communication_packets):
    #     #if((packet_info['mcs_index'] != '130') and (packet_info['short_gi'] == False)):
    #     print(f"Packet #{i+1}: {packet_info}")