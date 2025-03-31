from parser_for_testings import *
import csv
import time
import math
from collections import defaultdict,deque

"""
    Updates the RSSI history for a given SSID and Channel, and computes the Weighted Moving Average (WMA).
    
    Args:
        ssid (str): The SSID of the Wi-Fi network.
        channel (int): The channel the network is operating on.
        new_rssi (int): The new RSSI value detected.
        timestamp (float): The timestamp of the packet.
        rssi_history(dictionary): list of logged rssi's for each (ssid-channel) pair
        last_activity(dictionary): list of last shown timestamp(packet) for each ssid
        window_size(int): max length of rssi_history

    Returns:
        float: The computed Weighted Moving Average (WMA) of RSSI values for the SSID-channel pair.
"""
def update_rssi(ssid, channel, new_rssi, timestamp, rssi_history, last_activity, window_size):
    key = (ssid, channel)  # Track RSSI per SSID-Channel pair

    if key not in rssi_history:
        rssi_history[key] = deque(maxlen=window_size)
    
    
    rssi_history[key].append((new_rssi,timestamp))
    last_activity[key] = timestamp  # Update last seen time
    
    return compute_wma(key, rssi_history)



"""
    Computes the Weighted Moving Average (WMA) for the stored RSSI values of an SSID-Channel pair.
    
    Args:
        key (tuple): A tuple (SSID, Channel) identifying the RSSI values.
        rssi_history(dictionary): list of logged rssi's for each (ssid-channel) pair
    
    Returns:
        float: The computed WMA of the RSSI values rounded to 2 decimal places.
"""
def compute_wma(key, rssi_history):
    rssi_tuples = list(rssi_history[key])  # List of (RSSI, timestamp) tuples
    rssi_values = [rssi for rssi, _ in rssi_tuples]  # Extract just RSSI values
    n = len(rssi_values)
    
    if n == 0:
        return None
    
    weights = [i + 1 for i in range(n)]  # Assigning higher weight to more recent values
    wma = sum(rssi * weight for rssi, weight in zip(rssi_values, weights)) / sum(weights) #Computing the average
    
    return round(wma, 2)


"""
    Computes the weight of an SSID based on the last activity, using an exponential decay function.
    
    Args:
        key (tuple): A tuple (SSID, Channel) identifying the RSSI values.
        current_packet_timestamp (float): The timestamp of the current packet.
        last_activity(dictionary): list of last shown timestamp(packet) for each ssid
        decay_rate (float): Exponential decay factor that controls how quickly old SSID values lose significance.
                            A higher value means faster decay, while a lower value retains past activity longer.  
    
    Returns:
        float: The computed weight (a value between 0 and 1).
"""
def compute_weight(key, current_packet_timestamp, last_activity, decay_rate):
    last_seen = last_activity.get(key, current_packet_timestamp)  # Default to packet timestamp if not found

    last_seen = float(last_seen)
    current_packet_timestamp = float(current_packet_timestamp)

    elapsed_time = (current_packet_timestamp - last_seen)/ 1e6  # Convert microseconds to seconds

    return math.exp(-decay_rate * elapsed_time)  # Exponential decay


"""
    Computes the RSSID (Wi-Fi density metric) for each channel based on weighted RSSI values.
    
    Args:
        timestamp (float): The timestamp of the packet.
        rssi_history(dictionary): list of logged rssi's for each (ssid-channel) pair
        last_activity(dictionary): list of last shown timestamp(packet) for each ssid
        decay_rate (float): Exponential decay factor that controls how quickly old SSID values lose significance.
                            A higher value means faster decay, while a lower value retains past activity longer. 
    
    Returns:
        dict: A dictionary mapping channels to their computed RSSID values.
"""
def compute_rssid_per_channel(timestamp, rssi_history, last_activity, decay_rate):
    rssid_per_channel = defaultdict(float)

    for (ssid, channel), rssi_values in rssi_history.items():
        wma = compute_wma((ssid, channel), rssi_history)
        if wma is not None:
            if wma != 0:
                rssid_per_channel[channel] += (1 / abs(wma)) * compute_weight((ssid, channel), timestamp, last_activity, decay_rate)
    
    return {channel: round(value, 4) for channel, value in rssid_per_channel.items()}

"""
    Logs the RSSID value for each channel at a given packet timestamp.
    
    Args:
        packet_timestamp: (float) Timestamp of the packet in microseconds.
        rssi_history(dictionary): list of logged rssi's for each (ssid-channel) pair
        last_activity(dictionary): list of last shown timestamp(packet) for each ssid
        decay_rate (float): Exponential decay factor that controls how quickly old SSID values lose significance.
                            A higher value means faster decay, while a lower value retains past activity longer. 
        rssid_log(list): list of logged rssid values

    Returns:
        Nothing
"""
def log_rssid(packet_timestamp, rssi_history, last_activity, decay_rate, rssid_log):  # Accept packet's actual timestamp
    rssid_per_channel = compute_rssid_per_channel(packet_timestamp, rssi_history, last_activity, decay_rate)

    if rssid_per_channel:
        for channel, rssid_value in rssid_per_channel.items():
            rssid_log.append((packet_timestamp, channel, rssid_value))  


"""
    Saves the logged RSSID values to a CSV file.
    
    Args:
        rssid_log(list): list of logged rssid values
        file_path: (str) Path to the CSV file where RSSID logs will be saved(defaults to rssid_log.csv if not specified).
"""
def save_rssid_log(rssid_log, file_path="rssid_log.csv"):
    with open(file_path, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Timestamp", "Channel", "RSSID"])
        writer.writerows(rssid_log)
    print(f"RSSID log saved to {file_path}")


"""
    Computes Wi-Fi density metrics based on packet data by updating RSSI values,
    computing RSSID, and logging the results.
    
    Args:
        packet_data: (list) List of packet dictionaries containing SSID, signal strength, channel, and timestamp.
        rssi_history(dictionary): list of logged rssi's for each (ssid-channel) pair
        last_activity(dictionary): list of last shown timestamp(packet) for each ssid
        decay_rate (float): Exponential decay factor that controls how quickly old SSID values lose significance.
                            A higher value means faster decay, while a lower value retains past activity longer. 
        window_size(int): max length of rssi_history
        rssid_log(list): list of logged rssid values
    Returns:
        Nothing
"""
def compute_density_metrics(packet_data, rssi_history, last_activity, decay_rate, window_size, rssid_log):
    
    for packet in packet_data:
        ssid = packet.get('ssid')
        signal_strength = packet.get('signal_strength')
        channel = packet.get('channel')  # Extract channel info
        timestamp = packet.get('tsf_timestamp')
        
        if ssid and signal_strength and channel and timestamp:
            try:
                signal_strength = int(signal_strength)
                channel = int(channel)  # Convert channel to integer
                update_rssi(ssid, channel, signal_strength, timestamp, rssi_history, last_activity, window_size)
                log_rssid(timestamp, rssi_history, last_activity, decay_rate, rssid_log)
            except ValueError:
                continue


"""
    Computes the average downlink signal strength from AP to the device.
    
    Args:
        rssi_log(list): list of logged rssi values
        packet_data (list): List of packets containing RSSI values.
    
    Returns:
        float: The average RSSI value in dBm.
"""
def compute_downlink_signal_strength(packet_data, rssi_log): 

    for packet in packet_data:
        signal_strength = packet.get('signal_strength')
        packet_timestamp = packet.get('tsf_timestamp')  

        if signal_strength and packet_timestamp:
            try:
                signal_strength = int(signal_strength)
                rssi_log.append((packet_timestamp, signal_strength))  # Log timestamped signal strength
            except ValueError:
                continue
    
    if rssi_log:
        avg_rssi = sum(value for _, value in rssi_log) / len(rssi_log)  # Compute average from log
        return avg_rssi
    else:
        return None


"""
    Analyzes Wi-Fi signal quality based on signal strength (RSSI in dBm).
    
    Args:
        signal_strength: (int) The RSSI value in dBm.
    Returns:
        (str): Description of expected signal quality.
"""
def analyze_signal_quality(signal_strength):
    if signal_strength >= -30:
        return "Maximum signal strength, you are probably standing right next to the access point."
    elif signal_strength >= -55:
        return "Excellent signal strength."
    elif signal_strength >= -67:
        return "Reliable signal strength – adequate for VoIP and most applications."
    elif signal_strength >= -80:
        return "Unreliable signal strength."
    elif signal_strength >= -90:
        return "Chances of connecting are very low at this level."
    else:
        return "No usable signal detected."


"""
    Saves the RSSI log to a CSV file.
    
    Args:
        rssi_log(list): list of logged rssi values
        file_path(String): The path the file should be saved(defaults to rssi_log.csv if not specified)

    Returns:
        Nothing
"""
def save_rssi_log(rssi_log, file_path="rssi_log.csv"):
    with open(file_path, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Timestamp", "RSSI"])
        writer.writerows(rssi_log)
    print(f"RSSI log saved to {file_path}")


"""
    Computes the theoretical downlink throughput based on data rate and frame loss rate.
    
    Args:
        data_frames (list): List of data frames containing retry flags and data rates.
    
    Returns:
        float: The calculated throughput in Mbps.
"""
def calculate_throughput(data_frames):
    if not data_frames:
        print("No data frames available for throughput calculation.")
        return 0
    
    frame_loss_rate = calculate_frame_loss(data_frames)
    
    # Compute average data rate
    data_rates = [float(packet.get("data_rate", 0)) for packet in data_frames if "data_rate" in packet]
    avg_data_rate = sum(data_rates) / len(data_rates) if data_rates else 0

    throughput = avg_data_rate * (1 - frame_loss_rate)
    return throughput


"""
    Computes the frame loss rate based on retry flags in Wi-Fi packets.
    
    Args:
        data_frames (list): List of data frames containing retry flags.
    
    Returns:
        float: The computed frame loss rate (value between 0 and 1).
"""
def calculate_frame_loss(data_frames):
    retried_frames = [packet for packet in data_frames if packet.get("retry_flag") == "1"]
    frame_loss_rate = len(retried_frames) / len(data_frames) if len(data_frames) > 0 else 0
    return frame_loss_rate


def main():
    pcap_file = 'pcap_files/faye2p4.pcap'
    device_mac = "dc:e9:94:2a:68:31"
    ap_mac = "d0:b6:6f:96:2b:b6" #d0:b6:6f:96:2b:bb
    filtered_frames = {"0x0008", "0x0020", "0x0028"} 
    wlan_ra = "02:33:f6:61:e2:57"
    wlan_sa = "d0:b6:6f:96:2b:b0" 


    # For Wi-Fi Density Metrics
    window_size = 10  # Number of RSSI readings to store for Weighted Moving Average (WMA)
    rssi_history = {}  # Dictionary to store recent RSSI values for each (SSID, Channel) pair
    rssid_log = []  # Stores computed RSSID values over time
    last_activity = {}  # Stores last seen timestamp for each SSID
    # Controls exponential decay of SSID weight
    decay_rate = 0.1  # probably good between 0.1-0.01(especially in big pcaps you can make DR even smaller)

    #For the signal strength quality metric
    rssi_log = []  # Stores (timestamp, signal_strength)(only data frames AP->Our Device) over time 

    
    #Density Metrics
    #If we want to analyze every single packet
    packet_data = extract_all_data_testing_pcap(pcap_file)

    #If we want to analyze only beacon and data frames
    #packet_data = filter_beacon_and_data_frames(extract_all_data_testing_pcap(pcap_file))

    compute_density_metrics(packet_data, rssi_history, last_activity, decay_rate, window_size, rssid_log)
    save_rssid_log(rssid_log,"rssid_log.csv")

    #Calculate how good our signal strength is
    our_data = no_filter_for_1_2(packet_data, ap_mac, device_mac)
    avg_rssi = compute_downlink_signal_strength(our_data, rssi_log)
    if avg_rssi:
        print(analyze_signal_quality(avg_rssi))
    save_rssi_log(rssi_log, "rssi_log.csv")
    

    '''
    data_frames = no_filter_for_1_2(extract_all_data_testing_pcap(pcap_file), wlan_sa, wlan_ra)
    calculate_throughput(data_frames)
    '''

    
    pcap_part2 = "pcap_files/1_2_test_pcap2.pcap"
    data_frames = filter_by_receiver(extract_all_data_testing_pcap(pcap_part2), "dc:e9:94:2a:68:31", filtered_frames)
    calculate_throughput(data_frames)
    

if __name__ == '__main__':
	main()