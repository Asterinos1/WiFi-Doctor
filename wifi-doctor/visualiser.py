import matplotlib.pyplot as plt
import pandas as pd
import csv
from collections import defaultdict, deque
from performance_monitor import *

# Load RSSID log data
def load_rssid_log(file_path="rssid_log.csv"):
    timestamps, channels, rssid_values = [], [], []
    try:
        with open(file_path, "r") as csvfile:
            reader = csv.reader(csvfile)
            next(reader)  # Skip header
            for row in reader:
                timestamps.append(float(row[0]) / 1e6)  # Convert microseconds to seconds
                channels.append(int(row[1]))
                rssid_values.append(float(row[2]))
    except FileNotFoundError:
        print(f"File {file_path} not found.")
    return timestamps, channels, rssid_values

# Load RSSI log data
def load_rssi_log(file_path="rssi_log.csv"):
    timestamps, rssi_values = [], []
    try:
        with open(file_path, "r") as csvfile:
            reader = csv.reader(csvfile)
            next(reader)  # Skip header
            for row in reader:
                timestamps.append(float(row[0]) / 1e6)  # Convert microseconds to seconds
                rssi_values.append(float(row[1]))
    except FileNotFoundError:
        print(f"File {file_path} not found.")
    return timestamps, rssi_values

# Function to plot RSSID over time
def plot_rssid_over_time():
    timestamps, channels, rssid_values = load_rssid_log()  # Load data from CSV

    if not timestamps:
        print("No RSSID data available.")
        return

    plt.style.use("ggplot")  # Clean white background
    plt.figure(1,figsize=(10, 5))

    unique_channels = set(channels)  # Get unique channels

    for channel in sorted(unique_channels):
        # Get indices where this channel appears
        channel_indices = [i for i, ch in enumerate(channels) if ch == channel]
        channel_timestamps = [timestamps[i] for i in channel_indices]
        channel_rssid_values = [rssid_values[i] for i in channel_indices]

        #plt.scatter(channel_timestamps, channel_rssid_values, label=f"Channel {channel}", alpha=0.7, edgecolors="black")
        # Plot connected line + scatter for better visibility
        plt.plot(channel_timestamps, channel_rssid_values, label=f"Channel {channel}", linestyle="-", marker="o", alpha=0.8)

    plt.xlabel("Time (seconds)")
    plt.ylabel("RSSID")
    plt.title("RSSID Over Time")
    plt.grid(True, linestyle="--", alpha=0.7)
    plt.legend()

    # Format x-axis: Show only seconds, avoid clutter
    plt.xticks(rotation=30)
    plt.gca().xaxis.set_major_locator(plt.MaxNLocator(integer=True))

    plt.savefig("rssid_plot.png")
    plt.show()
    # plt.savefig("rssid_plot.png")


# Plot RSSI (signal strength) over time
def plot_signal_strength_over_time():
    timestamps, rssi_values = load_rssi_log()
    if not timestamps:
        return
    
    plt.figure(2,figsize=(10, 5))
    plt.plot(timestamps, rssi_values, marker='o', linestyle='-', color='b', alpha=0.7)
    plt.xlabel("Time (seconds)")
    plt.ylabel("RSSI (dBm)")
    plt.title("Signal Strength Over Time")
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.savefig("rssi_plot.png")
    plt.show()
    # plt.savefig("rssi_plot.png")

def print_throughput(throughput_data):
    print(f"Calculate Throughput: {throughput_data} Mbps")

def main():
    pcap_file = "pcap_files/faye2p4.pcap"
    device_mac = "dc:e9:94:2a:68:31"
    ap_mac = "d0:b6:6f:96:2b:b6"
    filtered_frames = {"0x0008", "0x0020", "0x0028"} 
    
    window_size = 10
    rssi_history = {}
    rssid_log = []
    last_activity = {}
    decay_rate = 0.1
    rssi_log = []
    
    packet_data = extract_all_data_testing_pcap(pcap_file)
    compute_density_metrics(packet_data, rssi_history, last_activity, decay_rate, window_size, rssid_log)
    save_rssid_log(rssid_log)
    
    our_data = no_filter_for_1_2(packet_data, ap_mac, device_mac)
    avg_rssi = compute_downlink_signal_strength(our_data, rssi_log)
    save_rssi_log(rssi_log)
    
    print(f"Average Downlink Signal Strength: {avg_rssi:.2f} dBm")
    print(analyze_signal_quality(avg_rssi))
    
    pcap_part2 = "pcap_files/1_2_test_pcap2.pcap"
    data_frames = filter_by_receiver(extract_all_data_testing_pcap(pcap_part2), device_mac, filtered_frames)
    throughput = calculate_throughput(data_frames)
    
    plot_rssid_over_time()
    plot_signal_strength_over_time()
    print_throughput(throughput)

if __name__ == "__main__":
    main()