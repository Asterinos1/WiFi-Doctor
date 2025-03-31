# wifi_doctor.py
import os
import pathlib
from parser_all import extract_all_data, add_rate_gap, filter_for_1_2
from parser_for_testings import extract_all_data_testing_pcap as extract_testing, no_filter_for_1_2 as no_filter_test
from parser_home import extract_all_data_testing_pcap as extract_home, no_filter_for_1_2 as no_filter_home

from performance_monitor import (
    compute_density_metrics, save_rssid_log, compute_downlink_signal_strength,
    analyze_signal_quality, save_rssi_log, calculate_throughput
)
from visualiser import plot_rssid_over_time, plot_signal_strength_over_time, print_throughput
from analyzer import annotate_performance, plot_all_in_one

def get_parser_choice():
    print("\nSelect Parser:")
    print("1) parser_all")
    print("2) parser_for_testing")
    print("3) parser_home")
    print("4) Exit")
    return input("Enter your choice: ").strip()

def get_pcap_file():
    print("\nAvailable PCAP files:")
    current_dir = pathlib.Path(__file__).parent
    pcap_dir = current_dir / "pcap_files"

    if not pcap_dir.exists():
        print(f"[ERROR] Could not find directory: {pcap_dir}")
        return None

    files = [f for f in pcap_dir.iterdir() if f.suffix == ".pcap"]
    if not files:
        print("No .pcap files found in pcap_files/")
        return None

    for i, file in enumerate(files, 1):
        print(f"{i}) {file.name}")
    choice = int(input("Select a file: "))
    return str(files[choice - 1])

def run_analysis(pcap_file, parser_name):
    print(f"\n[INFO] Running Wi-Fi Doctor using parser: {parser_name}")
    
    file_name = os.path.basename(pcap_file)
    # Load and parse packets
    if parser_name == "parser_all":
        data = extract_all_data(pcap_file)
        data = add_rate_gap(data)
        
        if file_name == "HowIWiFi_PCAP.pcap":
            print("HowIWiFi_PCAP.pcap (downlink) detected.")
            communication_packets = filter_for_1_2(data, "2c:f8:9b:dd:06:a0", "00:20:a6:fc:b0:36", "0x0028")
        elif file_name == "faye2p4.pcap":
            print("faye2p4.pcap (downlink)  detected.")
            communication_packets = no_filter_test(data, "d0:b6:6f:96:2b:b6", "dc:e9:94:2a:68:31")
        elif file_name in ["1_2_test_pcap1.pcap", "1_2_test_pcap2.pcap"]:
            print("1_2_test_pcapX.pcap (downlink)  detected.")
            communication_packets = no_filter_test(data, "d0:b6:6f:96:2b:bb", "dc:e9:94:2a:68:31")
        else:
            communication_packets = data

    elif parser_name == "parser_for_testing":
        data = extract_testing(pcap_file)
        data = add_rate_gap(data)

        if file_name == "HowIWiFi_PCAP.pcap":
            print("HowIWiFi_PCAP.pcap (downlink) detected.")
            communication_packets = filter_for_1_2(data, "2c:f8:9b:dd:06:a0", "00:20:a6:fc:b0:36", "0x0028")
        elif file_name == "faye2p4.pcap":
            print("faye2p4.pcap (downlink)  detected.")
            communication_packets = no_filter_test(data, "d0:b6:6f:96:2b:b6", "dc:e9:94:2a:68:31")
        elif file_name in ["1_2_test_pcap1.pcap", "1_2_test_pcap2.pcap"]:
            print("1_2_test_pcapX.pcap (downlink)  detected.")
            communication_packets = no_filter_test(data, "d0:b6:6f:96:2b:bb", "dc:e9:94:2a:68:31")
        else:
            communication_packets = data
    elif parser_name == "parser_home":
        data = extract_home(pcap_file)
        data = add_rate_gap(data)

        if file_name == "HowIWiFi_PCAP.pcap":
            print("HowIWiFi_PCAP.pcap (downlink) detected.")
            communication_packets = filter_for_1_2(data, "2c:f8:9b:dd:06:a0", "00:20:a6:fc:b0:36", "0x0028")
        elif file_name == "faye2p4.pcap":
            print("faye2p4.pcap (downlink)  detected.")
            communication_packets = no_filter_test(data, "d0:b6:6f:96:2b:b6", "dc:e9:94:2a:68:31")
        elif file_name in ["1_2_test_pcap1.pcap", "1_2_test_pcap2.pcap"]:
            print("1_2_test_pcapX.pcap (downlink)  detected.")
            communication_packets = no_filter_test(data, "d0:b6:6f:96:2b:bb", "dc:e9:94:2a:68:31")
        else:
            communication_packets = data
    else:
        print("[ERROR] Invalid parser name.")
        return

    print(f"Amount of communication packets: {len(communication_packets)}")

    # === Performance Monitoring ===
    rssi_history = {}
    last_activity = {}
    rssid_log = []
    rssi_log = []
    decay_rate = 0.1
    window_size = 10

    compute_density_metrics(data, rssi_history, last_activity, decay_rate, window_size, rssid_log)
    save_rssid_log(rssid_log)
    avg_rssi = compute_downlink_signal_strength(communication_packets, rssi_log)
    save_rssi_log(rssi_log)

    if(avg_rssi is None):
        print(f"\nError in calculating avg_rssi, it's None")
    else:
        print(f"\n[INFO] Average Signal Strength: {avg_rssi:.2f} dBm")
        print("[INFO] Signal Quality Analysis:", analyze_signal_quality(avg_rssi))

    # # === Throughput Calculation ===
    throughput = calculate_throughput(communication_packets)
    print_throughput(throughput)

    # # === Visualize Results ===
    plot_rssid_over_time()
    plot_signal_strength_over_time()

    # === Annotate and Save Analysis ===
    base_name = os.path.basename(pcap_file).replace(".pcap", "")
    output_path = f"{base_name}_analysis.txt"
    with open(output_path, "w") as f:
        annotate_performance(communication_packets, f)
    
    plot_all_in_one(communication_packets, base_name)

    print(f"[INFO] Detailed annotations saved to {output_path}")

def main():
    while True:
        parser_choice = get_parser_choice()
        if parser_choice == "4":
            print("Exiting Wi-Fi Doctor. Goodbye!")
            break

        parser_map = {
            "1": "parser_all",
            "2": "parser_for_testing",
            "3": "parser_home (for dev purposes, contains bugs)"
        }

        selected_parser = parser_map.get(parser_choice)
        if not selected_parser:
            print("Invalid choice. Try again.")
            continue

        pcap_file = get_pcap_file()
        run_analysis(pcap_file, selected_parser)

if __name__ == "__main__":
    main()