import parser_all as pars  

def calculate_throughput(data: list) -> list:
    """
    Calculates the throughput for each packet based on the data rate and frame loss rate.

    Args:
        data (list): List of packet dictionaries extracted from pcap file.

    Returns:
        list: List of dictionaries with throughput data added.
    """
    for packet in data:
        try:
            # Data rate in Mbps
            data_rate = float(packet.get('data_rate', 0))

            # Frame Loss Rate = Number of retries / Total frames
            retry_flag = packet.get('retry_flag', None)
            frame_loss_rate = 0
            if retry_flag == '1':  # retry flag is set
                frame_loss_rate = 0.5  # Assuming 50% frame loss, adjust as needed

            throughput = data_rate * (1 - frame_loss_rate)
            packet['throughput'] = throughput
        except (ValueError, TypeError):
            packet['throughput'] = None

    return data


def analyze_performance(data: list) -> dict:
    """
    Analyzes the performance based on key metrics such as PHY Type, Bandwidth, Data Rate, MCS Index, etc.

    Args:
        data (list): List of packet dictionaries extracted from pcap file.

    Returns:
        dict: A summary analysis of the Wi-Fi performance issues.
    """
    performance_issues = {
        'low_throughput': [],
        'interference': [],
        'poor_signal': [],
        'configuration_issues': []
    }

    for packet in data:
        if packet.get('throughput', None) is not None and packet['throughput'] < 20:  # Threshold for "low" throughput
            performance_issues['low_throughput'].append(packet)

        # Checking signal strength
        signal_strength = packet.get('signal_strength', None)
        if signal_strength is not None and float(signal_strength) < -70:  # Signal strength in dBm
            performance_issues['poor_signal'].append(packet)

        # Check for interference (based on retries or low SNR)
        snr = packet.get('snr', None)
        if snr is not None and float(snr) < 20:  # Low SNR indicates interference
            performance_issues['interference'].append(packet)

        # Check configuration issues (e.g., using inefficient PHY Type or MCS Index)
        phy_type = packet.get('phy_type', None)
        mcs_index = packet.get('mcs_index', None)
        if phy_type == '802.11a' or (mcs_index is not None and int(mcs_index) < 7):  # Example thresholds
            performance_issues['configuration_issues'].append(packet)

    return performance_issues


def summarize_issues(performance_issues: dict):
    """
    Prints a summary of the performance issues.

    Args:
        performance_issues (dict): Dictionary containing lists of packets categorized by performance issues.
    """
    print("Performance Analysis Summary:\n")
    
    print(f"Low Throughput Packets: {len(performance_issues['low_throughput'])}")
    print(f"Packets with Poor Signal Strength: {len(performance_issues['poor_signal'])}")
    print(f"Packets with Interference Issues (Low SNR): {len(performance_issues['interference'])}")
    print(f"Packets with Wi-Fi Configuration Issues: {len(performance_issues['configuration_issues'])}")
    
    # Optionally, you could print more details of each issue group if needed


if __name__ == "__main__":
    # Use the parser functions from parser_all
    pcap_file = 'analyzer/pcap_files/HowIWiFi_PCAP.pcap'  # Example path to the pcap file

    # Step 1: Extract all data from the pcap file using the parser
    print("Extracting data from pcap file...")
    data = pars.extract_all_data(pcap_file)

    # Step 2: Find spatial streams (if missing) using the parser
    print("Finding spatial streams...")
    data = pars.find_spatial_streams(data)

    # Step 3: Calculate throughput for each packet
    print("Calculating throughput...")
    data = calculate_throughput(data)

    # Step 4: Analyze performance based on the extracted data
    print("Analyzing performance...")
    performance_issues = analyze_performance(data)

    # Step 5: Summarize the performance issues
    summarize_issues(performance_issues)
