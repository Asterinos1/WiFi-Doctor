import matplotlib.pyplot as plt
import pandas as pd

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

# on this visualizer part.
def plot_all_in_one(packets, pcap_file_name):
    # Extract and process data
    timestamps = list(range(len(packets)))
    signal_values = [int(p['signal_strength']) for p in packets if p.get('signal_strength') is not None]
    mcs_vals = [int(p['mcs_index']) for p in packets if p.get('mcs_index') is not None]
    mcs_timestamps = [i for i, p in enumerate(packets) if p.get('mcs_index') is not None]
    dr_vs_rssi = [(float(p['data_rate']), int(p['signal_strength']))
                  for p in packets if p.get('data_rate') and p.get('signal_strength')]

    rate_gaps = [int(p['rate_gap']) for p in packets if p.get('rate_gap') is not None]
    rg_signal_pairs = [(int(p['signal_strength']), int(p['rate_gap']))
                       for p in packets if p.get('rate_gap') is not None and p.get('signal_strength') is not None]
    rg_indices = [i for i, p in enumerate(packets) if p.get('rate_gap') is not None]

    retry_flags = []
    for p in packets:
        val = str(p.get('retry_flag', '')).strip().lower()
        if val in ['1', 'true']:
            retry_flags.append(1)
        elif val in ['0', 'false']:
            retry_flags.append(0)

    # Set up a 3x2 plot grid
    fig, axs = plt.subplots(3, 2, figsize=(14, 12))
    fig.suptitle(f"{pcap_file_name} Analysis", fontsize=16)

    # (1,1): Signal Strength Over Time
    axs[0, 0].scatter(timestamps[:len(signal_values)], signal_values, marker='o')
    axs[0, 0].set_title("Signal Strength Over Time")
    axs[0, 0].set_xlabel("Packet #")
    axs[0, 0].set_ylabel("Signal Strength (dBm)")
    axs[0, 0].grid()

    # (1,2): Retry Flag Histogram
    axs[0, 1].hist(retry_flags, bins=[-0.5, 0.5, 1.5], rwidth=0.6)
    axs[0, 1].set_xticks([0, 1])
    axs[0, 1].set_xticklabels(["No Retry", "Retry"])
    axs[0, 1].set_title("Retry Flag Distribution")
    axs[0, 1].set_xlabel("Retry Flag")
    axs[0, 1].set_ylabel("Count")
    axs[0, 1].grid()

    # (2,1): MCS Index Over Time
    axs[1, 0].scatter(mcs_timestamps, mcs_vals, marker='.', color='purple')
    axs[1, 0].set_title("MCS Index Over Time")
    axs[1, 0].set_xlabel("Packet #")
    axs[1, 0].set_ylabel("MCS Index")
    axs[1, 0].grid()

    # (2,2): Avg Data Rate per Signal Bin
    if dr_vs_rssi:
        df = pd.DataFrame(dr_vs_rssi, columns=["data_rate", "signal_strength"])
        bin_width = 5
        df['rssi_bin'] = (df['signal_strength'] // bin_width) * bin_width
        grouped = df.groupby('rssi_bin')['data_rate'].mean().reset_index()
        grouped = grouped.sort_values('rssi_bin')

        axs[1, 1].bar(grouped['rssi_bin'].astype(str), grouped['data_rate'], width=0.8)
        axs[1, 1].set_title("Avg Data Rate per Signal Strength Bin")
        axs[1, 1].set_xlabel("Signal Strength (dBm bins)")
        axs[1, 1].set_ylabel("Average Data Rate (Mbps)")
        axs[1, 1].tick_params(axis='x', rotation=45)
        axs[1, 1].grid(axis='y')

   # (3,1): Histogram of Rate Gap values grouped by Signal Strength Bins
    if rg_signal_pairs:
        df = pd.DataFrame(rg_signal_pairs, columns=["signal_strength", "rate_gap"])

        # Bin RSSI
        bin_width = 5
        df['rssi_bin'] = (df['signal_strength'] // bin_width) * bin_width

        # Group by RSSI bin
        grouped = df.groupby('rssi_bin')

        # Prepare data for multiple hist lines
        rssi_bins = sorted(grouped.groups.keys())
        data_to_plot = [group['rate_gap'].values for _, group in grouped]

        axs[2, 0].hist(data_to_plot, bins=range(-5, 15), stacked=True, label=[str(b) + " dBm" for b in rssi_bins])
        axs[2, 0].set_title("Rate Gap Distribution per Signal Strength Bin")
        axs[2, 0].set_xlabel("Rate Gap")
        axs[2, 0].set_ylabel("Packet Count")
        axs[2, 0].legend(title="RSSI Bins")
        axs[2, 0].grid(axis='y')

    # (3,2): Rate Gap over Packet Index
    if rg_indices and rate_gaps:
        axs[2, 1].plot(rg_indices, rate_gaps, marker='o', linestyle='-', color='red')
        axs[2, 1].set_title("Rate Gap over Time")
        axs[2, 1].set_xlabel("Packet #")
        axs[2, 1].set_ylabel("Rate Gap")
        axs[2, 1].grid()

    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    plt.savefig("analysis.png")
    plt.show()

def plot_data_rate_per_packet(packets, pcap_file_name):
    """
    Plots the data rate of each packet over time (by packet index) as individual points.
    """
    data_rates = [float(p['data_rate']) for p in packets if p.get('data_rate') is not None]
    data_rate_indices = [i for i, p in enumerate(packets) if p.get('data_rate') is not None]

    plt.figure(figsize=(10, 6))
    plt.scatter(data_rate_indices, data_rates, marker='o')  # <-- Changed to scatter
    plt.title(f"Data Rate per Packet - {pcap_file_name}")
    plt.xlabel("Packet #")
    plt.ylabel("Data Rate (Mbps)")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig("data_rate_per_packet.png")
    plt.show()
