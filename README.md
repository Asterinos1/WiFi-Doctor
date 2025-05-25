#  WiFi-Doctor

**Technical University of Crete**  
**Networks II Project**  
**Authors:**  
- @Asterinos1
- @fneamonitaki 
- @eNiaro


##  Requirements

Make sure you have **Python** installed and install the following libraries:

```bash
pip install matplotlib pandas numpy pyshark
```

## How to use the tool

- Place your .pcap file in the /pcap_files directory.

- Run the program:
    ```bash
    python wifi_doctor.py
    ```
- Choose a parser when prompted.

    (⚠️ parser_home is not recommended as it contains known bugs)
    
- Select a ```.pcap``` file from the listed options.
- The tool will parse the packets and extract relevant metrics.

- Choose between:

    - Monitor Mode Analysis (for Wi-Fi density and signal strength)

    - Performance Analysis (for throughput and bottleneck diagnosis)

After a successful run, you will find the following in your root directory:

1) rssid_log.csv – logs RSSID appearance over time

2) rssi_log.csv – logs signal strength values

3) Plots showing:

    1) RSSID density over time

    2) Signal strength trends
    
    3) Various stats from Analysis mode

3) Text file with annotated performance analysis (in Performance mode)

4) Terminal output for:

    1) Average Signal Strength

    2) Signal Quality

    3) Calculated Throughput

These outputs are enhanced with commentary and statistics to help you interpret network behavior.

## ❗ Known Issues

There is a bug affecting plot visuals when running Performance Analysis after a MonitorAnalysis without restarting the tool.
To avoid this issue, please restart the tool before switching between analysis types.
