WiFi-Doctor
Spring 2025 – Computer Networks II Project - Technical University of Crete
Course: Networks II Lab
Authors: Asterinos Karalis
         Ioanna Zografoula Neamonitaki
         Emmanouil Niaropetros
         Mixalis Kellis

How to use the tool:

1) Place any .pcap file you wish to analyse in the directory /pcap_files.

2) When you run the program, you will be asked to select a parser.
     (parser_home is NOT recommended, it was used for testing, contains bugs)

3) After the program will ask you to select a .pcap file.

4) Wait for the wifi_doctor to extract the info from the .pcap file.

5) Finally, select if you want to do Monitor or Performance Analysis.

After a succesfull run, there will be plots/txt files depicting the reults of the analysis/monitor inside
the root directory for you to analyse further if you wish to, they contain extra comments on the stats obtained by the packets.


** IMPORTANT **
There's a bug that makes the Performance Analysis plots to look strange when rerun or after the Monitor run. In that case restart the tool.


Example of succesfull run:

Select Parser:
1) parser_all
2) parser_for_testing
3) parser_home
4) Exit
Enter your choice: 2

Available PCAP files:
1) 1_2_test_pcap1.pcap
2) 1_2_test_pcap2.pcap
3) faye2p4.pcap
4) faye5.pcap
5) faye5v2.pcap
6) HowIWiFi_PCAP.pcap
7) wlp2s0_ch1.pcap
8) wlp2s0_ch11.pcap
9) wlp2s0_ch120.pcap
10) wlp2s0_ch149.pcap
11) wlp2s0_ch36.pcap
Select a file: 3

[INFO] Running Wi-Fi Doctor using parser: parser_for_testing
Extracting Data: 20836packet [01:51, 186.41packet/s]
faye2p4.pcap (downlink)  detected.
Amount of communication packets: 1377

Select Analysis Type:
1) Monitor Mode Analysis
2) Performance Analysis
Enter your choice: 1
RSSID log saved to rssid_log.csv
RSSI log saved to rssi_log.csv

[INFO] Average Signal Strength: -42.59 dBm
[INFO] Signal Quality Analysis: Excellent signal strength.
Calculate Throughput: 36.86383442265795 Mbps

        *** at this point there will be plots saved in the root directory ***

Select Parser:
1) parser_all
2) parser_for_testing
3) parser_home
4) Exit
Enter your choice: