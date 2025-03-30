Performance analyzer part here.


parser_all.py ->    1) annotate_performance() which performs the analysis
                    based on the info extracted by the parser, this method comments
                    on the various stats such PHY Type, Rate gap etc. and saves the analysis on
                    a seperate directory "analysis results". If it doesn't exist, it will create it automatically.
                    
                    2) plot_all_in_one(), this methods plots various stats:
                        (1,1): Signal Strength Over Time
                        (1,2): Retry Distribution <-- this one maybe has to go
                        (2,1): MCS Index Over Time
                        (2,2): Data Rate vs Signal Strength

                    3) kept the add_rate_gap()

pdf_data.py -> contains the data about MCS, SNR and RSSI. 
                and functions to access them based on the MCS index.


perf_analyzer ->    ** THIS IS A DUMMY FILE, IRRELEVANT **
                    removed dummy code, now contains pdf_data.py module and showcases example usage.


Notes:
pefkianakis's pcap -> missing info, has phy variety tho.