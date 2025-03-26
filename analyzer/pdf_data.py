def print_matrix(data):
    # Define the column headers
    headers = [
        "HT MCS", "VHT MCS", "Modulation", "Coding",
        "20 MHz 800ns", "20 MHz 400ns", "20 MHz Min. SNR", "20 MHz RSSI",
        "40 MHz 800ns", "40 MHz 400ns", "40 MHz Min. SNR", "40 MHz RSSI",
        "80 MHz 800ns", "80 MHz 400ns", "80 MHz Min. SNR", "80 MHz RSSI",
        "160 MHz 800ns", "160 MHz 400ns", "160 MHz Min. SNR", "160 MHz RSSI"
    ]
    
    # Calculate the maximum width for each column (to align the data properly)
    column_widths = [len(header) for header in headers]
    
    # Iterate over the rows to calculate the maximum width for each column
    for row in data:
        for i, key in enumerate(row):
            column_widths[i] = max(column_widths[i], len(str(row[key])))
    
    # Print the headers with proper alignment using tabs
    header_line = "\t".join([header.ljust(column_widths[i]) for i, header in enumerate(headers)])
    print(header_line)
    
    # Print the separator line (for better readability)
    print("\t".join(['-' * column_widths[i] for i in range(len(column_widths))]))
    
    # Print the rows with proper alignment
    spatial_groups = [1, 2, 3]  # The labels for the spatial groups
    
    for group in spatial_groups:
        print(f"------------------------------------------------------------------------------------------------------------------------------------------------ {group} spatial group ------------------------------------------------------------------------------------------------------------------------------------------------")  # Print the spatial group label
        
        for i in range(10):  # Each group has 10 rows
            index = (group - 1) * 10 + i  # Calculate the row index for the current group
            
            row = data[index]
            row_data = [
                str(row["HT MCS"]).ljust(column_widths[0]),
                str(row["VHT MCS"]).ljust(column_widths[1]),
                str(row["Modulation"]).ljust(column_widths[2]),
                str(row["Coding"]).ljust(column_widths[3]),
                str(row["20 MHz 800ns"]).ljust(column_widths[4]),
                str(row["20 MHz 400ns"]).ljust(column_widths[5]),
                str(row["20 MHz Min. SNR"]).ljust(column_widths[6]),
                str(row["20 MHz RSSI"]).ljust(column_widths[7]),
                str(row["40 MHz 800ns"]).ljust(column_widths[8]),
                str(row["40 MHz 400ns"]).ljust(column_widths[9]),
                str(row["40 MHz Min. SNR"]).ljust(column_widths[10]),
                str(row["40 MHz RSSI"]).ljust(column_widths[11]),
                str(row["80 MHz 800ns"]).ljust(column_widths[12]),
                str(row["80 MHz 400ns"]).ljust(column_widths[13]),
                str(row["80 MHz Min. SNR"]).ljust(column_widths[14]),
                str(row["80 MHz RSSI"]).ljust(column_widths[15]),
                str(row["160 MHz 800ns"]).ljust(column_widths[16]),
                str(row["160 MHz 400ns"]).ljust(column_widths[17]),
                str(row["160 MHz Min. SNR"]).ljust(column_widths[18]),
                str(row["160 MHz RSSI"]).ljust(column_widths[19]),
            ]
            
            # Print the row with proper alignment
            print("\t".join(row_data))

def initialize_data():
    # Define the data structure for the columns (same as before)
    ht_mcs = []
    ht_mcs_value = 0
    vht_mcs = []
    modulation = ["BPSK", "QPSK", "QPSK", "16-QAM", "16-QAM", "64-QAM", "64-QAM", "64-QAM", "256-QAM", "256-QAM"]
    coding = ["1/2", "1/2", "3/4", "1/2", "3/4", "2/3", "3/4", "5/6", "3/4", "5/6"]

    # Populate HT MCS for each group (10 rows per group)
    for i in range(0, 24, 10):  # Each group has 10 rows
        # Add 8 rows with valid HT MCS values and then 2 `None` placeholders
        ht_mcs.extend([ht_mcs_value + x for x in range(8)] + [None, None])
        
        # Increment the HT MCS value after each group, but ensure we don't increment by 2
        ht_mcs_value += 8  # Move to the next valid HT MCS number for the next group
        

    # Populate VHT MCS, which does NOT skip rows and follows a sequence from 0 to 9, repeated every 10 rows
    vht_mcs = [x % 10 for x in range(30)]  # VHT MCS goes from 0 to 9 and repeats every 10 rows

    # Now, create lists for the new columns
    data_rate_800ns = [
        # 1st spatial group
        [6.5, 13, 19.5, 26, 39, 52, 58.5, 65, 78, None],
        # 2nd spatial group
        [13, 26, 39, 52, 78, 104, 117, 130, 156, None],
        # 3rd spatial group
        [19.5, 39, 58.5, 78, 117, 156, 175.5, 195, 234, 260]
    ]

    data_rate_400ns = [
        # 1st spatial group
        [7.2, 14.4, 21.7, 28.9, 43.3, 57.8, 65, 72.2, 86.7, None],
        # 2nd spatial group
        [14.4, 28.9, 43.3, 57.8, 86.7, 115.6, 130.3, 144.4, 173.3, None],
        # 3rd spatial group
        [21.7, 43.3, 65, 86.7, 130, 173.3, 195, 216.7, 260, 288.9]
    ]

    rssi_min_snr_mhz = [2, 5, 9, 11, 15, 18, 20, 25, 29, 31]

    rssi_values_mhz = [-82, -79, -77, -74, -70, -66, -65, -64, -59, -57]

    # Additional data for the new columns
    # 40 MHz 800ns Data Rate
    data_rate_40mhz_800ns = [
        # 1st spatial group
        [13.5, 27, 40.5, 54, 81, 108, 121.5, 135, 162, 180],
        # 2nd spatial group
        [27, 54, 81, 108, 162, 216, 243, 270, 324, 360],
        # 3rd spatial group
        [40.5, 81, 121.5, 162, 243, 324, 364.5, 405, 486, 540]
    ]

    # 40 MHz 400ns Data Rate
    data_rate_40mhz_400ns = [
        # 1st spatial group
        [15, 30, 45, 60, 90, 120, 135, 150, 180, 200],
        # 2nd spatial group
        [30, 60, 90, 120, 180, 240, 270, 300, 360, 400],
        # 3rd spatial group
        [45, 90, 135, 180, 270, 360, 405, 450, 540, 600]
    ]

    # 40 MHz Min. SNR (same for all groups)
    rssi_min_snr_40mhz = [5, 8, 12, 14, 18, 21, 23, 28, 32, 34]

    # 40 MHz RSSI (same for all groups)
    rssi_values_40mhz = [-79, -76, -74, -71, -67, -63, -62, -61, -56, -54]


    # 80 MHz 800ns Data Rate
    data_rate_80mhz_800ns = [
        # 1st spatial group
        [29.3, 58.5, 87.8, 117, 175.5, 234, 263.3, 292.5, 351, 390],
        # 2nd spatial group
        [58.5, 117, 234, 351, 468, 526.5, 585, 702, 780, None],
        # 3rd spatial group
        [87.8, 175.5, 263.3, 351, 526.5, 702, None, 877.5, 1053, 1170]
    ]

    # 80 MHz 400ns Data Rate
    data_rate_80mhz_400ns = [
        # 1st spatial group
        [32.5, 65, 97.5, 130, 195, 260, 292.5, 325, 390, 433.3],
        # 2nd spatial group
        [65, 130, 195, 260, 390, 520, 585, 650, 780, 866.7],
        # 3rd spatial group
        [97.5, 195, 292.5, 390, 585, 780, None, 975, 1170, 1300]
    ]


    # 80 MHz Min. SNR (same for all groups)
    rssi_min_snr_80mhz = [8, 11, 15, 17, 21, 24, 26, 31, 35, 37]

    # 80 MHz RSSI (same for all groups)
    rssi_values_80mhz = [-76, -73, -71, -68, -64, -60, -59, -58, -53, -51]

    # Adding the new columns for 160 MHz Data Rate and other properties

    # 160 MHz 800ns Data Rate
    data_rate_160mhz_800ns = [
        # 1st spatial group
        [58.5, 117, 175.5, 234, 351, 468, 526.5, 585, 702, 780],
        # 2nd spatial group
        [117, 234, 351, 468, 702, 936, 1053, 1170, 1404, 1560],
        # 3rd spatial group
        [175.5, 351, 526.5, 702, 1053, 1404, 1580, 1755, 2106, None]
    ]

    # 160 MHz 400ns Data Rate
    data_rate_160mhz_400ns = [
        # 1st spatial group
        [65, 130, 195, 260, 390, 520, 585, 650, 780, 866.7],
        # 2nd spatial group
        [130, 260, 390, 520, 780, 1040, 1170, 1300, 1560, 1733],
        # 3rd spatial group
        [195, 390, 585, 780, 1170, 1560, 1755, 1950, 2340, None]
    ]

    # 160 MHz Min. SNR (same for all groups)
    rssi_min_snr_160mhz = [11, 14, 18, 20, 24, 27, 29, 34, 38, 40]

    # 160 MHz RSSI (same for all groups)
    rssi_values_160mhz = [-73, -70, -68, -65, -61, -57, -56, -55, -50, -48]

    # Now, integrate the new 160 MHz data into the row generation logic
    # Initialize an empty list to store the data for each row
    data = []

    # Now, generate the full data structure and populate the values
    for i in range(30):  # 3 spatial streams, each with 10 rows (30 rows total)
        group = i // 10  # Determine the spatial group (0 = 1st group, 1 = 2nd group, 2 = 3rd group)
        
        row = {
            "HT MCS": ht_mcs[i],
            "VHT MCS": vht_mcs[i],
            "Modulation": modulation[i % 10],  # Modulation repeats every 10 rows
            "Coding": coding[i % 10],  # Coding repeats every 10 rows
            # "20 MHz" section
            "20 MHz 800ns": data_rate_800ns[group][i % 10],  # 20 MHz 800ns data rate
            "20 MHz 400ns": data_rate_400ns[group][i % 10],  # 20 MHz 400ns data rate
            "20 MHz Min. SNR": rssi_min_snr_mhz[i % 10],  # SNR is the same for all groups
            "20 MHz RSSI": rssi_values_mhz[i % 10],  # RSSI is the same for all groups
            # "40 MHz" section
            "40 MHz 800ns": data_rate_40mhz_800ns[group][i % 10],  # 40 MHz 800ns data rate
            "40 MHz 400ns": data_rate_40mhz_400ns[group][i % 10],  # 40 MHz 400ns data rate
            "40 MHz Min. SNR": rssi_min_snr_40mhz[i % 10],  # 40 MHz SNR (same across groups)
            "40 MHz RSSI": rssi_values_40mhz[i % 10],  # 40 MHz RSSI (same across groups)
            # "80 MHz" section
            "80 MHz 800ns": data_rate_80mhz_800ns[group][i % 10],  # Placeholder for actual data
            "80 MHz 400ns": data_rate_80mhz_400ns[group][i % 10],  # Placeholder for actual data
            "80 MHz Min. SNR": rssi_min_snr_80mhz[i % 10],  # Placeholder for actual data
            "80 MHz RSSI": rssi_values_80mhz[i % 10],  # Placeholder for actual data
            # "160 MHz" section
            "160 MHz 800ns": data_rate_160mhz_800ns[group][i % 10],  # Placeholder for actual data
            "160 MHz 400ns": data_rate_160mhz_400ns[group][i % 10],  # Placeholder for actual data
            "160 MHz Min. SNR": rssi_min_snr_160mhz[i % 10],  # Placeholder for actual data
            "160 MHz RSSI": rssi_values_160mhz[i % 10],  # Placeholder for actual data
        }
        data.append(row)
    
    return data



def get_data_rate_ht_mcs(ht_mcs_value, mhz, data_rate_type, data):
    """
    Returns the data rate for a given HT MCS, MHz, and data rate type (either 800 or 400 ns).
    
    Parameters:
        ht_mcs_value (int): The HT MCS value for which the data rate is needed.
        mhz (int): The channel bandwidth in MHz (e.g., 20, 40).
        data_rate_type (int): The data rate type, either 800 ns or 400 ns.
        data (list): The dataset containing the HT MCS values and their corresponding data rates.
        
    Returns:
        float or None: The data rate corresponding to the given HT MCS value and MHz, or None if not found.
    """
    rate_column = f"{mhz} MHz {data_rate_type}ns"
    
    for row in data:
        if row["HT MCS"] == ht_mcs_value:
            return row[rate_column]
    
    return None

def get_min_snr_ht_mcs(ht_mcs_value, mhz, data):
    """
    Returns the minimum SNR for a given HT MCS and MHz.
    
    Parameters:
        ht_mcs_value (int): The HT MCS value for which the minimum SNR is needed.
        mhz (int): The channel bandwidth in MHz (e.g., 20, 40).
        data (list): The dataset containing the HT MCS values and their corresponding minimum SNR values.
        
    Returns:
        float or None: The minimum SNR corresponding to the given HT MCS value and MHz, or None if not found.
    """
    snr_column = f"{mhz} MHz Min. SNR"
    
    for row in data:
        if row["HT MCS"] == ht_mcs_value:
            return row[snr_column]
    
    return None

def get_rssi_ht_mcs(ht_mcs_value, mhz, data):
    """
    Returns the RSSI for a given HT MCS and MHz.
    
    Parameters:
        ht_mcs_value (int): The HT MCS value for which the RSSI is needed.
        mhz (int): The channel bandwidth in MHz (e.g., 20, 40).
        data (list): The dataset containing the HT MCS values and their corresponding RSSI values.
        
    Returns:
        float or None: The RSSI corresponding to the given HT MCS value and MHz, or None if not found.
    """
    rssi_column = f"{mhz} MHz RSSI"
    
    for row in data:
        if row["HT MCS"] == ht_mcs_value:
            return row[rssi_column]
    
    return None
