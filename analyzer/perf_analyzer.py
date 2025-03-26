import parser_all as parser
import pdf_data

#Example usage of pdf_data.py
#First create the data.
data = pdf_data.initialize_data()

#print the data using print_matrix
#print(pdf_data.print_matrix(data))

#get specific value of either data_rate or min snr or rssi using 
#the MCS index.
print(pdf_data.get_data_rate_ht_mcs(13, 80, 800, data))

# short_gi -> false = 800 ns else true = 400 ns
# def get_expected_mcs_index(short_gi, mhz, spatial_stream)
#     return mcs_index
# it's basically the reverse of get_data_rate_ht_mcs()
print(pdf_data.get_expected_mcs_index(81, 800, 40, 2, data))