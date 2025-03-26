import parser_all as parser
import pdf_data

#Example usage of pdf_data.py
#First create the data.
data = pdf_data.initialize_data()

#print the data using print_matrix
#print(pdf_data.print_matrix(data))

#get specific value of either data_rate or min snr or rssi using 
#the MCS index.
print(pdf_data.get_data_rate_ht_mcs(24, 20, 800, data))