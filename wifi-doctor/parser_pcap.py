import pyshark

capture = pyshark.FileCapture('trace801_11_.pcap', display_filter='wlan.fc.type_subtype == 8')
packet_count = 0
frequencies = []
transmitted_mac_addresses = []
ssids = []

def capturing_data_freq(captured_beacon_frames):
    frequencies = []
    for packet in captured_beacon_frames:
        if hasattr(packet, 'radiotap') and hasattr(packet.radiotap, 'channel_freq'):
            try:
                freq = packet.radiotap.channel_freq
                frequencies.append(freq)
            except AttributeError:
                continue
    return frequencies

def capturing_data_trans_mac(captured_beacon_frames):
    transmitted_mac_addresses=[]
    for packet in captured_beacon_frames:
        if hasattr(packet, 'wlan'):
            try:
                src_mac = packet.wlan.sa  # Source MAC
                transmitted_mac_addresses.append(src_mac)
            except AttributeError:
                continue
    return transmitted_mac_addresses


#for packet in capture:
#   if hasattr(packet, 'wlan'):
#    print(f"Beacon Interval: {packet['wlan.mgt'].get('wlan.fixed.beacon', 'N/A')}")

def capture_bssid(captured_beacon_frames):
    ssids = []  # Reset the list inside function
    for packet in captured_beacon_frames:
        try:
            if 'wlan.mgt' in packet:
                ssid_tag = packet['wlan.mgt'].get('wlan.tag', None)
                
                if ssid_tag and 'SSID parameter set:' in ssid_tag:
                    ssid_value = ssid_tag.split('SSID parameter set: ')[-1].strip('"')
                    
                    if ssid_value:
                        ssids.append(ssid_value)

        except AttributeError as e:
            print(f"Error: {e}")  
            continue  # Skip to the next packet

    return ssids  # Returns only "30 Munroe St" SSIDs

def capturing_channels(captured_beacon_frames):
    channels = []
    for packet in captured_beacon_frames:
        if hasattr(packet, 'wlan_radio') and hasattr(packet.wlan_radio, 'channel'):
            try:
                channel_to_add = packet.wlan_radio.channel
                channels.append(channel_to_add)
            except AttributeError:
                continue
    return channels

def capturing_phy_types(captured_beacon_frames):
    phy_types = []
    for packet in captured_beacon_frames:
        if hasattr(packet, 'wlan_radio') and hasattr(packet.wlan_radio, 'phy'):
            try:
                phy_type = packet.wlan_radio.phy
                phy_types.append(phy_type)
            except AttributeError:
                continue
    return phy_types

def capturing_signal_strength(captured_beacon_frames):
    signal_strengths = []
    for packet in captured_beacon_frames:
        if hasattr(packet, 'wlan_radio') and hasattr(packet.wlan_radio, 'signal_dbm'):
            try:
                signal_strength = packet.wlan_radio.signal_dbm
                signal_strengths.append(signal_strength)
            except AttributeError:
                continue
    return signal_strengths

def capturing_snr(captured_beacon_frames):
    snr_list = []
    for packet in captured_beacon_frames:
        if hasattr(packet, 'wlan_radio') and hasattr(packet.wlan_radio, 'snr'):
            try:
                snr_to_add = packet.wlan_radio.snr
                snr_list.append(snr_to_add)
            except AttributeError:
                continue
    return snr_list

list_test_bssid=[]
list_test_bssid= capturing_snr(capture)
print(list_test_bssid)
print(len(list_test_bssid))

#to do: antistoicia type me phy

'''name_to_search = "linksys12"

if name_to_search in ssids:
    print(f"{name_to_search} is in the list!")
else:
    print(f"{name_to_search} is not in the list.")
print("this is the linkys: {}")



'''

''' for i, packet in enumerate(capture):
    print(f"\nPacket #{i} layers and fields:")
    for layer in packet.layers:
        print(f"Layer: {layer.layer_name}")
        print(layer._all_fields)  # prints all fields in the layer'''


