from PKIManager import ECManager, ECResponse
from scapy.all import rdpcap, raw
import os
import json
import time

def count_certificates(pcap_path, start_time= None, end_time= None):
    # check if pcap_path exists
    if not os.path.exists(pcap_path):
        print(f"Pcap file {pcap_path} does not exist.")
        return
    
    packets = rdpcap(pcap_path)
    bts = packets[0].time  # epoch time in seconds
    
    start = bts + start_time if start_time else bts
    end = bts + end_time if end_time else None

    HEADER_LENGTH = 14
    TAIL_LENGTH = 66
    SEQUENCE = b'\x81\x01\x01\x80\x03\x00\x80'

    digests = set()
    count = 0
    for pkt in packets:
        pkt_time = pkt.time
        if pkt_time < start:
            continue
        if end and pkt_time > end:
            break
        data = raw(pkt)[HEADER_LENGTH:-TAIL_LENGTH]  # dati tra header e coda
        security = False if data[:1] == b'\x11' else True  # controlla se il pacchetto è secured
        if not security:
            continue  # salta i pacchetti non secured
        if SEQUENCE in data:
            count += 1
            continue
        digest = raw(pkt)[-74:-66] 
        digests.add(digest.hex())

    return len(digests)

def active_certificates():
    cfile = 'certificates/certificates.json'

    with open(cfile, 'r') as file:
        certificates = json.load(file)
    return len(certificates['certificates'].keys())

    # load certificates

def delete_expired_certificates():
    cfile = 'certificates/certificates.json'
    
    with open(cfile, 'r') as file:
        certificates = json.load(file)
    
    current_time = int(time.time())
    to_delete = []
    for cert_id, cert_info in certificates['certificates'].items():
        if cert_info['expiration'] < current_time:
            to_delete.append(cert_id)
    
    for cert_id in to_delete:
        del certificates['certificates'][cert_id]
    
    with open(cfile, 'w') as file:
        json.dump(certificates, file, indent=4)
    
    return len(to_delete)


pcap = 'cattura_MIS_80211p.pcapng'
num_certs = count_certificates(pcap, start_time=0, end_time=60)
print(num_certs)    

manager = ECManager()  
response = ECResponse()

for i in range(2):
    #manager.regeneratePEM(i)
    #manager.createRequest(i)
    #response_file = manager.sendPOST(i)-
    print(response.getECResponse(i))