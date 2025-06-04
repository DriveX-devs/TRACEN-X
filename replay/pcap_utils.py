import utils
import asn1tools as asn

FILE = "/Users/diego/Downloads/track_2_50kmh_refTimeFix 1.pcapng"

def write_pcap(input_filename: str, start_time: int, end_time: int):
    cpm_asn = "../data/asn/CPM-all.asn"
    cpm_asn_compiled = asn.compile_files(cpm_asn, 'uper')
    input_filename = FILE
    pcap = rdpcap(input_filename)
    for i, pkt in enumerate(pcap):
        payload = bytes(pkt)
        payload = bytearray(payload)
        try:
            cpm_decoded = cpm_asn_compiled.decode('CollectivePerceptionMessage', payload)
        except Exception as e:
            print(e)
            cam_decoded = None


write_pcap(None, 0, None)