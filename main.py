from scapy.all import *
from monitor_traffic import MonitorTraffic
import logging
from joblib import Parallel, delayed

if __name__ == "__main__":

    sniff_interval = 5
    packet_size_std_threshold = 5
    interface = "wlp2s0"
    log_file = "app_log.log"

    # Configure the root logger
    logging.basicConfig(filename=log_file,level=logging.INFO,format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    def sniff_packets():
        sniff(iface=interface,prn=monitor.register_packet, store=0)

    def monitor_packets():
        while True:  # Run indefinitely
            logging.info(f"Running func")
            monitor.monitor_packets_size(sniff_time=sniff_interval, threshold=packet_size_std_threshold)
            # time.sleep(5)

    # Start sniffing packets and monitoring in parallel
    monitor = MonitorTraffic(sniff_interval,packet_size_std_threshold)
    
    logging.info(f"Going to run parallel jobs")

    while True:
        sniff(iface=interface,prn=monitor.monitor_packets_size, store=0)
        print("lol")

    # Parallel(n_jobs=2)([delayed(sniff_packets)(), delayed(monitor_packets)()])