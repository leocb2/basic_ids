from scapy.all import *
import time
import statistics
import logging
from io import StringIO

class MonitorTraffic:
    packets = []
    unusual_packet_size = []

    def __init__(self,sniff_time,threshold,reset_time = 86400):
        self.logger = logging.getLogger(__name__)
        self.logger.info("MonitorTraffic instance created.")
        self.sniff_time = sniff_time
        self.threshold = threshold
        self.reset_time = reset_time

    def _register_packet(self,packet):
        # reset packets
        if len(self.packets) >= 1 and time.time() - self.packets[0].time >= self.reset_time:
            self.packets = []

        self.packets.append(packet)
        self.logger.info(f"Packet registered. Total packets: {len(self.packets)}")

    def _get_packets_size_mean(self):
        if len(self.packets) >= 1:
            return statistics.mean([len(p) for p in self.packets])
        else:
            return 0
    
    def _get_packets_size_std(self):
        if len(self.packets) >= 2:
            return statistics.stdev([len(p) for p in self.packets])
        else:
            return 0

    def monitor_packets_size(self,packet):
        self._register_packet(packet)
        current_time = time.time()

        # filter packets
        packets_interval = [p for p in self.packets if p.time >= current_time - self.sniff_time]

        # get packet sizes
        packet_sizes = [len(p) for p in packets_interval]

        # packets statistics
        if len(packet_sizes) < 1:
            self.logger.info("No packets captured")
            return
        
        mean_packet_size = self._get_packets_size_mean()
        std_packet_size = self._get_packets_size_std()

        total_size = sum(packet_sizes)

        if total_size > mean_packet_size + self.threshold*std_packet_size:
            self.unusual_packet_size.append((total_size,packets_interval))

            self.logger.info(f"Unusual traffic volume detected: {total_size} bytes in the last {self.sniff_time} seconds. Packets:\n")
            
            output = StringIO()
            for p in packets_interval:
                print(p.show(dump=True), file=output)

            self.logger.info(output.getvalue())
            output.close()








# def monitor_traffic(iface, sniff_time, alert_threshold):
#     packets = []
#     packet_sizes = []
#     start_time = time.time()

#     def packet_callback(packet):
#         packet_sizes.append(len(packet))  # Append size of each packet
#         print(packet[IP].src)

#     while True:
#         current_time = time.time()
#         if current_time - start_time >= sniff_time:  # Check every sniff_time
#             total_size = sum(packet_sizes)
#             if len(packet_sizes) > 1:
#                 mean_packet_size = statistics.mean(packet_sizes)
#                 stdev_packet_size = statistics.stdev(packet_sizes)
#                 # If the total size is above the threshold, print a warning
#                 if total_size > mean_packet_size + alert_threshold * stdev_packet_size:

#                     for p in packets:


#                     with open(log_file, "a") as f:
#                         f.write(packet.show(dump=True))  # Write packet information to the log file

#                     print(f"Unusual traffic volume detected: {total_size} bytes in the last {sniff_time} seconds")
#             packet_sizes.clear()  # Clear the list for the next sniff_time
#             start_time = current_time  # Reset the start time
#         else:
#             # Continue sniffing packets on the specified interface
#             sniff(prn=packet_callback, filter="", iface=iface, store=False, timeout=1)  # Sniff for one second

# # Call the function with your specific parameters
# monitor_traffic("wlo1", 1, 2)