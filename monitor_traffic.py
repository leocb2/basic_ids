from scapy.all import *
import time
import statistics
import logging
from io import StringIO

class MonitorTraffic:
    packets = []
    packets_timestamps = []
    unusual_packet_size = []

    def __init__(self,sniff_time,threshold,reset_time = 86400):

        if sniff_time <= 0:
            raise ValueError("sniff_time must be higher than 0.")
        
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
        self.packets_timestamps.append(packet.time)
        # self.logger.info(f"Packet registered. Total packets: {len(self.packets)}")

    def _calculate_packet_rate(self):
        current_time = time.time()

        # filter packet timestamps
        recent_packets = [p for p in self.packets if p >= current_time - self.sniff_time]
        
        # calculate packet rate for this interval
        packet_rate = len(recent_packets) / self.sniff_time
        self.packet_rates.append(packet_rate)

    def _get_packets_rate_mean(self):
        if len(self.packets) >= 1:
            return statistics.mean(len(self.packets)/self.sniff_time)
        else:
            return None
    
    def _get_packets_rate_std(self):
        if len(self.packets) >= 2:
            return statistics.stdev(len(self.packets)/self.sniff_time)
        else:
            return None

    def monitor_packets_size(self,packet):
        self._register_packet(packet)
        current_time = time.time()

        # filter packets
        packets_interval = [p for p in self.packets if p.time >= current_time - self.sniff_time]
        
        # packets statistics
        if len(packets_interval) < 1:
            self.logger.info("No packets captured")
            return
        
        mean_packet_rate = self._get_packets_rate_mean()
        std_packet_rate = self._get_packets_rate_std()

        total_size = len(packets_interval)

        if total_size > mean_packet_rate + self.threshold*std_packet_rate:
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