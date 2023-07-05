from scapy.all import *
import time
import statistics
import logging
from io import StringIO

class MonitorTraffic:
    packets = []
    packet_rates = []
    last_rate_time = 0
    last_rate_calculation = 0
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
            self.logger.info("Packets reset.")
            self.packets = []

        self.packets.append(packet)
        # self.logger.info(f"Packet registered. Total packets: {len(self.packets)}")

    def _calculate_packet_rate(self):
        # get the length of the packets
        len_packets = len(self.packets)
        
        if len_packets > 1:
            if self.packets[-1].time - self.packets[0].time < 60 or time.time() - self.last_rate_calculation < self.sniff_time:
                return len(self.packet_rates)
        else:
            return 0
            
        # calculate the maximum time, subtracting the time when the sniffing started 
        # from the current time. We don't want to include the current time window.
        max_time = time.time() - self.sniff_time

        idx = 0

        # if there is more than one packet rate already calculated,
        # try to find the index of the last rate time in the packets list.
        if len(self.packet_rates) > 1:
            try:
                idx = self.packets.index(self.last_rate_time)
            except:
                # if the index is not found, pass the exception and continue.
                pass

        # for each packet starting from the last found index up to the second to last packet
        for j in range(idx,len_packets-1):
            
            # initialize the time with the timestamp of the packet
            t = self.packets[j].time
            i = 0
            
            # loop while the current time is within the sniffing window and
            # the packet index is within the total packets
            while t <= min(self.packets[j].time + self.sniff_time,max_time) and j+i < len_packets:
                # update the time with the time of the next packet in the window
                t = self.packets[j+i].time
                i += 1

            # update the last_rate_time with the time of the last packet considered
            self.last_rate_time = t

            # append the rate calculated by dividing the number of packets 
            # in the sniffing window by the sniff time
            self.packet_rates.append(i/self.sniff_time)

        self.last_rate_calculation = time.time()
        return len(self.packet_rates)

    def _get_packets_rate_mean(self):
        if len(self.packet_rates) < 1:
            return None
        
        return statistics.mean(self.packet_rates)
    
    def _get_packets_rate_std(self):
        if len(self.packet_rates) < 2:
            return None
        
        return statistics.stdev(self.packet_rates)

    def monitor_packets_size(self,packet):
        self._register_packet(packet)
        current_time = time.time()

        # filter packets
        packets_interval = [p for p in self.packets if p.time >= current_time - self.sniff_time]
        
        # packets statistics
        if len(packets_interval) < 1:
            self.logger.info("No packets captured")
            return
        
        len_packet_rates = self._calculate_packet_rate()

        if len_packet_rates < 100:
            self.logger.info("Not enough historical packet rates yet. Collecting...")
            return
        
        mean_packet_rate = self._get_packets_rate_mean()
        std_packet_rate = self._get_packets_rate_std()

        if mean_packet_rate is None or std_packet_rate is None:
            return

        current_packet_rate = len(packets_interval)/self.sniff_time

        if current_packet_rate > mean_packet_rate + self.threshold*std_packet_rate:
            self.unusual_packet_size.append((current_packet_rate,packets_interval))

            self.logger.info(f"Unusual traffic volume detected: {current_packet_rate} packets/sec during the last {self.sniff_time} seconds. Mean = {mean_packet_rate} std = {std_packet_rate}\n")
            
            # output = StringIO()
            # for p in packets_interval:
            #     print(p.show(dump=True), file=output)

            # self.logger.info(output.getvalue())
            # output.close()








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