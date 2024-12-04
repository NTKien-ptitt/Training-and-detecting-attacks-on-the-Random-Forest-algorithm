from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
import numpy as np
import time
from collections import defaultdict
import os

# Định nghĩa các cột theo CICIDS 2017
columns = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets", 
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max", 
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std", 
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", 
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", 
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", 
    "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", 
    "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags", 
    "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length", 
    "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length", 
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count", 
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count", 
    "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size", 
    "Avg Fwd Segment Size", "Avg Bwd Segment Size", "Fwd Header Length.1", "Fwd Avg Bytes/Bulk", 
    "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", 
    "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", 
    "Subflow Bwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd", 
    "min_seg_size_forward", "Active Mean", "Active Std", "Active Max", "Active Min", 
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min", "Label"
]

# Tạo dictionary để lưu trữ các dòng chảy
flows = {}

# Hàm tính toán các đặc trưng và ghi dòng chảy vào DataFrame
def export_flow(flow, flow_id, label):
    # Chuyển đổi các danh sách thành kiểu float
    fwd_iat_list = [float(x) for x in flow['fwd_iat']]
    bwd_iat_list = [float(x) for x in flow['bwd_iat']]
    flow_iat_list = [float(x) for x in flow['flow_iat']]
    packet_lengths_list = [float(x) for x in flow['packet_lengths']]
    fwd_pkt_lengths_list = [float(x) for x in flow['fwd_pkt_lengths']]
    bwd_pkt_lengths_list = [float(x) for x in flow['bwd_pkt_lengths']]

    # Tính toán các đặc trưng cần thiết
    total_packets = flow['total_fwd_packets'] + flow['total_bwd_packets']
    total_bytes = flow['total_length_fwd_packets'] + flow['total_length_bwd_packets']
    flow_duration = float(flow['flow_duration']) if flow['flow_duration'] > 0 else 1.0  # Tránh chia cho 0

    flow_bytes_per_s = total_bytes / flow_duration
    flow_packets_per_s = total_packets / flow_duration

    # Tính toán IAT cho forward và backward
    fwd_iat_mean = np.mean(fwd_iat_list) if fwd_iat_list else 0
    fwd_iat_std = np.std(fwd_iat_list) if len(fwd_iat_list) > 1 else 0
    fwd_iat_max = max(fwd_iat_list) if fwd_iat_list else 0
    fwd_iat_min = min(fwd_iat_list) if fwd_iat_list else 0
    fwd_iat_total = sum(fwd_iat_list) if fwd_iat_list else 0

    bwd_iat_mean = np.mean(bwd_iat_list) if bwd_iat_list else 0
    bwd_iat_std = np.std(bwd_iat_list) if len(bwd_iat_list) > 1 else 0
    bwd_iat_max = max(bwd_iat_list) if bwd_iat_list else 0
    bwd_iat_min = min(bwd_iat_list) if bwd_iat_list else 0
    bwd_iat_total = sum(bwd_iat_list) if bwd_iat_list else 0

    # Tính toán thống kê độ dài gói tin
    pkt_len_min = min(packet_lengths_list) if packet_lengths_list else 0
    pkt_len_max = max(packet_lengths_list) if packet_lengths_list else 0
    pkt_len_mean = np.mean(packet_lengths_list) if packet_lengths_list else 0
    pkt_len_std = np.std(packet_lengths_list) if len(packet_lengths_list) > 1 else 0
    pkt_len_var = np.var(packet_lengths_list) if len(packet_lengths_list) > 1 else 0

    # Tính toán các đặc trưng khác
    avg_packet_size = (total_bytes / total_packets) if total_packets > 0 else 0
    fwd_pkt_len_mean = np.mean(fwd_pkt_lengths_list) if fwd_pkt_lengths_list else 0
    bwd_pkt_len_mean = np.mean(bwd_pkt_lengths_list) if bwd_pkt_lengths_list else 0
    fwd_pkt_len_std = np.std(fwd_pkt_lengths_list) if len(fwd_pkt_lengths_list) > 1 else 0
    bwd_pkt_len_std = np.std(bwd_pkt_lengths_list) if len(bwd_pkt_lengths_list) > 1 else 0

    # Tính toán Down/Up Ratio
    down_up_ratio = (flow['total_bwd_packets'] / flow['total_fwd_packets']) if flow['total_fwd_packets'] > 0 else 0

    # Chuẩn bị dữ liệu để ghi vào DataFrame
    row = {
        "Destination Port": flow['dst_port'],
        "Flow Duration": flow_duration,
        "Total Fwd Packets": flow['total_fwd_packets'],
        "Total Backward Packets": flow['total_bwd_packets'],
        "Total Length of Fwd Packets": flow['total_length_fwd_packets'],
        "Total Length of Bwd Packets": flow['total_length_bwd_packets'],
        "Fwd Packet Length Max": max(fwd_pkt_lengths_list) if fwd_pkt_lengths_list else 0,
        "Fwd Packet Length Min": min(fwd_pkt_lengths_list) if fwd_pkt_lengths_list else 0,
        "Fwd Packet Length Mean": fwd_pkt_len_mean,
        "Fwd Packet Length Std": fwd_pkt_len_std,
        "Bwd Packet Length Max": max(bwd_pkt_lengths_list) if bwd_pkt_lengths_list else 0,
        "Bwd Packet Length Min": min(bwd_pkt_lengths_list) if bwd_pkt_lengths_list else 0,
        "Bwd Packet Length Mean": bwd_pkt_len_mean,
        "Bwd Packet Length Std": bwd_pkt_len_std,
        "Flow Bytes/s": flow_bytes_per_s,
        "Flow Packets/s": flow_packets_per_s,
        "Flow IAT Mean": np.mean(flow_iat_list) if flow_iat_list else 0,
        "Flow IAT Std": np.std(flow_iat_list) if len(flow_iat_list) > 1 else 0,
        "Flow IAT Max": max(flow_iat_list) if flow_iat_list else 0,
        "Flow IAT Min": min(flow_iat_list) if flow_iat_list else 0,
        "Fwd IAT Total": fwd_iat_total,
        "Fwd IAT Mean": fwd_iat_mean,
        "Fwd IAT Std": fwd_iat_std,
        "Fwd IAT Max": fwd_iat_max,
        "Fwd IAT Min": fwd_iat_min,
        "Bwd IAT Total": bwd_iat_total,
        "Bwd IAT Mean": bwd_iat_mean,
        "Bwd IAT Std": bwd_iat_std,
        "Bwd IAT Max": bwd_iat_max,
        "Bwd IAT Min": bwd_iat_min,
        "Fwd PSH Flags": flow['fwd_psh_flags'],
        "Bwd PSH Flags": flow['bwd_psh_flags'],
        "Fwd URG Flags": flow['fwd_urg_flags'],
        "Bwd URG Flags": flow['bwd_urg_flags'],
        "Fwd Header Length": flow['fwd_header_length'],
        "Bwd Header Length": flow['bwd_header_length'],
        "Fwd Packets/s": (flow['total_fwd_packets'] / flow_duration) if flow_duration > 0 else 0,
        "Bwd Packets/s": (flow['total_bwd_packets'] / flow_duration) if flow_duration > 0 else 0,
        "Min Packet Length": pkt_len_min,
        "Max Packet Length": pkt_len_max,
        "Packet Length Mean": pkt_len_mean,
        "Packet Length Std": pkt_len_std,
        "Packet Length Variance": pkt_len_var,
        "FIN Flag Count": flow['fin_flag_count'],
        "SYN Flag Count": flow['syn_flag_count'],
        "RST Flag Count": flow['rst_flag_count'],
        "PSH Flag Count": flow['psh_flag_count'],
        "ACK Flag Count": flow['ack_flag_count'],
        "URG Flag Count": flow['urg_flag_count'],
        "CWE Flag Count": flow['cwe_flag_count'],
        "ECE Flag Count": flow['ece_flag_count'],
        "Down/Up Ratio": down_up_ratio,
        "Average Packet Size": avg_packet_size,
        "Avg Fwd Segment Size": fwd_pkt_len_mean,
        "Avg Bwd Segment Size": bwd_pkt_len_mean,
        "Fwd Header Length.1": flow['fwd_header_length'],
        "Fwd Avg Bytes/Bulk": 0,
        "Fwd Avg Packets/Bulk": 0,
        "Fwd Avg Bulk Rate": 0,
        "Bwd Avg Bytes/Bulk": 0,
        "Bwd Avg Packets/Bulk": 0,
        "Bwd Avg Bulk Rate": 0,
        "Subflow Fwd Packets": flow['total_fwd_packets'],
        "Subflow Fwd Bytes": flow['total_length_fwd_packets'],
        "Subflow Bwd Packets": flow['total_bwd_packets'],
        "Subflow Bwd Bytes": flow['total_length_bwd_packets'],
        "Init_Win_bytes_forward": flow['init_win_bytes_fwd'],
        "Init_Win_bytes_backward": flow['init_win_bytes_bwd'],
        "act_data_pkt_fwd": 0,
        "min_seg_size_forward": 0,
        "Active Mean": 0,
        "Active Std": 0,
        "Active Max": 0,
        "Active Min": 0,
        "Idle Mean": 0,
        "Idle Std": 0,
        "Idle Max": 0,
        "Idle Min": 0,
        "Label": label
    }

    return row

# Hàm xử lý gói tin
def process_packets(packets, label):
    flows = {}
    for packet in packets:
        if IP in packet:
            try:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                protocol = packet[IP].proto
                src_port = packet.sport if hasattr(packet, 'sport') else 0
                dst_port = packet.dport if hasattr(packet, 'dport') else 0

                # Định danh dòng chảy bằng bộ 5 thành phần
                flow_id = (ip_src, src_port, ip_dst, dst_port, protocol)
                rev_flow_id = (ip_dst, dst_port, ip_src, src_port, protocol)

                timestamp = float(packet.time)

                if flow_id in flows:
                    flow = flows[flow_id]
                    direction = 'forward'
                elif rev_flow_id in flows:
                    flow = flows[rev_flow_id]
                    direction = 'backward'
                else:
                    # Tạo dòng chảy mới
                    flow = {
                        'src_ip': ip_src,
                        'src_port': src_port,
                        'dst_ip': ip_dst,
                        'dst_port': dst_port,
                        'protocol': protocol,
                        'start_time': timestamp,
                        'flow_duration': 0.0,
                        'total_fwd_packets': 0,
                        'total_bwd_packets': 0,
                        'total_length_fwd_packets': 0,
                        'total_length_bwd_packets': 0,
                        'fwd_pkt_lengths': [],
                        'bwd_pkt_lengths': [],
                        'packet_times': [],
                        'packet_lengths': [],
                        'flow_iat': [],
                        'fwd_iat': [],
                        'bwd_iat': [],
                        'fwd_psh_flags': 0,
                        'bwd_psh_flags': 0,
                        'fwd_urg_flags': 0,
                        'bwd_urg_flags': 0,
                        'fwd_header_length': 0,
                        'bwd_header_length': 0,
                        'fin_flag_count': 0,
                        'syn_flag_count': 0,
                        'rst_flag_count': 0,
                        'psh_flag_count': 0,
                        'ack_flag_count': 0,
                        'urg_flag_count': 0,
                        'cwe_flag_count': 0,
                        'ece_flag_count': 0,
                        'init_win_bytes_fwd': 0,
                        'init_win_bytes_bwd': 0,
                    }
                    flows[flow_id] = flow
                    direction = 'forward'

                flow['flow_duration'] = float(timestamp - flow['start_time'])

                packet_len = float(len(packet))
                flow['packet_lengths'].append(packet_len)
                flow['packet_times'].append(timestamp)

                # Tính toán Flow IAT
                if len(flow['packet_times']) > 1:
                    flow_iat = float(timestamp - flow['packet_times'][-2])
                    flow['flow_iat'].append(flow_iat)

                if direction == 'forward':
                    flow['total_fwd_packets'] += 1
                    flow['total_length_fwd_packets'] += packet_len
                    flow['fwd_pkt_lengths'].append(packet_len)
                    if 'last_fwd_pkt_time' in flow:
                        fwd_iat = float(timestamp - flow['last_fwd_pkt_time'])
                        flow['fwd_iat'].append(fwd_iat)
                    flow['last_fwd_pkt_time'] = timestamp

                    if TCP in packet:
                        tcp_flags = packet[TCP].flags
                        if tcp_flags & 0x08:  # PSH flag
                            flow['fwd_psh_flags'] += 1
                        if tcp_flags & 0x20:  # URG flag
                            flow['fwd_urg_flags'] += 1
                        flow['fwd_header_length'] += packet[TCP].dataofs * 4

                        if flow['total_fwd_packets'] == 1:
                            flow['init_win_bytes_fwd'] = packet[TCP].window

                        # Đếm cờ TCP
                        if tcp_flags & 0x01:
                            flow['fin_flag_count'] += 1
                        if tcp_flags & 0x02:
                            flow['syn_flag_count'] += 1
                        if tcp_flags & 0x04:
                            flow['rst_flag_count'] += 1
                        if tcp_flags & 0x08:
                            flow['psh_flag_count'] += 1
                        if tcp_flags & 0x10:
                            flow['ack_flag_count'] += 1
                        if tcp_flags & 0x20:
                            flow['urg_flag_count'] += 1
                        if tcp_flags & 0x40:
                            flow['ece_flag_count'] += 1
                        if tcp_flags & 0x80:
                            flow['cwe_flag_count'] += 1

                else:
                    flow['total_bwd_packets'] += 1
                    flow['total_length_bwd_packets'] += packet_len
                    flow['bwd_pkt_lengths'].append(packet_len)
                    if 'last_bwd_pkt_time' in flow:
                        bwd_iat = float(timestamp - flow['last_bwd_pkt_time'])
                        flow['bwd_iat'].append(bwd_iat)
                    flow['last_bwd_pkt_time'] = timestamp

                    if TCP in packet:
                        tcp_flags = packet[TCP].flags
                        if tcp_flags & 0x08:  # PSH flag
                            flow['bwd_psh_flags'] += 1
                        if tcp_flags & 0x20:  # URG flag
                            flow['bwd_urg_flags'] += 1
                        flow['bwd_header_length'] += packet[TCP].dataofs * 4

                        if flow['total_bwd_packets'] == 1:
                            flow['init_win_bytes_bwd'] = packet[TCP].window

                # Bạn có thể thêm điều kiện để xuất dòng chảy nếu cần

            except Exception as e:
                print(f"Lỗi khi xử lý gói tin: {e}")

    # Sau khi xử lý tất cả các gói tin, xuất các dòng chảy
    flow_rows = []
    for flow_id, flow in flows.items():
        row = export_flow(flow, flow_id, label)
        flow_rows.append(row)

    return flow_rows

# Đường dẫn tới file PCAP
pcap_file_benign = r'C:\Users\KIEN\Desktop\wireshark\normal.pcapng'
pcap_file_malicious = r'C:\Users\KIEN\Desktop\wireshark\attack.pcapng'

# Đọc gói tin từ file PCAP
print("Đang đọc gói tin benign...")
packets_benign = rdpcap(pcap_file_benign)
print("Đang xử lý gói tin benign...")
benign_flows = process_packets(packets_benign, 'BENIGN')

print("Đang đọc gói tin malicious...")
packets_malicious = rdpcap(pcap_file_malicious)
print("Đang xử lý gói tin malicious...")
malicious_flows = process_packets(packets_malicious, 'MALICIOUS')

# Kết hợp dữ liệu và lưu vào CSV
all_flows = benign_flows + malicious_flows
df = pd.DataFrame(all_flows, columns=columns)

# Lưu vào CSV
csv_file = 'network_traffic_data.csv'
df.to_csv(csv_file, index=False)
print(f"Dữ liệu đã được lưu vào {csv_file}")
