# Huấn luyện mô hình học máy phát hiện tấn công dựa trên thuật toán Random Forest
## 1. Cấu trúc
1. **`detect.py`**:
   - **Chức năng**: Giám sát và phát hiện tấn công mạng trong thời gian thực. Sử dụng các mô hình học máy đã được huấn luyện để nhận dạng các mẫu tấn công trong lưu lượng mạng.
   - **Lệnh sử dụng**: 
     ```bash
     python detect.py -i <mạng giám sát>
     ```
     Trong đó, `-i <mạng giám sát>` chỉ ra mạng (interface) cần giám sát. Ví dụ, bạn có thể sử dụng `ens33` (giao diện mạng mà bạn đã cấu hình).
   
2. **`train.py` và `train1.py`**:
   - **Chức năng**: Huấn luyện mô hình học máy để phát hiện các tấn công mạng từ tập dữ liệu. Sau khi huấn luyện, mô hình sẽ được lưu thành một tệp `.pkl` (Pickle file), để có thể sử dụng trong quá trình phát hiện tấn công.
   - **Lệnh sử dụng**: 
     ```bash
     python train.py
     ```
     hoặc
     ```bash
     python train1.py
     ```
     Các tệp này sẽ chứa mã huấn luyện mô hình, sử dụng một số thuật toán học máy như SVM, Random Forest, Decision Trees, hoặc các mô hình học sâu (deep learning).

3. **`processpcap.py`**:
   - **Chức năng**: Xử lý các tệp `.pcap` (tệp chứa dữ liệu mạng) và trích xuất các đặc trưng để tạo ra dataset dùng cho việc huấn luyện mô hình. Quá trình này bao gồm việc phân tích các gói tin trong tệp `.pcap`, sau đó trích xuất các đặc trưng như thời gian, kích thước gói, IP nguồn, IP đích, và các đặc trưng khác để xây dựng dataset.
   - **Lệnh sử dụng**:
     ```bash
     python processpcap.py 
     ```
     Quá trình này sẽ giúp bạn chuẩn bị dữ liệu từ các tệp `.pcap` để huấn luyện mô hình.

### Quy trình hoạt động tổng quan:

1. **Thu thập dữ liệu**: Sử dụng tệp `processpcap.py` để trích xuất các đặc trưng từ các tệp `.pcap`, tạo ra dataset cho mô hình học máy.
2. **Huấn luyện mô hình**: Dùng `train.py` hoặc `train1.py` để huấn luyện mô hình học máy dựa trên dataset đã chuẩn bị từ bước trước.
3. **Giám sát và phát hiện tấn công**: Chạy `detect.py` để giám sát lưu lượng mạng và sử dụng mô hình học máy đã huấn luyện để phát hiện các tấn công.

## 2. Hướng dẫn thực hiện

