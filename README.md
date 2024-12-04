# Huấn luyện mô hình học máy phát hiện tấn công dựa trên thuật toán Random Forest
---
# MỤC LỤC
### [1. Cấu trúc](#1-cấu-trúc)
### [2. Hướng dẫn thực hiện](#2-Hướng-dẫn-thực-hiện)
- [2.1 `processpcap.py`](#21-processpcappy)
- [2.2 `train.py` và `train1.py`](#22-trainpy-và-train1py)
- [2.3 `detect.py`](#23-detectpy)

---
## 1. Cấu trúc
1.1. **`detect.py`**:
   - **Chức năng**: Giám sát và phát hiện tấn công mạng trong thời gian thực. Sử dụng các mô hình học máy đã được huấn luyện để nhận dạng các mẫu tấn công trong lưu lượng mạng.
   - **Lệnh sử dụng**: 
     ```bash
     python detect.py -i <mạng giám sát>
     ```
     Trong đó, `-i <mạng giám sát>` chỉ ra mạng (interface) cần giám sát. Ví dụ, bạn có thể sử dụng `ens33` (giao diện mạng mà bạn đã cấu hình).
   
1.2. **`train.py` và `train1.py`**:
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

1.3. **`processpcap.py`**:
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

---
## 2. Hướng dẫn thực hiện
### 2.1 `processpcap.py`
Để chuẩn bị dữ liệu từ các tệp `pcapng`, chúng ta sẽ tạo một mã Python để phân tích và trích xuất các đặc trưng từ hai tệp `normal.pcapng` và `attack.pcapng`. Dữ liệu này sẽ được lưu vào một tệp CSV (`network_traffic_data.csv`) để sử dụng cho quá trình huấn luyện mô hình.
![image](https://github.com/user-attachments/assets/32aa0706-e705-412d-957d-c78f71b88824)

Cấu trúc mã `processpcap.py` sẽ bao gồm:

- Đọc dữ liệu từ tệp `pcapng` (sử dụng thư viện `scapy`).
- Phân tích các gói tin trong tệp và trích xuất các đặc trưng (như thời gian, kích thước gói, IP nguồn, IP đích, v.v.).
- Tạo một dataset từ các đặc trưng đã trích xuất.
- Lưu dataset vào tệp `network_traffic_data.csv`.
![image](https://github.com/user-attachments/assets/f557f7ba-d670-449c-997a-6889ae20d9ad)


**Lưu ý:**
- Bạn cần thay thế `path_to_your_files` bằng đường dẫn chính xác đến các tệp `normal.pcapng` và `attack.pcapng`.
- Tệp `network_traffic_data.csv` sẽ chứa dữ liệu về các gói tin trong mạng, bao gồm các đặc trưng như IP nguồn, IP đích, cổng nguồn, cổng đích, kích thước gói và thời gian.

### 2.2 `train.py` và `train1.py`
Sau khi đã có tệp `network_traffic_data.csv`, bạn sẽ sử dụng tệp này để huấn luyện mô hình học máy trong các tệp `train.py` và `train1.py`. Quá trình này bao gồm việc:
![image](https://github.com/user-attachments/assets/76967138-4b3c-4b89-b831-74ea32172e2f)

- Đọc dữ liệu từ `network_traffic_data.csv`.
- Chia dữ liệu thành các đặc trưng (features) và nhãn (labels).
- Huấn luyện mô hình học máy, ví dụ như Random Forest.
- Lưu mô hình đã huấn luyện và scaler vào các tệp `random_forest.pkl` và `scaler.pkl`.
![image](https://github.com/user-attachments/assets/2884ae86-44f1-4a77-be48-804e807573fc)


**Lưu ý:**
- `train.py` sẽ huấn luyện mô hình sử dụng dữ liệu từ `network_traffic_data.csv`, sau đó lưu mô hình và scaler vào các tệp `random_forest.pkl` và `scaler.pkl`.
- Bạn có thể điều chỉnh tham số mô hình hoặc cách chuẩn hóa dữ liệu tùy theo yêu cầu.

Kết quả sau khi huấn luyện sẽ là hai tệp:
- `random_forest.pkl`: Lưu mô hình Random Forest đã huấn luyện.
- `scaler.pkl`: Lưu scaler dùng để chuẩn hóa dữ liệu.

Bạn có thể sử dụng hai tệp này trong quá trình giám sát tấn công mạng với `detect.py`.
### 2.3 `detect.py`

Cập nhật mô hình phát hiện tấn công bằng cách thêm hai tập huấn luyện vào:

- `random_forest.pkl`
- `scaler.pkl`

![image](https://github.com/user-attachments/assets/e4361e48-ab51-49d2-ae06-893537959108)

Để kiểm tra giao diện mạng cần giám sát, bạn có thể sử dụng lệnh:

```bash
ip a
```

Để chạy chương trình giám sát, nếu giao diện mạng là `eth0`, bạn sử dụng lệnh:

```bash
python detect.py -i eth0
```

Hoặc, thay `<mạng giám sát>` bằng giao diện mạng tương ứng:

```bash
python detect.py -i <mạng giám sát>
```




