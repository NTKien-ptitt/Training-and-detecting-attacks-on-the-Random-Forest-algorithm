import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, classification_report
import joblib  # Thêm thư viện joblib

# 1. Tải dữ liệu
data = pd.read_csv('network_traffic_data.csv')

# 2. Tiền xử lý dữ liệu
data = data.dropna()

# Mã hóa nhãn
le = LabelEncoder()
data['Label'] = le.fit_transform(data['Label'])

# Tách đặc trưng và nhãn
X = data.drop('Label', axis=1)
y = data['Label']

# Chuẩn hóa dữ liệu
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# **Lưu scaler vào file 'scaler.pkl'**
joblib.dump(scaler, 'scaler.pkl')

# Chia tập huấn luyện và kiểm tra
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# 3. Xây dựng mô hình Random Forest
model = RandomForestClassifier(n_estimators=100, random_state=42)

# 4. Huấn luyện mô hình
model.fit(X_train, y_train)

# 5. Đánh giá mô hình
test_acc = model.score(X_test, y_test)
print(f'Độ chính xác trên tập kiểm tra: {test_acc}')

# Ma trận nhầm lẫn và báo cáo phân loại
y_pred = model.predict(X_test)
cm = confusion_matrix(y_test, y_pred)
print(cm)
print(classification_report(y_test, y_pred))

# 6. Lưu mô hình
joblib.dump(model, 'random_forest_model.pkl')
