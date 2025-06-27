# TripleDES_AES
# Ứng dụng Triple DES và AES để bảo vệ thông tin nhạy cảm trong cơ sở dữ liệu

## 🛡️ Giới thiệu

Trong thời đại số, việc bảo mật thông tin nhạy cảm trong cơ sở dữ liệu trở nên vô cùng quan trọng, đặc biệt là với các hệ thống chứa thông tin cá nhân, tài chính, y tế, v.v. Dự án này triển khai và so sánh hai thuật toán mã hóa phổ biến là **Triple DES** và **AES (Advanced Encryption Standard)** để mã hóa và giải mã dữ liệu trước khi lưu trữ trong cơ sở dữ liệu. Mục tiêu là đảm bảo dữ liệu không thể bị truy cập trái phép kể cả khi bị rò rỉ hoặc đánh cắp.

---

## 📌 Mục tiêu

- Triển khai mã hóa và giải mã dữ liệu sử dụng **Triple DES** và **AES**.
- Ứng dụng mã hóa vào việc bảo vệ thông tin nhạy cảm như: mật khẩu, số điện thoại, địa chỉ, số CMND/CCCD,...
- So sánh hiệu năng và độ an toàn của hai thuật toán.
- Tích hợp giải pháp mã hóa vào hệ quản trị cơ sở dữ liệu (ví dụ: MySQL, SQLite).

---

## 🛠️ Công nghệ sử dụng

- Ngôn ngữ lập trình: **PYTHON**

---

## 🔐 Các tính năng chính

- ✅ Mã hóa dữ liệu đầu vào trước khi lưu vào cơ sở dữ liệu bằng Triple DES hoặc AES.
- ✅ Giải mã dữ liệu khi truy xuất để hiển thị cho người dùng hợp lệ.
- ✅ Cho phép lựa chọn thuật toán mã hóa sử dụng.
- ✅ Giao diện đơn giản để thử nghiệm và minh họa.

---

## 📊 So sánh Triple DES và AES

| Tiêu chí          | Triple DES       | AES (128/192/256 bit)   |
| ----------------- | ---------------- | ----------------------- |
| Độ an toàn        | Tốt (nhưng cũ)   | Rất cao, hiện đại       |
| Tốc độ xử lý      | Chậm hơn         | Nhanh hơn nhiều         |
| Độ dài khóa       | 112/168 bit      | 128/192/256 bit         |
| Ứng dụng phổ biến | Thẻ ngân hàng cũ | Chính phủ, doanh nghiệp |

---



