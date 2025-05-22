import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from Crypto.Util.number import getPrime, getRandomRange, bytes_to_long
from Crypto.Hash import SHA256
import os
import json
import shutil

class ElGamalSignatureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Hệ thống ký số ElGamal")
        self.root.geometry("800x600")
        
        # Khởi tạo tham số
        self.p = None
        self.g = None
        self.x = None
        self.y = None
        
        # Tạo giao diện
        self.create_widgets()
        
    def create_widgets(self):
        # Tab control
        tab_control = ttk.Notebook(self.root)
        
        # Tab 1: Tạo khóa
        tab1 = ttk.Frame(tab_control)
        tab_control.add(tab1, text='Tạo khóa')
        self.create_key_tab(tab1)
        
        # Tab 2: Ký file
        tab2 = ttk.Frame(tab_control)
        tab_control.add(tab2, text='Ký file')
        self.create_sign_tab(tab2)
        
        # Tab 3: Gửi file
        tab3 = ttk.Frame(tab_control)
        tab_control.add(tab3, text='Gửi file')
        self.create_send_tab(tab3)
        
        # Tab 4: Xác thực
        tab4 = ttk.Frame(tab_control)
        tab_control.add(tab4, text='Xác thực')
        self.create_verify_tab(tab4)
        
        tab_control.pack(expand=1, fill="both")
        
        # Console output
        self.console = tk.Text(self.root, height=10)
        self.console.pack(fill=tk.BOTH, expand=True)
        
    # Tab 1: Tạo khóa
    def create_key_tab(self, parent):
        frame = ttk.LabelFrame(parent, text="Tạo cặp khóa")
        frame.pack(pady=10, padx=10, fill=tk.BOTH)
        
        ttk.Label(frame, text="Kích thước khóa (bits):").grid(row=0, column=0, padx=5, pady=5)
        self.key_size_entry = ttk.Entry(frame)
        self.key_size_entry.grid(row=0, column=1, padx=5, pady=5)
        self.key_size_entry.insert(0, "512")
        
        ttk.Button(frame, text="Tạo khóa", command=self.generate_keys).grid(row=1, column=0, columnspan=2, pady=10)
        
        # Hiển thị thông tin khóa
        self.key_info = tk.Text(frame, height=8, width=60)
        self.key_info.grid(row=2, column=0, columnspan=2, padx=5, pady=5)
        
    # Tab 2: Ký file
    def create_sign_tab(self, parent):
        frame = ttk.LabelFrame(parent, text="Ký file")
        frame.pack(pady=10, padx=10, fill=tk.BOTH)
        
        ttk.Label(frame, text="File cần ký:").grid(row=0, column=0, padx=5, pady=5)
        self.file_to_sign_entry = ttk.Entry(frame, width=40)
        self.file_to_sign_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Chọn file", command=self.browse_file_to_sign).grid(row=0, column=2, padx=5)
        
        ttk.Button(frame, text="Ký file", command=self.sign_file).grid(row=1, column=0, columnspan=3, pady=10)
        
        # Hiển thị thông tin chữ ký
        self.sign_info = tk.Text(frame, height=8, width=60)
        self.sign_info.grid(row=2, column=0, columnspan=3, padx=5, pady=5)
        
    # Tab 3: Gửi file
    def create_send_tab(self, parent):
        frame = ttk.LabelFrame(parent, text="Gửi file đã ký")
        frame.pack(pady=10, padx=10, fill=tk.BOTH)
        
        ttk.Label(frame, text="File gốc:").grid(row=0, column=0, padx=5, pady=5)
        self.original_file_entry = ttk.Entry(frame, width=40)
        self.original_file_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Chọn file", command=self.browse_original_file).grid(row=0, column=2, padx=5)
        
        ttk.Label(frame, text="File chữ ký:").grid(row=1, column=0, padx=5, pady=5)
        self.signature_file_entry = ttk.Entry(frame, width=40)
        self.signature_file_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Chọn file", command=self.browse_signature_file).grid(row=1, column=2, padx=5)
        
        ttk.Label(frame, text="Thư mục đích:").grid(row=2, column=0, padx=5, pady=5)
        self.destination_folder_entry = ttk.Entry(frame, width=40)
        self.destination_folder_entry.grid(row=2, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Chọn thư mục", command=self.browse_destination_folder).grid(row=2, column=2, padx=5)
        
        ttk.Button(frame, text="Gửi file", command=self.send_signed_file).grid(row=3, column=0, columnspan=3, pady=10)
        
    # Tab 4: Xác thực
    def create_verify_tab(self, parent):
        frame = ttk.LabelFrame(parent, text="Xác thực chữ ký")
        frame.pack(pady=10, padx=10, fill=tk.BOTH)
        
        ttk.Label(frame, text="File gốc:").grid(row=0, column=0, padx=5, pady=5)
        self.verify_file_entry = ttk.Entry(frame, width=40)
        self.verify_file_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Chọn file", command=self.browse_verify_file).grid(row=0, column=2, padx=5)
        
        ttk.Label(frame, text="File chữ ký:").grid(row=1, column=0, padx=5, pady=5)
        self.verify_signature_entry = ttk.Entry(frame, width=40)
        self.verify_signature_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Chọn file", command=self.browse_verify_signature).grid(row=1, column=2, padx=5)
        
        ttk.Button(frame, text="Xác thực", command=self.verify_signature).grid(row=2, column=0, columnspan=3, pady=10)
        
        # Hiển thị kết quả xác thực
        self.verify_result = tk.Text(frame, height=8, width=60)
        self.verify_result.grid(row=3, column=0, columnspan=3, padx=5, pady=5)
    
    # Các hàm chức năng chính
    def generate_keys(self):
        try:
            key_size = int(self.key_size_entry.get())
            if key_size < 256:
                messagebox.showerror("Lỗi", "Kích thước khóa phải >= 256 bits")
                return
            
            self.p = getPrime(key_size)
            self.g = 2  # Đơn giản chọn g = 2
            self.x = getRandomRange(2, self.p-2)
            self.y = pow(self.g, self.x, self.p)
            
            self.key_info.delete(1.0, tk.END)
            self.key_info.insert(tk.END, f"Khóa công khai (p, g, y):\n")
            self.key_info.insert(tk.END, f"p = {self.p}\n")
            self.key_info.insert(tk.END, f"g = {self.g}\n")
            self.key_info.insert(tk.END, f"y = {self.y}\n\n")
            self.key_info.insert(tk.END, f"Khóa bí mật (x):\n")
            self.key_info.insert(tk.END, f"x = {self.x}\n")
            
            self.log("Đã tạo cặp khóa thành công!")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể tạo khóa: {str(e)}")
    
    def sign_file(self):
        if not self.p or not self.g or not self.x:
            messagebox.showerror("Lỗi", "Vui lòng tạo khóa trước khi ký!")
            return
            
        file_path = self.file_to_sign_entry.get()
        if not file_path:
            messagebox.showerror("Lỗi", "Vui lòng chọn file cần ký!")
            return
            
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Băm file
            h = SHA256.new(file_data).digest()
            h_int = bytes_to_long(h)
            
            # Chọn số ngẫu nhiên k
            while True:
                k = getRandomRange(2, self.p-2)
                if self.gcd(k, self.p-1) == 1:
                    break
            
            # Tính chữ ký
            r = pow(self.g, k, self.p)
            k_inv = self.modinv(k, self.p-1)
            s = (h_int - self.x * r) * k_inv % (self.p-1)
            
            # Lưu chữ ký
            sig_file = file_path + '.sig'
            with open(sig_file, 'w') as f:
                json.dump({
                    'r': r,
                    's': s,
                    'y': self.y,
                    'p': self.p,
                    'g': self.g
                }, f)
            
            self.sign_info.delete(1.0, tk.END)
            self.sign_info.insert(tk.END, f"Đã tạo chữ ký cho file: {file_path}\n")
            self.sign_info.insert(tk.END, f"File chữ ký: {sig_file}\n")
            self.sign_info.insert(tk.END, f"Chữ ký (r, s): ({r}, {s})\n")
            
            self.log(f"Đã ký file {file_path} thành công!")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể ký file: {str(e)}")
    
    def send_signed_file(self):
        original_file = self.original_file_entry.get()
        signature_file = self.signature_file_entry.get()
        destination = self.destination_folder_entry.get()
        
        if not original_file or not signature_file or not destination:
            messagebox.showerror("Lỗi", "Vui lòng điền đầy đủ thông tin!")
            return
            
        try:
            os.makedirs(destination, exist_ok=True)
            
            # Copy file gốc
            dest_file = os.path.join(destination, os.path.basename(original_file))
            shutil.copy2(original_file, dest_file)
            
            # Copy file chữ ký
            dest_sig = os.path.join(destination, os.path.basename(signature_file))
            shutil.copy2(signature_file, dest_sig)
            
            messagebox.showinfo("Thành công", f"Đã gửi file đến {destination}")
            self.log(f"Đã gửi file {original_file} và chữ ký đến {destination}")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể gửi file: {str(e)}")
    
    def verify_signature(self):
        file_path = self.verify_file_entry.get()
        sig_path = self.verify_signature_entry.get()
        
        if not file_path or not sig_path:
            messagebox.showerror("Lỗi", "Vui lòng chọn file và chữ ký!")
            return
            
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            with open(sig_path, 'r') as f:
                sig_data = json.load(f)
            
            # Băm file
            h = SHA256.new(file_data).digest()
            h_int = bytes_to_long(h)
            
            # Lấy thông tin từ chữ ký
            r = sig_data['r']
            s = sig_data['s']
            y = sig_data['y']
            p = sig_data['p']
            g = sig_data['g']
            
            # Xác thực
            v1 = pow(g, h_int, p)
            v2 = (pow(y, r, p) * pow(r, s, p)) % p
            
            self.verify_result.delete(1.0, tk.END)
            self.verify_result.insert(tk.END, f"Thông tin chữ ký:\n")
            self.verify_result.insert(tk.END, f"File: {file_path}\n")
            self.verify_result.insert(tk.END, f"p = {p}\n")
            self.verify_result.insert(tk.END, f"g = {g}\n")
            self.verify_result.insert(tk.END, f"y = {y}\n")
            self.verify_result.insert(tk.END, f"r = {r}\n")
            self.verify_result.insert(tk.END, f"s = {s}\n\n")
            
            if v1 == v2:
                self.verify_result.insert(tk.END, "Kết quả: CHỮ KÝ HỢP LỆ\n")
                self.verify_result.insert(tk.END, f"v1 = {v1}\n")
                self.verify_result.insert(tk.END, f"v2 = {v2}\n")
                self.log(f"Xác thực thành công cho file {file_path}")
            else:
                self.verify_result.insert(tk.END, "Kết quả: CHỮ KÝ KHÔNG HỢP LỆ\n")
                self.verify_result.insert(tk.END, f"v1 = {v1}\n")
                self.verify_result.insert(tk.END, f"v2 = {v2}\n")
                self.log(f"Xác thực thất bại cho file {file_path}")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể xác thực: {str(e)}")
    
    # Các hàm tiện ích
    def browse_file_to_sign(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_to_sign_entry.delete(0, tk.END)
            self.file_to_sign_entry.insert(0, filename)
    
    def browse_original_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.original_file_entry.delete(0, tk.END)
            self.original_file_entry.insert(0, filename)
    
    def browse_signature_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.signature_file_entry.delete(0, tk.END)
            self.signature_file_entry.insert(0, filename)
    
    def browse_destination_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.destination_folder_entry.delete(0, tk.END)
            self.destination_folder_entry.insert(0, folder)
    
    def browse_verify_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.verify_file_entry.delete(0, tk.END)
            self.verify_file_entry.insert(0, filename)
    
    def browse_verify_signature(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.verify_signature_entry.delete(0, tk.END)
            self.verify_signature_entry.insert(0, filename)
    
    def gcd(self, a, b):
        while b:
            a, b = b, a % b
        return a
    
    def modinv(self, a, m):
        g, x, y = self.extended_gcd(a, m)
        if g != 1:
            return None
        else:
            return x % m
    
    def extended_gcd(self, a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = self.extended_gcd(b % a, a)
            return (g, x - (b // a) * y, y)
    
    def log(self, message):
        self.console.insert(tk.END, message + "\n")
        self.console.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = ElGamalSignatureApp(root)
    root.mainloop()