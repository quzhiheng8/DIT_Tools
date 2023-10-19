import tkinter as tk
from tkinter import filedialog, ttk
import hashlib
import shutil
import os
import threading

# 创建一个Tkinter窗口
root = tk.Tk()
root.title("拷贝素材并哈希校验")

# 创建哈希校验函数
def calculate_hash(file_path, hash_type):
    try:
        with open(file_path, "rb") as file:
            data = file.read()
            if hash_type == "MD5":
                hash_value = hashlib.md5(data).hexdigest()
            elif hash_type == "SHA-256":
                hash_value = hashlib.sha256(data).hexdigest()
            return hash_value
    except Exception as e:
        return str(e)

# 创建拷贝和哈希校验函数
def copy_and_hash_with_progress(src_folder, dest_folders, hash_type):
    try:
        total_files = 0
        copied_files = 0
        file_list = []
        for root_dir, _, files in os.walk(src_folder):
            for file in files:
                total_files += 1
                src_file = os.path.join(root_dir, file)
                for dest_folder in dest_folders:
                    dest_file = os.path.join(dest_folder, os.path.basename(src_folder), os.path.relpath(src_file, src_folder))
                    file_list.append((src_file, dest_file))

        if total_files == 0:
            result_label.config(text="没有文件需要拷贝", fg="blue")
            return

        for src_file, dest_file in file_list:
            if not continue_copy:
                break
            # 检查文件是否存在
            if os.path.exists(src_file):
                # 确保目标目录存在
                if not os.path.exists(os.path.dirname(dest_file)):
                    os.makedirs(os.path.dirname(dest_file))
                shutil.copy2(src_file, dest_file)
                copied_files += 1
                progress_var.set(int(copied_files / total_files * 100))

        if continue_copy:
            # 拷贝完成后，用橙色字显示"拷贝完成，下面进行校验"
            result_label.config(text="拷贝完成，正在进行校验", fg="orange")
            verify_hash(src_folder, dest_folders, hash_type)
    except Exception as e:
        result_label.config(text=f"Error: {str(e)}", fg="red")

def verify_hash(src_folder, dest_folders, hash_type):
    try:
        total_files = 0
        hashed_files = 0
        for root_dir, _, files in os.walk(src_folder):
            for file in files:
                total_files += 1

        if total_files == 0:
            result_label.config(text="没有文件需要校验", fg="blue")
            return

        for root_dir, _, files in os.walk(src_folder):
            for file in files:
                src_file = os.path.join(root_dir, file)
                for dest_folder in dest_folders:
                    dest_file = os.path.join(dest_folder, os.path.basename(src_folder), os.path.relpath(src_file, src_folder))
                    if calculate_hash(src_file, hash_type) != calculate_hash(dest_file, hash_type):
                        result_label.config(text="校验失败，请删除拷贝文件并重新进行拷贝", fg="red")
                        copy_button.config(text="重置")
                        copy_button.config(command=reset_application)
                        return
                hashed_files += 1
                progress_var.set(int(hashed_files / total_files * 100))
        result_label.config(text="校验成功", fg="green")
        copy_button.config(text="重置")
        copy_button.config(command=reset_application)
    except Exception as e:
        result_label.config(text=f"Error: {str(e)}", fg="red")

def reset_application():
    source_entry.delete(0, "end")
    for entry in destination_entries:
        entry.delete(0, "end")
    hash_type_var.set("MD5")
    result_label.config(text="", fg="green")
    progress_var.set(0)
    copy_button.config(text="开始")
    copy_button.config(command=start_copy_thread)

def start_copy_thread():
    global continue_copy
    if continue_copy:
        continue_copy = False
        copy_button.config(text="继续")
        progress_bar["style"] = "Orange.TProgressbar"
        result_label.config(text="拷贝暂停 点击开始键继续拷贝", fg="orange")
    else:
        continue_copy = True
        copy_button.config(text="暂停")
        progress_bar["style"] = "Green.TProgressbar"
        source_folder = source_entry.get()
        dest_folders = [entry.get() for entry in destination_entries if entry.get()]
        hash_type = hash_type_var.get()
        progress_var.set(0)
        threading.Thread(target=copy_and_hash_with_progress, args=(source_folder, dest_folders, hash_type)).start()

continue_copy = False

source_label = tk.Label(root, text="源文件夹:")
source_label.pack()

source_entry = tk.Entry(root)
source_entry.pack()

# 创建函数以选择原文件夹
def select_source_folder():
    source_folder = filedialog.askdirectory()
    source_entry.delete(0, "end")
    source_entry.insert(0, source_folder)

# 创建函数以选择目标文件夹
def select_destination_folder():
    dest_folder = filedialog.askdirectory()
    entry = tk.Entry(root)
    entry.insert(0, dest_folder)
    entry.pack()
    destination_entries.append(entry)

source_button = tk.Button(root, text="选择文件夹", command=select_source_folder)
source_button.pack()

destination_label = tk.Label(root, text="目标文件夹:")
destination_label.pack()

destination_entries = []

destination_button = tk.Button(root, text="选择文件夹", command=select_destination_folder)
destination_button.pack()

hash_type_label = tk.Label(root, text="哈希类型:")
hash_type_label.pack()

hash_type_var = tk.StringVar()
hash_type_var.set("MD5")

hash_type_option = tk.OptionMenu(root, hash_type_var, "MD5", "SHA-256")
hash_type_option.pack()

copy_button = tk.Button(root, text="开始", command=start_copy_thread)
copy_button.pack()

style = ttk.Style()
style.configure("Orange.TProgressbar", foreground="orange", background="orange")
style.configure("Green.TProgressbar", foreground="green", background="green")

progress_var = tk.DoubleVar()
progress_bar = ttk.Progressbar(root, mode="determinate", variable=progress_var, style="Green.TProgressbar")
progress_bar.pack()

result_label = tk.Label(root, text="", fg="green")
result_label.pack()

root.mainloop()
