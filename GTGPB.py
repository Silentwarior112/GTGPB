import os
import tkinter as tk
from tkinter import filedialog, messagebox
import struct
import configparser
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import re

# Resolve tool paths relative to this script's directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

GTPS2MODELTOOL_EXE = os.path.normpath(os.path.join(SCRIPT_DIR, "GTPS2ModelTool", "GTPS2ModelTool.exe"))

zip_exe = os.path.normpath(os.path.join(SCRIPT_DIR, "PolyphonyPS2Zip", "PolyphonyPS2Zip.exe"))
    
COMP_MAGIC = b"\xC5\xEE\xF7\xFF"

# ChatGPT told me to put this here. Idk wtf I'm doing
def byte_count_to_bytes(byte_count):
    return byte_count.to_bytes(4, byteorder='big')  # Assuming a 4-byte integer

class AssetPackageGenerator(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("GTGPB")
        
        # Load the last used directory from the configuration file
        self.last_used_directory = self.load_last_directory()
        
        # Set window size
        self.geometry("512x360")  # Width x Height
    
        self.texture_names = []
        self.custom_filenames = {}  # Dictionary to hold texture labels
        self.destination_dir = None  # Destination directory for extraction
        
        # UI Components
        frame_left = tk.Frame(self)
        frame_left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        frame_right = tk.Frame(self)
        frame_right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Configure grid resizing
        frame_left.grid_rowconfigure(1, weight=1)
        frame_left.grid_columnconfigure(0, weight=1)
        
        frame_right.grid_rowconfigure(1, weight=1)
        frame_right.grid_columnconfigure(0, weight=1)
        
        # Buttons
        self.extract_button = tk.Button(self, text="Extract gpb to folder", command=self.on_extract_button_click)
        self.extract_button.pack(padx=0, pady=30)
        self.generate_button = tk.Button(self, text="Update GPB file entries", command=self.ask_root_folder_and_generate)
        self.generate_button.pack(padx=10, pady=5)
        self.generate_button = tk.Button(self, text="Generate gpb0 from .ini", command=self.generate_gpb0)
        self.generate_button.pack(padx=10, pady=5)
        self.generate_button = tk.Button(self, text="Generate gpb1 from .ini", command=self.generate_gpb1)
        self.generate_button.pack(padx=10, pady=5)
        self.generate_button = tk.Button(self, text="Generate gpb2 from .ini", command=self.generate_gpb2)
        self.generate_button.pack(padx=10, pady=5)
        self.generate_button = tk.Button(self, text="Generate gpb3 from .ini", command=self.generate_gpb3)
        self.generate_button.pack(padx=10, pady=5)
        
    def load_last_directory(self):
        config = configparser.ConfigParser()
        
        # Check if the configuration file exists
        if os.path.exists('config.ini'):
            config.read('config.ini')
            last_directory = config.get('Settings', 'LastUsedDirectory')
            return last_directory
        else:
            return "/"
    
    def save_last_directory(self, directory):
        config = configparser.ConfigParser()
        config['Settings'] = {'LastUsedDirectory': directory}
        
        with open('config.ini', 'w') as config_file:
            config.write(config_file)
    
    def on_extract_button_click(self):
        gpb_path = filedialog.askopenfilename(title="Select GPB File", filetypes=[("GPB files", "*.gpb")])
        
        if gpb_path:
            self.destination_dir = filedialog.askdirectory(title="Select Destination Directory")
            
            if self.destination_dir:
                with open(gpb_path, 'rb') as f:
                    # Read the first 4 bytes to identify the header
                    header_bytes = f.read(4)
                    header_str = header_bytes.decode('utf-8')
                    
                    # Reset the file pointer to the beginning
                    f.seek(0)
                    
                    # Check the header and call the appropriate extraction method
                    if header_str == "gpb0":
                        self.extract_gpb0(gpb_path)
                    elif header_str == "gpb1":
                        self.extract_gpb1(gpb_path)
                    elif header_str == "gpb2":
                        self.extract_gpb2(gpb_path)
                    elif header_str == "3bpg":
                        self.extract_gpb3(gpb_path)
                    else:
                        messagebox.showerror("Error", f"Unsupported file format with header: {header_str}")

    def update_texture_listbox(self):
        self.texture_listbox.delete(0, tk.END)
        self.filename_listbox.delete(0, tk.END)
        
        for directory, filename in self.texture_names:
            self.texture_listbox.insert(tk.END, os.path.join(directory, filename))
            
            custom_filename = self.custom_filenames.get(filename, filename)
            self.filename_listbox.insert(tk.END, custom_filename)

    def generate_gpb0(self):
        ini_file_path = filedialog.askopenfilename(title="Select gpb_config.ini File", filetypes=[("INI files", "*.ini")])
        if not ini_file_path:
            return
    
        output_gpb_file = filedialog.asksaveasfile(
            title="Save .gpb File As",
            filetypes=[("GPB files", "*.gpb")],
            defaultextension=".gpb"
        )
        if not output_gpb_file:
            return
        output_gpb_path = output_gpb_file.name
    
        def show_wait_dialog():
            parent = self.winfo_toplevel()
            dlg = tk.Toplevel(parent)
            dlg.title("Working")
            dlg.resizable(False, False)
            dlg.transient(parent)
            dlg.grab_set()
            tk.Label(dlg, text="Converting textures...\n\nPlease wait.", padx=30, pady=20).pack()
            dlg.update_idletasks()
            dlg.update()
            x = parent.winfo_rootx() + (parent.winfo_width() // 2) - (dlg.winfo_width() // 2)
            y = parent.winfo_rooty() + (parent.winfo_height() // 2) - (dlg.winfo_height() // 2)
            dlg.geometry(f"+{x}+{y}")
            return dlg
    
        wait_dialog = show_wait_dialog()
    
        def worker():
            img_deletions = []
            ps2zip_deletions = []
            del_lock = threading.Lock()
    
            def record_delete(lst, p):
                with del_lock:
                    lst.append(os.path.normpath(p))
    
            def cleanup_recorded():
                def unique(seq):
                    seen = set()
                    out = []
                    for p in seq:
                        if p not in seen:
                            out.append(p)
                            seen.add(p)
                    return out
    
                for p in unique(ps2zip_deletions):
                    try:
                        if os.path.isfile(p):
                            os.remove(p)
                    except Exception as e:
                        print(f"[Cleanup] Failed to delete: {p}\n  {e}")
    
                for p in unique(img_deletions):
                    try:
                        if os.path.isfile(p):
                            os.remove(p)
                    except Exception as e:
                        print(f"[Cleanup] Failed to delete: {p}\n  {e}")
    
            try:
                # PRE: convert all .png under ini folder -> .img (multithread)
                root_folder = os.path.dirname(ini_file_path)
                png_files = []
                for root, _, files in os.walk(root_folder):
                    for fn in files:
                        if fn.lower().endswith(".png"):
                            png_files.append(os.path.join(root, fn))
    
                def run_make_tex_set(png_path: str):
                    subprocess.run([GTPS2MODELTOOL_EXE, "make-tex-set", "-i", png_path],
                                capture_output=True, text=True, check=True)
                    img_path = os.path.splitext(png_path)[0] + ".img"
                    record_delete(img_deletions, img_path)
    
                max_workers = min(8, (os.cpu_count() or 4))
                errors = []
                with ThreadPoolExecutor(max_workers=max_workers) as ex:
                    futures = {ex.submit(run_make_tex_set, p): p for p in png_files}
                    for fut in as_completed(futures):
                        p = futures[fut]
                        try:
                            fut.result()
                        except subprocess.CalledProcessError as e:
                            err = (e.stderr or e.stdout or "").strip()
                            errors.append((p, err))
                        except Exception as e:
                            errors.append((p, str(e)))
    
                if errors:
                    def on_fail():
                        wait_dialog.destroy()
                        print("make-tex-set errors:")
                        for p, err in errors:
                            print(f"- {p}\n  {err}\n")
                        messagebox.showerror("Conversion error",
                                            f"make-tex-set failed for {len(errors)} PNG file(s).\nSee console.\n\nAborting.")
                    self.after(0, on_fail)
                    return
    
                # Parse [Textures] in numeric order + compression
                config = configparser.ConfigParser()
                config.read(ini_file_path)
                if 'Textures' not in config:
                    def on_fail2():
                        wait_dialog.destroy()
                        messagebox.showerror("Error", "Missing [Textures] section in ini.")
                    self.after(0, on_fail2)
                    return
    
                tex = config['Textures']
                pat = re.compile(r'^texture_(\d+)_(path|label|compression)$', re.IGNORECASE)
    
                items = {}
                for k, v in tex.items():
                    m = pat.match(k)
                    if not m:
                        continue
                    idx = int(m.group(1))
                    field = m.group(2).lower()
                    items.setdefault(idx, {})[field] = v
    
                indices = sorted(items.keys())
                if not indices:
                    def on_fail3():
                        wait_dialog.destroy()
                        messagebox.showerror("Error", "No texture_* entries found in [Textures].")
                    self.after(0, on_fail3)
                    return
    
                texture_paths = []
                texture_labels = []
                texture_comp = []
    
                for idx in indices:
                    entry = items[idx]
                    if 'path' not in entry or 'label' not in entry:
                        def on_missing():
                            wait_dialog.destroy()
                            messagebox.showerror("Error", f"Missing path/label for texture_{idx}.")
                        self.after(0, on_missing)
                        return
    
                    try:
                        comp_val = 1 if int(entry.get('compression', '0')) == 1 else 0
                    except Exception:
                        comp_val = 0
    
                    texture_paths.append(entry['path'])
                    texture_labels.append(entry['label'])
                    texture_comp.append(comp_val)
    
                # Compress flagged textures -> .ps2zip
                to_compress = [p for p, c in zip(texture_paths, texture_comp) if c == 1]
    
                def run_ps2zip(img_path: str):
                    subprocess.run([zip_exe, img_path], capture_output=True, text=True, check=True)
                    out_path = img_path + ".ps2zip"
                    if not os.path.isfile(out_path):
                        raise RuntimeError(f"PS2Zip output not found:\n{out_path}")
                    record_delete(ps2zip_deletions, out_path)
    
                errors = []
                if to_compress:
                    with ThreadPoolExecutor(max_workers=max_workers) as ex:
                        futures = {ex.submit(run_ps2zip, p): p for p in to_compress}
                        for fut in as_completed(futures):
                            p = futures[fut]
                            try:
                                fut.result()
                            except subprocess.CalledProcessError as e:
                                err = (e.stderr or e.stdout or "").strip()
                                errors.append((p, err))
                            except Exception as e:
                                errors.append((p, str(e)))
    
                if errors:
                    def on_fail_zip():
                        wait_dialog.destroy()
                        print("PS2Zip errors:")
                        for p, err in errors:
                            print(f"- {p}\n  {err}\n")
                        messagebox.showerror("Compression error",
                                            f"PS2Zip failed for {len(errors)} texture(s).\nSee console.\n\nAborting.")
                    self.after(0, on_fail_zip)
                    return
    
                # PACK GPB0
                num_textures = len(texture_paths)
                with open(output_gpb_path, "wb") as f:
                    f.write(b'gpb0')
                    f.write(struct.pack('<I', num_textures))
    
                    metadata_start = f.tell()
                    f.write(b'\x00' * (num_textures * 8))
    
                    filename_offsets = []
                    current_offset = f.tell()
    
                    for custom_filename in texture_labels:
                        bts = custom_filename.encode('utf-8') + b'\x00'
                        for b in bts:
                            f.write(struct.pack('B', b))
                        filename_offsets.append(current_offset)
                        current_offset = f.tell()
    
                    while f.tell() % 16 != 0:
                        f.write(b'\x5E')
    
                    texture_offsets = []
                    for path, comp_val in zip(texture_paths, texture_comp):
                        pack_path = (path + ".ps2zip") if comp_val == 1 else path
                        with open(pack_path, 'rb') as img_file:
                            img_data = img_file.read()
    
                        texture_offset = f.tell()
                        f.write(img_data)
    
                        while f.tell() % 16 != 0:
                            f.write(b'\x5E')
    
                        texture_offsets.append(texture_offset)
    
                    for i in range(num_textures):
                        f.seek(metadata_start + i * 8)
                        f.write(struct.pack('<I', filename_offsets[i]))
                        f.seek(metadata_start + 4 + i * 8)
                        f.write(struct.pack('<I', texture_offsets[i]))
    
                cleanup_recorded()
    
                def on_success():
                    wait_dialog.destroy()
                    messagebox.showinfo("Success!", f"GPB generation completed. {num_textures} textures packed.")
                self.after(0, on_success)
    
            except Exception as e:
                try:
                    cleanup_recorded()
                except Exception:
                    pass
    
                def on_error():
                    wait_dialog.destroy()
                    messagebox.showerror("Error", str(e))
                self.after(0, on_error)
    
        threading.Thread(target=worker, daemon=True).start()

    def generate_gpb1(self):
        ini_file_path = filedialog.askopenfilename(title="Select gpb_config.ini File", filetypes=[("INI files", "*.ini")])
        if not ini_file_path:
            return
    
        output_gpb_file = filedialog.asksaveasfile(
            title="Save .gpb File As",
            filetypes=[("GPB files", "*.gpb")],
            defaultextension=".gpb"
        )
        if not output_gpb_file:
            return
        output_gpb_path = output_gpb_file.name
    
        def show_wait_dialog():
            parent = self.winfo_toplevel()
            dlg = tk.Toplevel(parent)
            dlg.title("Working")
            dlg.resizable(False, False)
            dlg.transient(parent)
            dlg.grab_set()
            tk.Label(dlg, text="Converting textures...\n\nPlease wait.", padx=30, pady=20).pack()
            dlg.update_idletasks()
            dlg.update()
            x = parent.winfo_rootx() + (parent.winfo_width() // 2) - (dlg.winfo_width() // 2)
            y = parent.winfo_rooty() + (parent.winfo_height() // 2) - (dlg.winfo_height() // 2)
            dlg.geometry(f"+{x}+{y}")
            return dlg
    
        wait_dialog = show_wait_dialog()
    
        def worker():
            img_deletions = []
            ps2zip_deletions = []
            del_lock = threading.Lock()
    
            def record_delete(lst, p):
                with del_lock:
                    lst.append(os.path.normpath(p))
    
            def cleanup_recorded():
                def unique(seq):
                    seen = set()
                    out = []
                    for p in seq:
                        if p not in seen:
                            out.append(p)
                            seen.add(p)
                    return out
    
                for p in unique(ps2zip_deletions):
                    try:
                        if os.path.isfile(p):
                            os.remove(p)
                    except Exception as e:
                        print(f"[Cleanup] Failed to delete: {p}\n  {e}")
    
                for p in unique(img_deletions):
                    try:
                        if os.path.isfile(p):
                            os.remove(p)
                    except Exception as e:
                        print(f"[Cleanup] Failed to delete: {p}\n  {e}")
    
            try:
                # PRE: convert all .png under ini folder -> .img (multithread)
                root_folder = os.path.dirname(ini_file_path)
                png_files = []
                for root, _, files in os.walk(root_folder):
                    for fn in files:
                        if fn.lower().endswith(".png"):
                            png_files.append(os.path.join(root, fn))
    
                def run_make_tex_set(png_path: str):
                    subprocess.run([GTPS2MODELTOOL_EXE, "make-tex-set", "-i", png_path],
                                capture_output=True, text=True, check=True)
                    img_path = os.path.splitext(png_path)[0] + ".img"
                    record_delete(img_deletions, img_path)
    
                max_workers = min(8, (os.cpu_count() or 4))
                errors = []
                with ThreadPoolExecutor(max_workers=max_workers) as ex:
                    futures = {ex.submit(run_make_tex_set, p): p for p in png_files}
                    for fut in as_completed(futures):
                        p = futures[fut]
                        try:
                            fut.result()
                        except subprocess.CalledProcessError as e:
                            err = (e.stderr or e.stdout or "").strip()
                            errors.append((p, err))
                        except Exception as e:
                            errors.append((p, str(e)))
    
                if errors:
                    def on_fail():
                        wait_dialog.destroy()
                        print("make-tex-set errors:")
                        for p, err in errors:
                            print(f"- {p}\n  {err}\n")
                        messagebox.showerror("Conversion error",
                                            f"make-tex-set failed for {len(errors)} PNG file(s).\nSee console.\n\nAborting.")
                    self.after(0, on_fail)
                    return
    
                # Parse [Textures] in numeric order + compression
                config = configparser.ConfigParser()
                config.read(ini_file_path)
                if 'Textures' not in config:
                    def on_fail2():
                        wait_dialog.destroy()
                        messagebox.showerror("Error", "Missing [Textures] section in ini.")
                    self.after(0, on_fail2)
                    return
    
                tex = config['Textures']
                pat = re.compile(r'^texture_(\d+)_(path|label|compression)$', re.IGNORECASE)
    
                items = {}
                for k, v in tex.items():
                    m = pat.match(k)
                    if not m:
                        continue
                    idx = int(m.group(1))
                    field = m.group(2).lower()
                    items.setdefault(idx, {})[field] = v
    
                indices = sorted(items.keys())
                if not indices:
                    def on_fail3():
                        wait_dialog.destroy()
                        messagebox.showerror("Error", "No texture_* entries found in [Textures].")
                    self.after(0, on_fail3)
                    return
    
                texture_paths = []
                texture_labels = []
                texture_comp = []
    
                for idx in indices:
                    entry = items[idx]
                    if 'path' not in entry or 'label' not in entry:
                        def on_missing():
                            wait_dialog.destroy()
                            messagebox.showerror("Error", f"Missing path/label for texture_{idx}.")
                        self.after(0, on_missing)
                        return
    
                    try:
                        comp_val = 1 if int(entry.get('compression', '0')) == 1 else 0
                    except Exception:
                        comp_val = 0
    
                    texture_paths.append(entry['path'])
                    texture_labels.append(entry['label'])
                    texture_comp.append(comp_val)
    
                # Compress flagged textures -> .ps2zip
                to_compress = [p for p, c in zip(texture_paths, texture_comp) if c == 1]
    
                def run_ps2zip(img_path: str):
                    subprocess.run([zip_exe, img_path], capture_output=True, text=True, check=True)
                    out_path = img_path + ".ps2zip"
                    if not os.path.isfile(out_path):
                        raise RuntimeError(f"PS2Zip output not found:\n{out_path}")
                    record_delete(ps2zip_deletions, out_path)
    
                errors = []
                if to_compress:
                    with ThreadPoolExecutor(max_workers=max_workers) as ex:
                        futures = {ex.submit(run_ps2zip, p): p for p in to_compress}
                        for fut in as_completed(futures):
                            p = futures[fut]
                            try:
                                fut.result()
                            except subprocess.CalledProcessError as e:
                                err = (e.stderr or e.stdout or "").strip()
                                errors.append((p, err))
                            except Exception as e:
                                errors.append((p, str(e)))
    
                if errors:
                    def on_fail_zip():
                        wait_dialog.destroy()
                        print("PS2Zip errors:")
                        for p, err in errors:
                            print(f"- {p}\n  {err}\n")
                        messagebox.showerror("Compression error",
                                            f"PS2Zip failed for {len(errors)} texture(s).\nSee console.\n\nAborting.")
                    self.after(0, on_fail_zip)
                    return
    
                # PACK GPB1
                num_textures = len(texture_paths)
                with open(output_gpb_path, "wb") as f:
                    f.write(b'gpb1')
                    f.write(b'\x00' * 8)
                    f.write(struct.pack('<I', num_textures))
    
                    metadata_start = f.tell()
                    f.write(b'\x00' * (num_textures * 8))
    
                    filename_offsets = []
                    current_offset = f.tell()
    
                    for custom_filename in texture_labels:
                        bts = custom_filename.encode('utf-8') + b'\x00'
                        for b in bts:
                            f.write(struct.pack('B', b))
                        filename_offsets.append(current_offset)
                        current_offset = f.tell()
    
                    while f.tell() % 16 != 0:
                        f.write(b'\x5E')
    
                    texture_offsets = []
                    for path, comp_val in zip(texture_paths, texture_comp):
                        pack_path = (path + ".ps2zip") if comp_val == 1 else path
                        with open(pack_path, 'rb') as img_file:
                            img_data = img_file.read()
    
                        texture_offset = f.tell()
                        f.write(img_data)
    
                        while f.tell() % 16 != 0:
                            f.write(b'\x5E')
    
                        texture_offsets.append(texture_offset)
    
                    for i in range(num_textures):
                        f.seek(metadata_start + i * 8)
                        f.write(struct.pack('<I', filename_offsets[i]))
                        f.seek(metadata_start + 4 + i * 8)
                        f.write(struct.pack('<I', texture_offsets[i]))
    
                cleanup_recorded()
    
                def on_success():
                    wait_dialog.destroy()
                    messagebox.showinfo("Success!", f"GPB generation completed. {num_textures} textures packed.")
                self.after(0, on_success)
    
            except Exception as e:
                try:
                    cleanup_recorded()
                except Exception:
                    pass
    
                def on_error():
                    wait_dialog.destroy()
                    messagebox.showerror("Error", str(e))
                self.after(0, on_error)
    
        threading.Thread(target=worker, daemon=True).start()

    def generate_gpb2(self):
        # Ask user to select the gpb_config.ini file
        ini_file_path = filedialog.askopenfilename(
            title="Select gpb_config.ini File",
            filetypes=[("INI files", "*.ini")]
        )
        if not ini_file_path:
            return
    
        # Ask user to specify the output .gpb file location and name
        output_gpb_file = filedialog.asksaveasfile(
            title="Save .gpb File As",
            filetypes=[("GPB files", "*.gpb")],
            defaultextension=".gpb"
        )
        if not output_gpb_file:
            return
    
        output_gpb_path = output_gpb_file.name
    
        # Simple modal wait dialog (no counter/bar)
        def show_wait_dialog():
            parent = self.winfo_toplevel()
            dlg = tk.Toplevel(parent)
            dlg.title("Working")
            dlg.resizable(False, False)
            dlg.transient(parent)
            dlg.grab_set()
            tk.Label(dlg, text="Converting textures...\n\nPlease wait.", padx=30, pady=20).pack()
            dlg.update_idletasks()
            dlg.update()
            x = parent.winfo_rootx() + (parent.winfo_width() // 2) - (dlg.winfo_width() // 2)
            y = parent.winfo_rooty() + (parent.winfo_height() // 2) - (dlg.winfo_height() // 2)
            dlg.geometry(f"+{x}+{y}")
            return dlg
    
        wait_dialog = show_wait_dialog()
    
        def worker():
            img_deletions = []
            ps2zip_deletions = []
            del_lock = threading.Lock()
    
            def record_delete(lst, p):
                with del_lock:
                    lst.append(os.path.normpath(p))
    
            def cleanup_recorded():
                def unique(seq):
                    seen = set()
                    out = []
                    for p in seq:
                        if p not in seen:
                            out.append(p)
                            seen.add(p)
                    return out
    
                # Delete .img.ps2zip first (if any)
                for p in unique(ps2zip_deletions):
                    try:
                        if os.path.isfile(p):
                            os.remove(p)
                    except Exception as e:
                        print(f"[Cleanup] Failed to delete: {p}\n  {e}")
    
                # Then delete converted .img files
                for p in unique(img_deletions):
                    try:
                        if os.path.isfile(p):
                            os.remove(p)
                    except Exception as e:
                        print(f"[Cleanup] Failed to delete: {p}\n  {e}")
    
            try:
                # ---------------------------------------------------------
                # PRE-STEP A: multithreaded conversion of ALL .png files
                # Root = folder containing the ini file
                # ---------------------------------------------------------
                root_folder = os.path.dirname(ini_file_path)
                png_files = []
                for root, _, files in os.walk(root_folder):
                    for fn in files:
                        if fn.lower().endswith(".png"):
                            png_files.append(os.path.join(root, fn))
    
                def run_make_tex_set(png_path: str):
                    subprocess.run(
                        [GTPS2MODELTOOL_EXE, "make-tex-set", "-i", png_path],
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    img_path = os.path.splitext(png_path)[0] + ".img"
                    record_delete(img_deletions, img_path)
    
                max_workers = min(8, (os.cpu_count() or 4))
                errors = []
    
                with ThreadPoolExecutor(max_workers=max_workers) as ex:
                    futures = {ex.submit(run_make_tex_set, p): p for p in png_files}
                    for fut in as_completed(futures):
                        p = futures[fut]
                        try:
                            fut.result()
                        except subprocess.CalledProcessError as e:
                            err = (e.stderr or e.stdout or "").strip()
                            errors.append((p, err))
                        except Exception as e:
                            errors.append((p, str(e)))
    
                if errors:
                    def on_fail():
                        wait_dialog.destroy()
                        print("GTPS2ModelTool make-tex-set errors:")
                        for p, err in errors:
                            print(f"- {p}\n  {err}\n")
                        messagebox.showerror(
                            "Conversion error",
                            f"make-tex-set failed for {len(errors)} PNG file(s).\n"
                            f"See console for details.\n\nAborting GPB generation."
                        )
                    self.after(0, on_fail)
                    return
    
                # ---------------------------------------------------------
                # Parse [Textures] entries in numeric order, including compression flag
                # ---------------------------------------------------------
                config = configparser.ConfigParser()
                config.read(ini_file_path)
                if 'Textures' not in config:
                    def on_fail2():
                        wait_dialog.destroy()
                        messagebox.showerror("Error", "Missing [Textures] section in ini.")
                    self.after(0, on_fail2)
                    return
    
                tex = config['Textures']
                pat = re.compile(r'^texture_(\d+)_(path|label|compression)$', re.IGNORECASE)
    
                items = {}
                for k, v in tex.items():
                    m = pat.match(k)
                    if not m:
                        continue
                    idx = int(m.group(1))
                    field = m.group(2).lower()
                    items.setdefault(idx, {})[field] = v
    
                indices = sorted(items.keys())
                if not indices:
                    def on_fail3():
                        wait_dialog.destroy()
                        messagebox.showerror("Error", "No texture_* entries found in [Textures].")
                    self.after(0, on_fail3)
                    return
    
                texture_paths = []
                texture_labels = []
                texture_comp = []
    
                for idx in indices:
                    entry = items[idx]
                    if 'path' not in entry or 'label' not in entry:
                        def on_missing():
                            wait_dialog.destroy()
                            messagebox.showerror("Error", f"Missing path/label for texture_{idx}.")
                        self.after(0, on_missing)
                        return
    
                    comp_raw = entry.get('compression', '0')
                    try:
                        comp_val = 1 if int(comp_raw) == 1 else 0
                    except Exception:
                        comp_val = 0
    
                    texture_paths.append(entry['path'])
                    texture_labels.append(entry['label'])
                    texture_comp.append(comp_val)
    
                # ---------------------------------------------------------
                # PRE-STEP B: PS2ZIP compress only flagged textures (.img -> .img.ps2zip)
                # ---------------------------------------------------------
                to_compress = [p for p, c in zip(texture_paths, texture_comp) if c == 1]
    
                def run_ps2zip(img_path: str):
                    subprocess.run(
                        [zip_exe, img_path],
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    out_path = img_path + ".ps2zip"
                    if not os.path.isfile(out_path):
                        raise RuntimeError(f"PS2Zip output not found:\n{out_path}")
                    record_delete(ps2zip_deletions, out_path)
    
                errors = []
                if to_compress:
                    with ThreadPoolExecutor(max_workers=max_workers) as ex:
                        futures = {ex.submit(run_ps2zip, p): p for p in to_compress}
                        for fut in as_completed(futures):
                            p = futures[fut]
                            try:
                                fut.result()
                            except subprocess.CalledProcessError as e:
                                err = (e.stderr or e.stdout or "").strip()
                                errors.append((p, err))
                            except Exception as e:
                                errors.append((p, str(e)))
    
                if errors:
                    def on_fail_zip():
                        wait_dialog.destroy()
                        print("PolyphonyPS2Zip errors:")
                        for p, err in errors:
                            print(f"- {p}\n  {err}\n")
                        messagebox.showerror(
                            "Compression error",
                            f"PS2Zip failed for {len(errors)} texture(s).\n"
                            f"See console for details.\n\nAborting GPB generation."
                        )
                    self.after(0, on_fail_zip)
                    return
    
                # ---------------------------------------------------------
                # PACK GPB2 (same format), using .img.ps2zip when compression=1
                # ---------------------------------------------------------
                num_textures = len(texture_paths)
    
                with open(output_gpb_path, "wb") as f:
                    f.write(b'gpb2')
                    f.write(b'\x00' * 8)
                    f.write(struct.pack('<I', num_textures))
    
                    metadata_start = f.tell()
                    f.write(b'\x00' * (num_textures * 16))
    
                    filename_offsets = []
                    current_offset = f.tell()
    
                    for custom_filename in texture_labels:
                        custom_filename_bytes = custom_filename.encode('utf-8') + b'\x00'
                        for byte in custom_filename_bytes:
                            f.write(struct.pack('B', byte))
                        filename_offsets.append(current_offset)
                        current_offset = f.tell()
    
                    while f.tell() % 16 != 0:
                        f.write(b'\x5E')
    
                    texture_offsets = []
                    for path, comp_val in zip(texture_paths, texture_comp):
                        pack_path = (path + ".ps2zip") if comp_val == 1 else path
                        with open(pack_path, 'rb') as img_file:
                            img_data = img_file.read()
    
                        texture_offset = f.tell()
                        f.write(img_data)
    
                        while f.tell() % 16 != 0:
                            f.write(b'\x5E')
    
                        texture_offsets.append(texture_offset)
    
                    for i in range(num_textures):
                        f.seek(metadata_start + i * 16)
                        f.write(struct.pack('<I', filename_offsets[i]))
                        f.seek(metadata_start + 4 + i * 16)
                        f.write(struct.pack('<I', texture_offsets[i]))
                        f.seek(metadata_start + 8 + i * 16)
                        f.write(b'\x00' * 8)
    
                # Cleanup at end
                cleanup_recorded()
    
                def on_success():
                    wait_dialog.destroy()
                    messagebox.showinfo("Success!", f"GPB generation completed. {num_textures} textures packed.")
                self.after(0, on_success)
    
            except Exception as e:
                try:
                    cleanup_recorded()
                except Exception:
                    pass
    
                def on_error():
                    wait_dialog.destroy()
                    messagebox.showerror("Error", str(e))
                self.after(0, on_error)
    
        threading.Thread(target=worker, daemon=True).start()

    def generate_gpb3(self):
        # Ask user to select the gpb_config.ini file
        ini_file_path = filedialog.askopenfilename(title="Select gpb_config.ini File", filetypes=[("INI files", "*.ini")])
        if not ini_file_path:
            return  # Return if no file selected
            
        # Ask user to specify the output .gpb file location and name
        output_gpb_file = filedialog.asksaveasfile(
            title="Save .gpb File As",
            filetypes=[("GPB files", "*.gpb")],
            defaultextension=".gpb"
        )
        if not output_gpb_file:
            return  # Return if user cancels the save dialog
            
        # Get the selected output file path
        output_gpb_path = output_gpb_file.name
        
        # Load and parse the gpb_config.ini file
        config = configparser.ConfigParser()
        config.read(ini_file_path)
    
        # Clear existing texture lists
        self.texture_names.clear()
        self.custom_filenames.clear()
    
        extracted_filenames = []
    
        # Iterate through sections and keys in the config file
        for section in config.sections():
            for key in config[section]:
                # Check if key ends with '_path_'
                if key.endswith('_path_'):
                    full_path = config[section][key]
                    
                    # Check file size in bytes directly
                    if os.path.getsize(full_path) > 134217728:  # 128 MB
                        # Display warning message
                        user_choice = messagebox.askyesno(
                            "Large file detected!",
                            f"The file `{full_path}` is larger than 128 megabytes. The PS3 only has 256mb of video memory.\nYou have likely selected the wrong root folder, and should abort this process and try again. Are you sure you want to continue?"
                        )
                        if not user_choice:
                            return  # Abort the operation if the user chooses not to continue
    
                    # Extract filename from full path
                    filename = os.path.basename(full_path)
    
                    # Extract relative path from full path
                    relative_path = os.path.relpath(full_path, os.path.dirname(ini_file_path)).replace("\\", "/")[:-4]
    
                    self.texture_names.append((os.path.dirname(full_path), filename))
                    self.custom_filenames[filename] = relative_path
    
                    # Add filename to extracted_filenames list
                    extracted_filenames.append(filename)

                    self.update_texture_listbox()
                    self.update_filename_listbox()
    
        config = configparser.ConfigParser()
        config.read(ini_file_path)
    
        texture_paths = []
        texture_labels = []
        for key in config['Textures']:
            if key.endswith('_path'):
                texture_paths.append(config['Textures'][key])
            elif key.endswith('_label'):
                texture_labels.append(config['Textures'][key])
    
        if len(texture_paths) != len(texture_labels):
            messagebox.showerror("Error", "Mismatch between texture paths and labels.")
            return
    
        num_textures = len(texture_paths)
    
        with open(output_gpb_path, "wb") as f:
            # Step 1: haha PD forgot that PS3 is Big-endian
            f.write(b'3bpg')
            f.write(b'\x00' * 4)
            
            # 20, byte count of the header, static
            f.write(b'\x00' * 3)
            f.write(b'\x20')
    
            # Texture count, dynamic
            f.write(struct.pack('>I', num_textures))
    
            # 20, start of the metadata chunk, static
            f.write(b'\x00' * 3)
            f.write(b'\x20')

            # Calculate the offset for the start of the string chunk
            string_chunk_start = 0x20 + (num_textures * 16)  # Start after header space, scale up with number of textures
            f.write(struct.pack('>I', string_chunk_start))
            
            # Reserve 4 bytes for the start of the texture chunk
            f.write(b'\x00' * 4)
            texture_data_start = f.tell()

            #padding, static
            f.write(b'\x00' * 4)

            # Step 3: Write reserved space for texture metadata
            metadata_start = f.tell()
            f.write(b'\x00' * (num_textures * 16))
    
            # Step 4: Insert the file names and labels
            filename_offsets = []
            current_offset = f.tell()
    
            for custom_filename in texture_labels:
                custom_filename_bytes = custom_filename.encode('utf-8') + b'\x00'
    
                # Write each byte of the custom_filename_bytes
                for byte in custom_filename_bytes:
                    f.write(struct.pack('B', byte))
    
                # Store filename offset
                filename_offsets.append(current_offset)
    
                current_offset = f.tell()  # Update the current offset after writing each filename
    
            # Pad to 0x00000100, or if already above that, pad to next factor of 64
            current_pos = f.tell()
            next_factor_of_64 = (current_pos + 63) // 64 * 64
            padding_needed = max(0x00000100 - current_pos, next_factor_of_64 - current_pos)
            while padding_needed > 0:
                bytes_to_write = min(padding_needed, 16)  # Write up to 16 bytes at a time
                f.write(b'\x5E' * bytes_to_write)
                padding_needed -= bytes_to_write
    
            # Step 6: Insert the user's inputted texture files into the gpb file
            texture_offsets = []
            byte_counts = []
            
            for path in texture_paths:
                with open(path, 'rb') as img_file:
                    img_data = img_file.read()
            
                    # Write texture data and get its offset
                    texture_offset = f.tell()  # offset
                    f.write(img_data)  # read the .img file
                    
                    # padding again because I suck at programming
                    while f.tell() % 128 != 0:
                        f.write(b'\x5E')
                        
                    texture_offsets.append(texture_offset)
                    byte_counts.append(len(img_data))  # Store byte count for this texture

            # Step 7: Populate texture metadata
            for i in range(num_textures):
                # Write filename address
                f.seek(metadata_start + i * 16)
                f.write(struct.pack('>I', filename_offsets[i]))
    
                # Write texture data address
                f.seek(metadata_start + 4 + i * 16)
                f.write(struct.pack('>I', texture_offsets[i]))
                
                # Write texture data byte count
                f.seek(metadata_start + 8 + i * 16)
                f.write(byte_count_to_bytes(byte_counts[i]))
    
                # Write padding (8 bytes)
                f.seek(metadata_start + 12 + i * 16)
                f.write(b'\x00' * 4)
            
            # Step 8: Populate Address 0x00000018 through 0x0000001C (Texture chunk start)
            with open(output_gpb_path, 'rb+') as f_step8:
                f_step8.seek(0x00000024)
                data = f_step8.read(4)
                f_step8.seek(0x00000018)
                f_step8.write(data)
                    
            #Final padding to the next factor of 64
            current_pos = f.tell()
            next_factor_of_64 = (current_pos + 63) // 64 * 64
            padding_needed = next_factor_of_64 - current_pos
            
            # Re-open the file to add padding
            with open(output_gpb_path, "ab") as f:
                f.write(b'\x5E' * padding_needed)
            
            messagebox.showinfo("Success!", f"GPB generation completed. {num_textures} textures packed.")

    def extract_gpb0(self, gpb_path):
        if not self.destination_dir:
            messagebox.showerror("Error", "No destination directory selected.")
            return
    
        def run_dump(img_path: str):
            # Check compression magic
            try:
                with open(img_path, "rb") as fh:
                    magic = fh.read(4)
            except Exception as e:
                raise RuntimeError(f"Failed reading magic for: {img_path}\n{e}")
    
            dump_input = img_path
            decompressed_path = None
    
            # 1) Decompress if needed
            if magic == COMP_MAGIC:
                subprocess.run(
                    [zip_exe, img_path],
                    capture_output=True,
                    text=True,
                    check=True
                )
                decompressed_path = img_path + "_decompressed"
                dump_input = decompressed_path
    
                if not os.path.isfile(decompressed_path):
                    raise RuntimeError(f"PolyphonyPS2Zip did not produce expected output:\n{decompressed_path}")
    
            # 2) Convert to PNG
            subprocess.run(
                [GTPS2MODELTOOL_EXE, "dump", "-i", dump_input],
                capture_output=True,
                text=True,
                check=True
            )
    
            # 3) Cleanup ONLY after successful dump
            try:
                if os.path.isfile(img_path):
                    os.remove(img_path)
            except Exception as e:
                print(f"[Cleanup] Failed to delete original IMG: {img_path}\n  {e}")
    
            if decompressed_path:
                try:
                    if os.path.isfile(decompressed_path):
                        os.remove(decompressed_path)
                except Exception as e:
                    print(f"[Cleanup] Failed to delete decompressed IMG: {decompressed_path}\n  {e}")
    
        with open(gpb_path, 'rb') as f:
            # Step 1: Read texture count
            f.seek(0x00000004)
            num_textures = struct.unpack('<I', f.read(4))[0]
            print(f"Number of textures: {num_textures}")
    
            # Step 2: Read metadata
            metadata_start = 0x00000008
            metadata_end = metadata_start + (8 * int(num_textures))
            f.seek(metadata_start)
            metadata = f.read(metadata_end - metadata_start)
    
            extracted_labels = []     # original labels from GPB
            compression_flags = []    # 0/1 per texture
    
            # Step 3: Extract all files first
            for i in range(num_textures):
                filename_offset = int.from_bytes(metadata[i*8:i*8+4], byteorder='little')
                texture_offset  = int.from_bytes(metadata[i*8+4:i*8+8], byteorder='little')
    
                # Read label string
                f.seek(filename_offset)
                filename_bytes = bytearray()
                while True:
                    b = f.read(1)
                    if b == b'\x00':
                        break
                    filename_bytes.append(b[0])
                label = filename_bytes.decode('utf-8')
                extracted_labels.append(label)
    
                # Output dir
                dir_path = os.path.dirname(label)
                dir_full_path = os.path.join(self.destination_dir, dir_path)
                os.makedirs(dir_full_path, exist_ok=True)
    
                base = os.path.basename(label)
    
                # Export name rules:
                # - if label ends .png => replace to .img
                # - else => append .img (keeps old behavior)
                if base.lower().endswith(".png"):
                    exported_filename = os.path.splitext(base)[0] + ".img"
                else:
                    exported_filename = base + ".img"
    
                # Determine end boundary
                # (keep your metadata indexing style; key fix is: do NOT trim 0x5E)
                next_texture_offset = int.from_bytes(metadata[i*8+12:i*8+16], byteorder='little')
    
                if next_texture_offset == 0:
                    last_byte_address = os.path.getsize(gpb_path)
                else:
                    last_byte_address = next_texture_offset
    
                # Extract bytes
                f.seek(texture_offset)
                img_data = f.read(last_byte_address - texture_offset)
    
                compression_flags.append(1 if img_data[:4] == COMP_MAGIC else 0)
    
                output_path = os.path.join(dir_full_path, exported_filename)
                with open(output_path, 'wb') as out_file:
                    out_file.write(img_data)
    
            # Step 4: Write config (path=.img, label=original)
            config = configparser.ConfigParser()
            config.add_section('Textures')
    
            for idx, label in enumerate(extracted_labels, start=1):
                label_norm = label.replace("\\", "/")
    
                # path should point to .img (label stays same)
                path_name = label
                if path_name.lower().endswith(".png"):
                    path_name = os.path.splitext(path_name)[0] + ".img"
                else:
                    path_name = path_name + ".img"
    
                full_path = os.path.join(self.destination_dir, path_name).replace("\\", "/")
    
                config.set('Textures', f'texture_{idx}_path', full_path)
                config.set('Textures', f'texture_{idx}_label', label_norm)
                config.set('Textures', f'texture_{idx}_compression', str(compression_flags[idx-1]))
    
            config_file_path = os.path.join(self.destination_dir, 'gpb0_config.ini')
            with open(config_file_path, 'w', encoding='utf-8') as config_file:
                config.write(config_file)
    
        # Step 5: Convert all .img -> .png after config
        img_files = []
        for root, _, files in os.walk(self.destination_dir):
            for fn in files:
                if fn.lower().endswith('.img'):
                    img_files.append(os.path.join(root, fn))
    
        parent = tk._default_root
        wait_dialog = tk.Toplevel(parent)
        wait_dialog.title("Working")
        wait_dialog.resizable(False, False)
        wait_dialog.transient(parent)
        wait_dialog.grab_set()
        tk.Label(wait_dialog, text="Converting textures to PNG...\n\nPlease wait.", padx=30, pady=20).pack()
        wait_dialog.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (wait_dialog.winfo_width() // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (wait_dialog.winfo_height() // 2)
        wait_dialog.geometry(f"+{x}+{y}")
    
        max_workers = min(8, (os.cpu_count() or 4))
        errors = []
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(run_dump, p): p for p in img_files}
            for fut in as_completed(futures):
                p = futures[fut]
                try:
                    fut.result()
                except subprocess.CalledProcessError as e:
                    err = (e.stderr or e.stdout or "").strip()
                    errors.append((p, err))
                except Exception as e:
                    errors.append((p, str(e)))
    
        wait_dialog.destroy()
    
        if errors:
            print("Dump errors:")
            for p, err in errors:
                print(f"- {p}\n  {err}\n")
            messagebox.showerror(
                "Completed with errors",
                f"Extraction + config written.\n\nDump failed for {len(errors)} file(s). See console for details."
            )
        else:
            messagebox.showinfo("Success!", f"GPB extraction completed. {num_textures} textures extracted.")
            print(f"GPB extraction completed. {num_textures} textures extracted.")

    def extract_gpb1(self, gpb_path):
        if not self.destination_dir:
            messagebox.showerror("Error", "No destination directory selected.")
            return
    
        def run_dump(img_path: str):
            try:
                with open(img_path, "rb") as fh:
                    magic = fh.read(4)
            except Exception as e:
                raise RuntimeError(f"Failed reading magic for: {img_path}\n{e}")
    
            dump_input = img_path
            decompressed_path = None
    
            if magic == COMP_MAGIC:
                subprocess.run([zip_exe, img_path], capture_output=True, text=True, check=True)
                decompressed_path = img_path + "_decompressed"
                dump_input = decompressed_path
                if not os.path.isfile(decompressed_path):
                    raise RuntimeError(f"PolyphonyPS2Zip did not produce expected output:\n{decompressed_path}")
    
            subprocess.run([GTPS2MODELTOOL_EXE, "dump", "-i", dump_input],
                        capture_output=True, text=True, check=True)
    
            try:
                if os.path.isfile(img_path):
                    os.remove(img_path)
            except Exception as e:
                print(f"[Cleanup] Failed to delete original IMG: {img_path}\n  {e}")
    
            if decompressed_path:
                try:
                    if os.path.isfile(decompressed_path):
                        os.remove(decompressed_path)
                except Exception as e:
                    print(f"[Cleanup] Failed to delete decompressed IMG: {decompressed_path}\n  {e}")
    
        with open(gpb_path, 'rb') as f:
            # gpb1 texture count lives at 0x0C in your existing code
            f.seek(0x0000000C)
            num_textures = struct.unpack('<I', f.read(4))[0]
            print(f"Number of textures: {num_textures}")
    
            metadata_start = 0x00000010
            metadata_end = metadata_start + (8 * int(num_textures))
            f.seek(metadata_start)
            metadata = f.read(metadata_end - metadata_start)
    
            extracted_labels = []
            compression_flags = []
    
            for i in range(num_textures):
                filename_offset = int.from_bytes(metadata[(i*8):(i*8)+4], byteorder='little')
                texture_offset  = int.from_bytes(metadata[(i*8)+4:(i*8)+8], byteorder='little')
    
                f.seek(filename_offset)
                filename_bytes = bytearray()
                while True:
                    b = f.read(1)
                    if b == b'\x00':
                        break
                    filename_bytes.append(b[0])
                label = filename_bytes.decode('utf-8')
                extracted_labels.append(label)
    
                dir_path = os.path.dirname(label)
                dir_full_path = os.path.join(self.destination_dir, dir_path)
                os.makedirs(dir_full_path, exist_ok=True)
    
                base = os.path.basename(label)
                if base.lower().endswith(".png"):
                    exported_filename = os.path.splitext(base)[0] + ".img"
                else:
                    exported_filename = base + ".img"
    
                next_texture_offset = int.from_bytes(metadata[(i*8)+12:(i*8)+16], byteorder='little')
                if next_texture_offset == 0:
                    last_byte_address = os.path.getsize(gpb_path)
                else:
                    last_byte_address = next_texture_offset  # do NOT trim 0x5E
    
                f.seek(texture_offset)
                img_data = f.read(last_byte_address - texture_offset)
    
                compression_flags.append(1 if img_data[:4] == COMP_MAGIC else 0)
    
                output_path = os.path.join(dir_full_path, exported_filename)
                with open(output_path, 'wb') as out_file:
                    out_file.write(img_data)
    
            config = configparser.ConfigParser()
            config.add_section('Textures')
    
            for idx, label in enumerate(extracted_labels, start=1):
                label_norm = label.replace("\\", "/")
    
                path_name = label
                if path_name.lower().endswith(".png"):
                    path_name = os.path.splitext(path_name)[0] + ".img"
                else:
                    path_name = path_name + ".img"
    
                full_path = os.path.join(self.destination_dir, path_name).replace("\\", "/")
    
                config.set('Textures', f'texture_{idx}_path', full_path)
                config.set('Textures', f'texture_{idx}_label', label_norm)
                config.set('Textures', f'texture_{idx}_compression', str(compression_flags[idx-1]))
    
            config_file_path = os.path.join(self.destination_dir, 'gpb1_config.ini')
            with open(config_file_path, 'w', encoding='utf-8') as config_file:
                config.write(config_file)
    
        img_files = []
        for root, _, files in os.walk(self.destination_dir):
            for fn in files:
                if fn.lower().endswith('.img'):
                    img_files.append(os.path.join(root, fn))
    
        parent = tk._default_root
        wait_dialog = tk.Toplevel(parent)
        wait_dialog.title("Working")
        wait_dialog.resizable(False, False)
        wait_dialog.transient(parent)
        wait_dialog.grab_set()
        tk.Label(wait_dialog, text="Converting textures to PNG...\n\nPlease wait.", padx=30, pady=20).pack()
        wait_dialog.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (wait_dialog.winfo_width() // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (wait_dialog.winfo_height() // 2)
        wait_dialog.geometry(f"+{x}+{y}")
    
        max_workers = min(8, (os.cpu_count() or 4))
        errors = []
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(run_dump, p): p for p in img_files}
            for fut in as_completed(futures):
                p = futures[fut]
                try:
                    fut.result()
                except subprocess.CalledProcessError as e:
                    err = (e.stderr or e.stdout or "").strip()
                    errors.append((p, err))
                except Exception as e:
                    errors.append((p, str(e)))
    
        wait_dialog.destroy()
    
        if errors:
            print("Dump errors:")
            for p, err in errors:
                print(f"- {p}\n  {err}\n")
            messagebox.showerror(
                "Completed with errors",
                f"Extraction + config written.\n\nDump failed for {len(errors)} file(s). See console for details."
            )
        else:
            messagebox.showinfo("Success!", f"GPB extraction completed. {num_textures} textures extracted.")
            print(f"GPB extraction completed. {num_textures} textures extracted.")

    def extract_gpb2(self, gpb_path):
        if not self.destination_dir:
            messagebox.showerror("Error", "No destination directory selected.")
            return
    
        def run_dump(img_path: str):
            # Check compression magic
            try:
                with open(img_path, "rb") as fh:
                    magic = fh.read(4)
            except Exception as e:
                raise RuntimeError(f"Failed reading magic for: {img_path}\n{e}")
        
            dump_input = img_path
            decompressed_path = None
        
            # 1) Decompress if needed
            if magic == COMP_MAGIC:
                subprocess.run(
                    [zip_exe, img_path],
                    capture_output=True,
                    text=True,
                    check=True
                )
        
                decompressed_path = img_path + "_decompressed"
                dump_input = decompressed_path
        
                if not os.path.isfile(decompressed_path):
                    raise RuntimeError(
                        f"PolyphonyPS2Zip did not produce expected output:\n{decompressed_path}"
                    )
        
            # 2) Convert to PNG
            subprocess.run([GTPS2MODELTOOL_EXE, "dump", "-i", dump_input],
                        capture_output=True, text=True, check=True)
        
            # 3) Cleanup (ONLY after successful dump)
            try:
                if os.path.isfile(img_path):
                    os.remove(img_path)
            except Exception as e:
                print(f"[Cleanup] Failed to delete original IMG: {img_path}\n  {e}")
        
            if decompressed_path:
                try:
                    if os.path.isfile(decompressed_path):
                        os.remove(decompressed_path)
                except Exception as e:
                    print(f"[Cleanup] Failed to delete decompressed IMG: {decompressed_path}\n  {e}")
    
        with open(gpb_path, 'rb') as f:
            # Read texture count
            f.seek(0x0000000C)
            num_textures = struct.unpack('<I', f.read(4))[0]
            print(f"Number of textures: {num_textures}")
    
            # Read metadata block
            metadata_start = 0x00000010
            metadata_end = metadata_start + (16 * int(num_textures))
            f.seek(metadata_start)
            metadata = f.read(metadata_end - metadata_start)
    
            extracted_filenames = []   # original filenames from GPB (labels)
            written_img_paths = []     # actual .img files written to disk (for dumping)
            compression_flags = []  # 0/1 aligned to extracted_filenames order
    
            # 1) EXTRACT ALL FILES FIRST (no subprocess here)
            for i in range(num_textures):
                filename_offset = int.from_bytes(metadata[i*16:i*16+4], byteorder='little')
                texture_offset  = int.from_bytes(metadata[i*16+4:i*16+8], byteorder='little')
    
                # Extract filename string
                f.seek(filename_offset)
                filename_bytes = bytearray()
                while True:
                    b = f.read(1)
                    if b == b'\x00':
                        break
                    filename_bytes.append(b[0])
                extracted_filename = filename_bytes.decode('utf-8')
                extracted_filenames.append(extracted_filename)
    
                # Create output directories
                dir_path = os.path.dirname(extracted_filename)
                dir_full_path = os.path.join(self.destination_dir, dir_path)
                os.makedirs(dir_full_path, exist_ok=True)
    
                name = os.path.basename(extracted_filename)
    
                # Write output file:
                # If GPB label ends in .png, write it as .img (replace ext, don't append)
                exported_filename = name
                if name.lower().endswith('.png'):
                    exported_filename = os.path.splitext(name)[0] + '.img'
    
                # Determine byte range for data (keeping your existing logic)
                # NOTE: Your original next_texture_offset indexing looks suspicious (i*16+20),
                # but I'm not changing it here since it's outside this performance refactor.
                next_texture_offset = int.from_bytes(metadata[i*16+20:i*16+24], byteorder='little')
    
                if next_texture_offset == 0:
                    last_byte_address = os.path.getsize(gpb_path)
                else:
                    # DO NOT trim trailing 0x5E; it can be real data
                    last_byte_address = next_texture_offset
    
                # Extract and write bytes
                f.seek(texture_offset)
                img_data = f.read(last_byte_address - texture_offset)
                
                is_compressed = 1 if img_data[:4] == COMP_MAGIC else 0
                compression_flags.append(is_compressed)
    
                output_path = os.path.join(dir_full_path, exported_filename)
                with open(output_path, 'wb') as out_file:
                    out_file.write(img_data)
    
                # Track .img outputs for later dumping
                if output_path.lower().endswith('.img'):
                    written_img_paths.append(output_path)
    
            # 2) WRITE CONFIG (path ends with .img, label ends with .png), GPB order preserved
            config = configparser.ConfigParser()
            config.add_section('Textures')
    
            for idx, filename in enumerate(extracted_filenames, start=1):
                # label stays as original (.png)
                label = filename.replace("\\", "/")
    
                # path is forced to .img when filename is .png
                path_name = filename
                if path_name.lower().endswith('.png'):
                    path_name = os.path.splitext(path_name)[0] + '.img'
    
                full_path = os.path.join(self.destination_dir, path_name).replace("\\", "/")
    
                config.set('Textures', f'texture_{idx}_path', full_path)
                config.set('Textures', f'texture_{idx}_label', label)
                config.set('Textures', f'texture_{idx}_compression', str(compression_flags[idx-1]))
    
            config_file_path = os.path.join(self.destination_dir, 'gpb2_config.ini')
            with open(config_file_path, 'w', encoding='utf-8') as config_file:
                config.write(config_file)
    
        # 3) AFTER CONFIG: find all .img recursively (in case some weren’t in written_img_paths)
        img_files = []
        for root, _, files in os.walk(self.destination_dir):
            for fn in files:
                if fn.lower().endswith('.img'):
                    img_files.append(os.path.join(root, fn))
    
        # Shitty ass Dialog window
        parent = tk._default_root  # guaranteed main window
        
        wait_dialog = tk.Toplevel(parent)
        wait_dialog.title("Working")
        wait_dialog.resizable(False, False)
        wait_dialog.transient(parent)
        wait_dialog.grab_set()
        
        label = tk.Label(
            wait_dialog,
            text="Converting textures to PNG...\n\nPlease wait.",
            padx=30,
            pady=20
        )
        label.pack()
        
        # Force layout so size is calculated
        wait_dialog.update_idletasks()
        
        # Center over parent window
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (wait_dialog.winfo_width() // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (wait_dialog.winfo_height() // 2)
        wait_dialog.geometry(f"+{x}+{y}")
        
        # 4) MULTITHREADED DUMP + DELETE
        max_workers = min(8, (os.cpu_count() or 4))
    
        errors = []
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(run_dump, p): p for p in img_files}
            for fut in as_completed(futures):
                p = futures[fut]
                try:
                    fut.result()
                except subprocess.CalledProcessError as e:
                    err = (e.stderr or e.stdout or "").strip()
                    errors.append((p, err))
                except Exception as e:
                    errors.append((p, str(e)))
    
        # 5) DONE
        wait_dialog.destroy()
        if errors:
            print("GTPS2ModelTool errors:")
            for p, err in errors:
                print(f"- {p}\n  {err}\n")
            messagebox.showerror(
                "Completed with errors",
                f"Extraction + config written.\n\n"
                f"Dump failed for {len(errors)} file(s). See console for details."
            )
        else:
            messagebox.showinfo("Success!", f"GPB extraction completed. {num_textures} textures extracted.")
            print(f"GPB extraction completed. {num_textures} textures extracted.")
    
    def extract_gpb3(self, gpb_path):
        if not self.destination_dir:
            messagebox.showerror("Error", "No destination directory selected.")
            return
                
        import struct
        
        # Define a variable to store the number of textures
        num_textures = None  # Initialize with None or any default value
    
        with open(gpb_path, 'rb') as f:
            # Step 1: Read the number of textures
            f.seek(0x0000000C)  # Seek to the address for texture count
            texture_count_bytes = f.read(4)  # Read 4 bytes
                
            # Unpack the bytes to get the integer value
            texture_count = struct.unpack('>I', texture_count_bytes)[0]
            
            # Store the texture_count value in num_textures
            num_textures = texture_count
            print(f"Number of textures: {num_textures}")  # Debugging
                
            # List to hold metadata
            filename_offsets = []
            texture_offsets = []
            next_texture_offsets = []
            
            # Step 1.1: Calculate byte range for texture metadata
            metadata_start = 0x00000020
            metadata_end = int(metadata_start) + (16 * int(num_textures))
            print(f"Metadata start: {metadata_start}, Metadata end: {metadata_end}")
            
            # Step 1.2: Read texture metadata
            f.seek(metadata_start)
            metadata = f.read(metadata_end - metadata_start)
            print(f"Metadata length: {len(metadata)}")  # Debugging
            
            # List to hold extracted filenames
            extracted_filenames = []
            # Step 2 & 3: Process each texture metadata chunk
            for i in range(num_textures):
                filename_offset = int.from_bytes(metadata[i*16:i*16+4], byteorder='big')
                texture_offset = int.from_bytes(metadata[i*16+4:i*16+8], byteorder='big')
                
                # Extract filename from the given offset
                f.seek(filename_offset)
                filename_bytes = bytearray()
                while True:
                    byte = f.read(1)
                    if byte == b'\x00':
                        break
                    filename_bytes.append(byte[0])
                    
                extracted_filename = filename_bytes.decode('utf-8')
                extracted_filenames.append(extracted_filename)  # Store the extracted filename in the list
                # Create directories if they don't exist
                dir_path = os.path.dirname(extracted_filename)
                dir_full_path = f"{self.destination_dir}{dir_path}"
                if not os.path.exists(dir_full_path):
                    os.makedirs(dir_full_path)
            
                # Determine exported filename
                exported_filename = os.path.basename(extracted_filename) + '.img'
            
                # Determine byte range for texture data
                next_texture_offset = int.from_bytes(metadata[i*16+20:i*16+24], byteorder='big')
                
                print(f"--------")
                print(f"Texture# {i+1}: `{extracted_filename}`")
                print(f"Extracting to: {dir_full_path}{exported_filename}")
                print(f"Label offset: {filename_offset}")  # Debugging
                print(f"1st byte: {texture_offset}")  # Debugging
                
                # Break out of the loop if next_texture_offset is 0
                if next_texture_offset == 0:
                    last_byte_address = os.path.getsize(gpb_path)
                    print(f"Last byte: [END OF FILE]")  # Debugging
                else:
                    f.seek(next_texture_offset - 1)
                    while f.read(1) == b'\x5E':
                        next_texture_offset -= 1
                        f.seek(next_texture_offset - 1)
                    last_byte_address = next_texture_offset
                    print(f"Last byte: {next_texture_offset}")  # Debugging
                        
                f.seek(texture_offset)
                img_data = f.read((last_byte_address) - texture_offset)
            
                output_path = os.path.join(dir_full_path, exported_filename)
                with open(output_path, 'wb') as out_file:
                    out_file.write(img_data)
                    
            print(f"--------")
            print(f"GPB extraction completed. {num_textures} textures extracted.")
                
            config = configparser.ConfigParser()
            config.add_section('Textures')
            
            for i, filename in enumerate(extracted_filenames):
                full_path = os.path.join(self.destination_dir, filename + '.img')
                full_path = full_path.replace("\\", "/")
                
                config.set('Textures', f'texture_{i+1}_path', full_path)
                config.set('Textures', f'texture_{i+1}_label', filename)
            
            config_file_path = os.path.join(self.destination_dir, 'gpb3_config.ini')
            with open(config_file_path, 'w') as config_file:
                config.write(config_file)
            
            messagebox.showinfo("Success!", f"GPB extraction completed. {num_textures} textures extracted.")
            
    def ask_root_folder_and_generate(self):
        root_folder = filedialog.askdirectory(title="Select Root Folder")
        
        if root_folder:
            self.generate_texture_paths(root_folder)
        else:
            messagebox.showerror("Error", "No root folder selected.")
        
    def generate_texture_paths(self, root_folder):
        config = configparser.ConfigParser()
        config.add_section('Textures')
    
        entries = []
    
        # Collect ALL PNG files
        for root, _, files in os.walk(root_folder):
            for file_name in files:
                if not file_name.lower().endswith('.png'):
                    continue
    
                rel_dir = os.path.relpath(root, root_folder)
    
                # Label stays .png
                if rel_dir == ".":
                    label = file_name
                else:
                    label = os.path.join(rel_dir, file_name)
    
                label = label.replace("\\", "/")
    
                # Path must point to .img (same name, different extension)
                img_name = os.path.splitext(file_name)[0] + ".img"
                abs_path = os.path.abspath(os.path.join(root, img_name))
                abs_path = abs_path.replace("\\", "/")
    
                entries.append((label, abs_path))
    
        # Strict ASCII lexicographic order (by label)
        entries.sort(key=lambda x: x[0])
    
        # Write config entries
        for idx, (label, abs_path) in enumerate(entries, start=1):
            config.set('Textures', f"texture_{idx}_path", abs_path)
            config.set('Textures', f"texture_{idx}_label", label)
            config.set('Textures', f"texture_{idx}_compression", "1")  # hard-coded compressed
    
        config_file_path = os.path.join(root_folder, 'generated_config.ini')
        with open(config_file_path, 'w', encoding='utf-8') as config_file:
            config.write(config_file)
    
        messagebox.showinfo(
            "Success!",
            f"Config file generated successfully at:\n{config_file_path}"
        )


if __name__ == "__main__":
    app = AssetPackageGenerator()
    app.mainloop()
