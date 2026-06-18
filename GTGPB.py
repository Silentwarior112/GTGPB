import os
import glob
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import struct
import configparser
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import re

# Resolve tool paths relative to this script's directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

GTPS2MODELTOOL_EXE = os.path.normpath(os.path.join(SCRIPT_DIR, "GTPS2ModelTool", "GTPS2ModelTool.exe"))

TEXTURESETCONVERTER_EXE = os.path.normpath(os.path.join(SCRIPT_DIR, "TXS3Converter", "TextureSetConverter.exe"))

zip_exe = os.path.normpath(os.path.join(SCRIPT_DIR, "PolyphonyPS2Zip", "PolyphonyPS2Zip.exe"))
    
COMP_MAGIC = b"\xC5\xEE\xF7\xFF"

# TXS3 (PS3) texture-set magics - big-endian "TXS3" and little-endian "3SXT"
TXS3_MAGICS = (b"TXS3", b"3SXT")

# Tex1 (PS2) texture magic
TEX1_MAGIC = b"Tex1"

# On-disk extension for TXS3 texture data: input to `convert-png`, output of `convert-img`.
TXS3_EXT = ".dds"


# Texture container magics each GPB family knows how to decode into an editable image. A GPB can
# hold ANY file, so an entry whose content magic isn't one of these is a non-texture and is dumped
# verbatim (raw passthrough) under its exact label name, then packed back as-is on rebuild.
TEX_MAGICS_PS2  = (TEX1_MAGIC,)                          # gpb0 / gpb1 (Tex1 only)
TEX_MAGICS_GPB2 = (TEX1_MAGIC, b"TXS3", b"3SXT")         # gpb2 (Tex1 + PS3 TXS3)
TEX_MAGICS_GPB3 = (b"TXS3", b"3SXT", b"Tpp1")            # gpb3 (TXS3 / 3SXT / Tpp1)


def _is_txs3_flagged(path):
    """True if a filename carries a ".CONTAINER.FORMAT" flag (TXS3 / 3SXT / Tpp1) before .png/.dds."""
    parts = os.path.splitext(os.path.basename(path))[0].split('.')
    return len(parts) >= 3 and parts[-2] in ("TXS3", "3SXT", "Tpp1")


def _peek_magic(blob, tmp_dir):
    """Content magic (first 4 bytes) of a GPB entry blob, decompressing a ps2zip wrapper first."""
    if blob[:4] != COMP_MAGIC:
        return blob[:4]
    tmp = os.path.join(tmp_dir, "__gpb_peek.tmp")
    dec = tmp + "_decompressed"
    try:
        with open(tmp, "wb") as fh:
            fh.write(blob)
        subprocess.run([zip_exe, tmp], capture_output=True, text=True, check=True)
        with open(dec, "rb") as fh:
            return fh.read(4)
    except Exception:
        return blob[:4]
    finally:
        for _p in (tmp, dec):
            try:
                if os.path.isfile(_p):
                    os.remove(_p)
            except Exception:
                pass


def _build_kind(path, has_tex1=True):
    """Classify a config ``texture_N_path`` for the rebuild:

    'multi'   -> a ``<name>.txs`` folder (multi-texture TXS3 set)
    'flagged' -> a ``name.CONTAINER.FORMAT.ext`` TXS3/3SXT/Tpp1 texture
    'tex1'    -> a plain ``.png`` Tex1 source (PS2; only when ``has_tex1``)
    'raw'     -> anything else: a non-texture file, packed into the GPB verbatim
    """
    bare = path.rstrip('/\\')
    if bare.lower().endswith('.txs'):
        return 'multi'
    if _is_txs3_flagged(path):
        return 'flagged'
    if has_tex1 and path.lower().endswith('.png'):
        return 'tex1'
    return 'raw'


def _texdata_path(src_path, has_tex1=True):
    """On-disk texture-data file a config source converts to (what the rebuild actually packs).

    Multi-texture set folder (.txs) -> the built ``.dds`` set. TXS3-flagged PNGs -> ``.dds`` (TXS3
    binary); TXS3-flagged ``.dds`` inputs -> ``.txs3`` (convert-img would otherwise overwrite the
    ``.dds`` source it reads). Plain ``.png`` Tex1 -> ``.img``. Raw passthrough files -> themselves.
    """
    kind = _build_kind(src_path, has_tex1=has_tex1)
    if kind == 'multi':
        return os.path.splitext(src_path.rstrip('/\\'))[0] + TXS3_EXT
    if kind == 'flagged':
        built_ext = ".txs3" if src_path.lower().endswith(".dds") else TXS3_EXT
        return os.path.splitext(src_path)[0] + built_ext
    if kind == 'tex1':
        return os.path.splitext(src_path)[0] + ".img"
    return src_path  # raw passthrough: pack verbatim

def byte_count_to_bytes(byte_count):
    return byte_count.to_bytes(4, byteorder='big')  # Assuming a 4-byte integer

class AssetPackageGenerator(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("GTGPB")
        
        # Load the last used directory from the configuration file
        self.last_used_directory = self.load_last_directory()
        
        self.texture_names = []
        self.custom_filenames = {}  # Dictionary to hold texture labels
        self.destination_dir = None  # Destination directory for extraction

        # ── UI ──────────────────────────────────────────────────────────────
        # General actions at the top, then one "Generate" button per GPB variant,
        # each under a section header naming the game(s) that use that format.
        container = tk.Frame(self, padx=16, pady=10)
        container.pack(fill=tk.BOTH, expand=True)

        tk.Button(container, text="Extract gpb to folder",
                  command=self.on_extract_button_click).pack(fill=tk.X, pady=(4, 4))
        tk.Button(container, text="Update GPB file entries",
                  command=self.ask_root_folder_and_generate).pack(fill=tk.X, pady=(0, 6))

        def section(title):
            ttk.Separator(container, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(8, 2))
            tk.Label(container, text=title, font=("Segoe UI", 9, "bold"),
                     fg="#444").pack(anchor=tk.W)

        def gen_button(text, command):
            tk.Button(container, text=text, command=command).pack(fill=tk.X, pady=2)

        section("GPB0 — GT4P Japan")
        gen_button("Generate gpb0 from .ini", self.generate_gpb0)

        section("GPB1 — GT4P")
        gen_button("Generate gpb1 from .ini", self.generate_gpb1)

        section("GPB2 — GT4 & TT")
        gen_button("Generate gpb2 from .ini", self.generate_gpb2)

        section("PS3 GPB2 — GTHD & GT5P")
        gen_button("Generate PS3 gpb2 from .ini", lambda: self.generate_gpb2(ps3=True))

        section("GPB3 — GTPSP, GT5, GT6")
        gen_button("Generate gpb3 from .ini", self.generate_gpb3)

        # Size to fit the contents (with a comfortable minimum width), then centre on screen.
        self.update_idletasks()
        w = max(self.winfo_reqwidth(), 320)
        h = self.winfo_reqheight()
        self.geometry(f"{w}x{h}")
        self.minsize(w, h)
        self.center_window(self)

    def center_window(self, win, over=None):
        """Centre ``win`` over the ``over`` window if it's mapped, else on the screen.

        Centring over the parent keeps modal dialogs on top of the app no matter where (or on
        which monitor) the user has dragged it; the result is clamped to stay fully on-screen.
        """
        win.update_idletasks()
        w = win.winfo_width() if win.winfo_width() > 1 else win.winfo_reqwidth()
        h = win.winfo_height() if win.winfo_height() > 1 else win.winfo_reqheight()
        # Centre over the parent's *frame* geometry (same coordinate system geometry() writes), so
        # there's no window-decoration offset; fall back to the screen when the parent isn't placed.
        x = y = None
        if over is not None and over.winfo_ismapped():
            mtch = re.match(r"(\d+)x(\d+)\+(-?\d+)\+(-?\d+)", over.geometry())
            if mtch:
                mw, mh, mx, my = map(int, mtch.groups())
                x = mx + (mw - w) // 2
                y = my + (mh - h) // 2
        if x is None:
            x = (win.winfo_screenwidth() - w) // 2
            y = (win.winfo_screenheight() - h) // 2
        # Keep the window fully on-screen.
        x = max(0, min(x, win.winfo_screenwidth() - w))
        y = max(0, min(y, win.winfo_screenheight() - h))
        win.geometry(f"+{x}+{y}")

    def show_progress_dialog(self, text="Working...\n\nPlease wait."):
        """A centred modal 'working' dialog with an animated progress bar."""
        dlg = tk.Toplevel(self)
        dlg.withdraw()  # stay hidden until centred so it never flashes at the default corner
        dlg.title("Working")
        dlg.resizable(False, False)
        dlg.transient(self)
        tk.Label(dlg, text=text, padx=30).pack(pady=(20, 8))
        bar = ttk.Progressbar(dlg, mode="indeterminate", length=260)
        bar.pack(padx=30, pady=(0, 20))
        self.center_window(dlg, over=self)  # position while hidden
        dlg.deiconify()                      # now reveal it, already centred
        dlg.grab_set()
        dlg.lift()
        bar.start(12)
        return dlg

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
    
        wait_dialog = self.show_progress_dialog("Converting textures...\n\nPlease wait.")
    
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
                    messagebox.showinfo("Success!", f"GPB generation completed. {num_textures} files packed.")
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
    
        wait_dialog = self.show_progress_dialog("Converting textures...\n\nPlease wait.")
    
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
                    messagebox.showinfo("Success!", f"GPB generation completed. {num_textures} files packed.")
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

    # ps3 variable is set at button press. The PS3 GPB2 button passes ps3=True.
    def generate_gpb2(self, ps3=False):
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
        wait_dialog = self.show_progress_dialog("Converting textures...\n\nPlease wait.")
    
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
                # Parse [Textures] entries in numeric order (drives conversion + packing)
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
                # PRE-STEP A: convert each config entry to its on-disk texture data. Routing is by
                # kind: flagged/.txs -> TextureSetConverter (TXS3), plain .png -> GTPS2ModelTool
                # (Tex1), raw passthrough files are packed verbatim (no conversion).
                # ---------------------------------------------------------
                def run_make_tex_set(src_path: str):
                    kind = _build_kind(src_path)
                    if kind == 'raw':
                        if not os.path.isfile(src_path):
                            raise RuntimeError(f"Raw file not found:\n{src_path}")
                        return  # packed verbatim, nothing to build
                    if kind in ('flagged', 'multi'):
                        subprocess.run(
                            [TEXTURESETCONVERTER_EXE, "convert-img", "-i", src_path],
                            capture_output=True, text=True, check=True
                        )
                    else:  # tex1
                        subprocess.run(
                            [GTPS2MODELTOOL_EXE, "make-tex-set", "-i", src_path],
                            capture_output=True, text=True, check=True
                        )
                    out_path = _texdata_path(src_path)
                    if not os.path.isfile(out_path):
                        raise RuntimeError(f"Texture build did not produce expected output:\n{out_path}")
                    record_delete(img_deletions, out_path)

                max_workers = min(8, (os.cpu_count() or 4))
                errors = []
                with ThreadPoolExecutor(max_workers=max_workers) as ex:
                    futures = {ex.submit(run_make_tex_set, p): p for p in texture_paths}
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
                        print("Texture conversion errors:")
                        for p, err in errors:
                            print(f"- {p}\n  {err}\n")
                        messagebox.showerror(
                            "Conversion error",
                            f"Texture conversion failed for {len(errors)} file(s).\n"
                            f"See console for details.\n\nAborting GPB generation."
                        )
                    self.after(0, on_fail)
                    return

                # Each config path maps to its built texture data (raw passthrough -> itself).
                texture_data = [_texdata_path(p) for p in texture_paths]

                # ---------------------------------------------------------
                # PRE-STEP B: PS2ZIP compression
                # ---------------------------------------------------------
                to_compress = [d for d, c in zip(texture_data, texture_comp) if c == 1]
    
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
                # PACK GPB2
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
    
                    # PS3 gpb2 packs texture data on a 128-byte grid (PS2 uses 16) and records
                    # the *padded* span (distance to the next texture, a multiple of 128) in the
                    # metadata byte-count field at +8. PS2 leaves +8 zero. Matching the original PS3
                    # layout matters: a zero byte-count / off-grid offset crashes the game.
                    
                    # ps3 variable is set at button press. The PS3 GPB2 button passes ps3=True.
                    data_align = 128 if ps3 else 16
                    while f.tell() % data_align != 0:
                        f.write(b'\x5E')

                    texture_offsets = []
                    byte_counts = []
                    for path, comp_val in zip(texture_data, texture_comp):
                        pack_path = (path + ".ps2zip") if comp_val == 1 else path
                        with open(pack_path, 'rb') as img_file:
                            img_data = img_file.read()

                        texture_offset = f.tell()
                        f.write(img_data)

                        while f.tell() % data_align != 0:
                            f.write(b'\x5E')

                        texture_offsets.append(texture_offset)
                        byte_counts.append(f.tell() - texture_offset)  # padded span

                    for i in range(num_textures):
                        f.seek(metadata_start + i * 16)
                        f.write(struct.pack('<I', filename_offsets[i]))
                        f.seek(metadata_start + 4 + i * 16)
                        f.write(struct.pack('<I', texture_offsets[i]))
                        f.seek(metadata_start + 8 + i * 16)
                        if ps3:
                            f.write(struct.pack('<I', byte_counts[i]))  # byte-count @+8
                            f.write(b'\x00' * 4)                        # field @+12 = 0
                        else:
                            f.write(b'\x00' * 8)
    
                # Cleanup
                cleanup_recorded()
    
                def on_success():
                    wait_dialog.destroy()
                    messagebox.showinfo("Success!", f"GPB generation completed. {num_textures} files packed.")
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

        # PRE-STEP: convert each texture PNG to its on-disk texture data. The PNG filename carries
        # a ".CONTAINER.FORMAT" flag (e.g. texture_name.3SXT.IDTEX8.png), so the converter reproduces the
        # exact original container + pixel format with no -f/--pf needed
        wait_dialog = self.show_progress_dialog("Converting textures...\n\nPlease wait.")
        gpb3_generated = []
        texture_dds = []
        conv_error = None
        for _png in texture_paths:
            wait_dialog.update()
            # Non-texture entries (no flag, not a .txs set) are packed verbatim - GPBs hold any file.
            if _build_kind(_png, has_tex1=False) == 'raw':
                if not os.path.isfile(_png):
                    conv_error = f"Raw file not found:\n{_png}"
                    break
                texture_dds.append(_png)
                continue
            try:
                subprocess.run([TEXTURESETCONVERTER_EXE, "convert-img", "-i", _png],
                               capture_output=True, text=True, check=True)
            except subprocess.CalledProcessError as e:
                err = (e.stderr or e.stdout or "").strip()
                conv_error = f"Texture conversion failed for:\n{_png}\n\n{err}"
                break
            _out = _texdata_path(_png, has_tex1=False)
            if not os.path.isfile(_out):
                conv_error = f"Converter did not produce expected output:\n{_out}"
                break
            gpb3_generated.append(_out)
            texture_dds.append(_out)

        if conv_error:
            wait_dialog.destroy()
            messagebox.showerror("Conversion error", conv_error)
            return

        with open(output_gpb_path, "wb") as f:
            # Step 1: Magic
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
    
            # First texture starts at align(nameEnd, 128) (PD's rule across all gpb3; 64-align here
            # put it at e.g. 0x1c0 instead of 0x200), with a 0x100 floor. Subsequent textures are
            # 128-padded below, so this keeps the whole texture region on a 128-byte grid.
            current_pos = f.tell()
            next_factor_of_128 = (current_pos + 127) // 128 * 128
            padding_needed = max(0x00000100 - current_pos, next_factor_of_128 - current_pos)
            while padding_needed > 0:
                bytes_to_write = min(padding_needed, 16)  # Write up to 16 bytes at a time
                f.write(b'\x5E' * bytes_to_write)
                padding_needed -= bytes_to_write
    
            # Step 6: Insert the files into the gpb file
            texture_offsets = []
            byte_counts = []

            for path in texture_dds:
                with open(path, 'rb') as img_file:
                    img_data = img_file.read()
            
                    # Write file data and get its offset
                    texture_offset = f.tell()  # offset
                    f.write(img_data)  # read the .img file
                    
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
                    
            # Final padding to the next factor of 64
            current_pos = f.tell()
            next_factor_of_64 = (current_pos + 63) // 64 * 64
            padding_needed = next_factor_of_64 - current_pos
            
            # Re-open the file to add padding
            with open(output_gpb_path, "ab") as f:
                f.write(b'\x5E' * padding_needed)
            
            # Cleanup texture files generated from PNGs in the pre-step
            for _p in gpb3_generated:
                try:
                    if os.path.isfile(_p):
                        os.remove(_p)
                except Exception as e:
                    print(f"[Cleanup] Failed to delete: {_p}\n  {e}")

            wait_dialog.destroy()
            messagebox.showinfo("Success!", f"GPB generation completed. {num_textures} files packed.")

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
            entry_info = []           # 'tex' or 'raw' per entry, in GPB order
            tex_scratch = []          # Tex1 .img scratch files to dump -> PNG

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

                # A GPB holds any file. Tex1 (PS2) textures convert to PNG; anything else is dumped
                # verbatim under its exact label name (raw passthrough), packed back as-is on rebuild.
                magic = _peek_magic(img_data, self.destination_dir)
                if magic in TEX_MAGICS_PS2:
                    scratch = os.path.join(dir_full_path, os.path.splitext(base)[0] + ".img")
                    with open(scratch, 'wb') as out_file:
                        out_file.write(img_data)
                    compression_flags.append(1 if img_data[:4] == COMP_MAGIC else 0)
                    tex_scratch.append(scratch)
                    entry_info.append('tex')
                    print(f"[Texture] '{base}'")
                else:
                    raw_path = os.path.join(dir_full_path, base)
                    with open(raw_path, 'wb') as out_file:
                        out_file.write(img_data)
                    compression_flags.append(0)
                    entry_info.append('raw')
                    print(f"[File] '{base}'")

            # Step 4: Write config (path = built .img for Tex1, the verbatim file for raw; label=original)
            config = configparser.ConfigParser()
            config.add_section('Textures')

            for idx, label in enumerate(extracted_labels, start=1):
                label_norm = label.replace("\\", "/")

                if entry_info[idx-1] == 'raw':
                    path_name = label                                  # verbatim file = label name
                else:
                    path_name = os.path.splitext(label)[0] + ".img"    # built Tex1 binary

                full_path = os.path.join(self.destination_dir, path_name).replace("\\", "/")

                config.set('Textures', f'texture_{idx}_path', full_path)
                config.set('Textures', f'texture_{idx}_label', label_norm)
                config.set('Textures', f'texture_{idx}_compression', str(compression_flags[idx-1]))

            config_file_path = os.path.join(self.destination_dir, 'gpb0_config.ini')
            with open(config_file_path, 'w', encoding='utf-8') as config_file:
                config.write(config_file)

        # Step 5: Convert the Tex1 .img scratch files -> .png (raw passthrough entries are final)
        wait_dialog = self.show_progress_dialog("Converting textures to PNG...\n\nPlease wait.")

        max_workers = min(8, (os.cpu_count() or 4))
        errors = []
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(run_dump, p): p for p in tex_scratch}
            for fut in as_completed(futures):
                wait_dialog.update()  # animate the progress bar as each texture finishes
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
            entry_info = []           # 'tex' or 'raw' per entry, in GPB order
            tex_scratch = []          # Tex1 .img scratch files to dump -> PNG

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

                next_texture_offset = int.from_bytes(metadata[(i*8)+12:(i*8)+16], byteorder='little')
                if next_texture_offset == 0:
                    last_byte_address = os.path.getsize(gpb_path)
                else:
                    last_byte_address = next_texture_offset  # do NOT trim 0x5E

                f.seek(texture_offset)
                img_data = f.read(last_byte_address - texture_offset)

                # A GPB holds any file. Tex1 (PS2) textures convert to PNG; anything else is dumped
                # verbatim under its exact label name (raw passthrough), packed back as-is on rebuild.
                magic = _peek_magic(img_data, self.destination_dir)
                if magic in TEX_MAGICS_PS2:
                    scratch = os.path.join(dir_full_path, os.path.splitext(base)[0] + ".img")
                    with open(scratch, 'wb') as out_file:
                        out_file.write(img_data)
                    compression_flags.append(1 if img_data[:4] == COMP_MAGIC else 0)
                    tex_scratch.append(scratch)
                    entry_info.append('tex')
                    print(f"[Texture] '{base}'")
                else:
                    raw_path = os.path.join(dir_full_path, base)
                    with open(raw_path, 'wb') as out_file:
                        out_file.write(img_data)
                    compression_flags.append(0)
                    entry_info.append('raw')
                    print(f"[File] '{base}'")

            config = configparser.ConfigParser()
            config.add_section('Textures')

            for idx, label in enumerate(extracted_labels, start=1):
                label_norm = label.replace("\\", "/")

                if entry_info[idx-1] == 'raw':
                    path_name = label                                  # verbatim file = label name
                else:
                    path_name = os.path.splitext(label)[0] + ".img"    # built Tex1 binary

                full_path = os.path.join(self.destination_dir, path_name).replace("\\", "/")

                config.set('Textures', f'texture_{idx}_path', full_path)
                config.set('Textures', f'texture_{idx}_label', label_norm)
                config.set('Textures', f'texture_{idx}_compression', str(compression_flags[idx-1]))

            config_file_path = os.path.join(self.destination_dir, 'gpb1_config.ini')
            with open(config_file_path, 'w', encoding='utf-8') as config_file:
                config.write(config_file)

        wait_dialog = self.show_progress_dialog("Converting textures to PNG...\n\nPlease wait.")

        max_workers = min(8, (os.cpu_count() or 4))
        errors = []
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(run_dump, p): p for p in tex_scratch}
            for fut in as_completed(futures):
                wait_dialog.update()  # animate the progress bar as each texture finishes
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
    
        def safe_rel_path(label):
            # Map a GPB label to a path that stays INSIDE destination_dir.
            # GT PS3 labels often start with ../../../ which would otherwise escape the
            # output folder (so os.walk never finds the files to convert). Strip drive
            # letters, leading slashes, and any '.'/'..' components.
            s = label.replace("\\", "/")
            parts = [p for p in s.split("/") if p not in ("", ".", "..") and ":" not in p]
            return os.path.join(*parts) if parts else "_unnamed_"
    
        def peek_format_magic(blob):
            # Return the 4-byte texture magic; decompress first if ps2zip-compressed.
            if blob[:4] != COMP_MAGIC:
                return blob[:4]
            tmp_path = os.path.join(self.destination_dir, "__gpb_peek.tmp")
            dec_path = tmp_path + "_decompressed"
            try:
                with open(tmp_path, "wb") as fh:
                    fh.write(blob)
                subprocess.run([zip_exe, tmp_path], capture_output=True, text=True, check=True)
                with open(dec_path, "rb") as fh:
                    return fh.read(4)
            finally:
                for _p in (tmp_path, dec_path):
                    try:
                        if os.path.isfile(_p):
                            os.remove(_p)
                    except Exception:
                        pass
    
        def run_dump(img_path: str, as_dds: bool = False):
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

            # 2) Convert to PNG (route by texture format: TXS3 magic or .dds extension)
            if magic == COMP_MAGIC:
                with open(dump_input, "rb") as _fh:
                    inner_magic = _fh.read(4)
            else:
                inner_magic = magic

            if inner_magic in TXS3_MAGICS or img_path.lower().endswith(TXS3_EXT):
                # TXS3 (PS3) -> PNG, or DDS when the label was a .dds (lossless DXT round-trip).
                cmd = [TEXTURESETCONVERTER_EXE, "convert-png", "-i", dump_input, "-f", "PS3"]
                if as_dds:
                    cmd.append("--dds")
                subprocess.run(cmd, capture_output=True, text=True, check=True)
            else:
                # Tex1 (.img) -> PNG via GTPS2ModelTool
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
            compression_flags = []  # 0/1 aligned to extracted_filenames order
            dump_jobs = []          # (scratch path, as_dds) per texture entry to convert
            entry_info = []         # ('tex', None) or ('raw', raw_path) per entry, in GPB order

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
    
                # Create output directories (sanitized so files stay inside destination_dir)
                rel_path = safe_rel_path(extracted_filename)
                dir_full_path = os.path.join(self.destination_dir, os.path.dirname(rel_path))
                os.makedirs(dir_full_path, exist_ok=True)
    
                name = os.path.basename(rel_path)
    
                # (Texture format is detected by magic after the blob is read, below.)
    
                # Determine byte range for data (keeping your existing logic)
                # NOTE: Your original next_texture_offset indexing looks suspicious (i*16+20),
                # but I'm not changing it here since it's outside this performance refactor.
                next_texture_offset = int.from_bytes(metadata[i*16+20:i*16+24], byteorder='little')
    
                if next_texture_offset == 0:
                    last_byte_address = os.path.getsize(gpb_path)
                else:
                    last_byte_address = next_texture_offset
    
                # Extract and write bytes
                f.seek(texture_offset)
                img_data = f.read(last_byte_address - texture_offset)

                # Detect the entry's content. A GPB holds any file: TXS3/Tex1 textures convert to an
                # editable image; anything else is dumped verbatim under its exact label name.
                tex_magic = peek_format_magic(img_data)
                if tex_magic in TXS3_MAGICS:
                    # TXS3 (PS3) -> scratch .dds, converted to a flagged image whose extension
                    # matches the label (".dds" label -> real DDS, else PNG).
                    scratch = os.path.join(dir_full_path, os.path.splitext(name)[0] + TXS3_EXT)
                    with open(scratch, 'wb') as out_file:
                        out_file.write(img_data)
                    compression_flags.append(1 if img_data[:4] == COMP_MAGIC else 0)
                    dump_jobs.append((scratch, extracted_filename.lower().endswith(".dds")))
                    entry_info.append(('tex', None))
                elif tex_magic == TEX1_MAGIC:
                    # Tex1 (PS2) -> scratch .img, converted to PNG via GTPS2ModelTool.
                    scratch = os.path.join(dir_full_path, os.path.splitext(name)[0] + ".img")
                    with open(scratch, 'wb') as out_file:
                        out_file.write(img_data)
                    compression_flags.append(1 if img_data[:4] == COMP_MAGIC else 0)
                    dump_jobs.append((scratch, False))
                    entry_info.append(('tex', None))
                    print(f"[Texture] '{name}'")
                else:
                    # Non-texture entry: dump verbatim, packed back as-is (compression preserved
                    # inside the bytes, so don't re-compress -> flag 0).
                    raw_path = os.path.join(dir_full_path, name)
                    with open(raw_path, 'wb') as out_file:
                        out_file.write(img_data)
                    compression_flags.append(0)
                    entry_info.append(('raw', raw_path))
                    print(f"[File] '{name}'")

            # Config is written AFTER the dump (below) so it can point at the format-flagged images
            # the dumper produces (TXS3 textures gain a ".CONTAINER.FORMAT" tag).

        # 3) DUMP every texture scratch file (raw passthrough entries are already final).
        wait_dialog = self.show_progress_dialog("Converting textures...\n\nPlease wait.")

        # 4) MULTITHREADED DUMP + DELETE
        max_workers = min(8, (os.cpu_count() or 4))

        errors = []
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(run_dump, scratch, as_dds): scratch for scratch, as_dds in dump_jobs}
            for fut in as_completed(futures):
                wait_dialog.update()  # animate the progress bar as each texture finishes
                p = futures[fut]
                try:
                    fut.result()
                except subprocess.CalledProcessError as e:
                    err = (e.stderr or e.stdout or "").strip()
                    errors.append((p, err))
                except Exception as e:
                    errors.append((p, str(e)))

        # 5) WRITE CONFIG: label = original GPB name; path = the editable produced above (a flagged
        #    image for TXS3, base.png for Tex1, a .txs/ folder for multi-texture) or the verbatim
        #    file for non-texture entries. GPB order preserved.
        config = configparser.ConfigParser()
        config.add_section('Textures')
        for idx, filename in enumerate(extracted_filenames, start=1):
            kind, raw_path = entry_info[idx-1]
            if kind == 'raw':
                tex_path = raw_path
            else:
                base = os.path.join(self.destination_dir, os.path.splitext(safe_rel_path(filename))[0])
                txs_folder = base + ".txs"
                if os.path.isdir(txs_folder):
                    tex_path = txs_folder
                else:
                    matches = glob.glob(glob.escape(base) + ".*.png") + glob.glob(glob.escape(base) + ".*.dds")
                    if not matches and os.path.exists(base + ".png"):
                        matches = [base + ".png"]
                    tex_path = matches[0] if matches else base + ".png"
            config.set('Textures', f'texture_{idx}_path', tex_path.replace("\\", "/"))
            config.set('Textures', f'texture_{idx}_label', filename.replace("\\", "/"))
            config.set('Textures', f'texture_{idx}_compression', str(compression_flags[idx-1]))
        config_file_path = os.path.join(self.destination_dir, 'gpb2_config.ini')
        with open(config_file_path, 'w', encoding='utf-8') as config_file:
            config.write(config_file)

        # 6) DONE
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

        def safe_rel_path(label):
            # Keep files INSIDE destination_dir: strip drive letters, leading
            # slashes, and any '.'/'..' components (GT PS3 labels use ../../../).
            s = label.replace("\\", "/")
            parts = [p for p in s.split("/") if p not in ("", ".", "..") and ":" not in p]
            return os.path.join(*parts) if parts else "_unnamed_"

        def run_dump(tex_path: str, as_dds: bool = False):
            # GPB3 textures are TXS3. Platform comes from the magic byte order:
            # "TXS3" (big-endian) = PS3, "3SXT" (little-endian) = PSP. Decompress
            # first if ps2zip-compressed, then convert TXS3 -> PNG (or -> DDS when the
            # original label was a .dds, so PS3 DXT textures round-trip losslessly).
            try:
                with open(tex_path, "rb") as fh:
                    magic = fh.read(4)
            except Exception as e:
                raise RuntimeError(f"Failed reading magic for: {tex_path}\n{e}")

            convert_input = tex_path
            decompressed_path = None
            if magic == COMP_MAGIC:
                subprocess.run([zip_exe, tex_path], capture_output=True, text=True, check=True)
                decompressed_path = tex_path + "_decompressed"
                convert_input = decompressed_path
                if not os.path.isfile(decompressed_path):
                    raise RuntimeError(f"PolyphonyPS2Zip did not produce expected output:\n{decompressed_path}")
                with open(decompressed_path, "rb") as fh:
                    magic = fh.read(4)

            fmt = "PSP" if magic == b"3SXT" else "PS3"
            # PSP (3SXT/Tpp1) has no DDS equivalent, so --dds is PS3-only (the converter also
            # ignores it for non-Cell textures, but skip it here so PSP dumps stay PNG).
            cmd = [TEXTURESETCONVERTER_EXE, "convert-png", "-i", convert_input, "-f", fmt]
            if as_dds and fmt == "PS3":
                cmd.append("--dds")
            subprocess.run(cmd, capture_output=True, text=True, check=True)

            try:
                if os.path.isfile(tex_path):
                    os.remove(tex_path)
            except Exception as e:
                print(f"[Cleanup] Failed to delete original texture: {tex_path}\n  {e}")
            if decompressed_path:
                try:
                    if os.path.isfile(decompressed_path):
                        os.remove(decompressed_path)
                except Exception as e:
                    print(f"[Cleanup] Failed to delete decompressed: {decompressed_path}\n  {e}")

        with open(gpb_path, 'rb') as f:
            # Texture count (PS3 gpb3 is big-endian)
            f.seek(0x0000000C)
            num_textures = struct.unpack('>I', f.read(4))[0]
            print(f"Number of textures: {num_textures}")

            # Metadata: 16 bytes per texture starting at 0x20
            metadata_start = 0x00000020
            metadata_end = metadata_start + (16 * int(num_textures))
            f.seek(metadata_start)
            metadata = f.read(metadata_end - metadata_start)

            extracted_filenames = []
            tex_dumps = []    # (scratch TXS3-binary path, dump-as-dds?) per texture entry
            entry_info = []   # ('tex', None) or ('raw', raw_path) per entry, in GPB order

            for i in range(num_textures):
                filename_offset = int.from_bytes(metadata[i*16:i*16+4], byteorder='big')
                texture_offset  = int.from_bytes(metadata[i*16+4:i*16+8], byteorder='big')

                # Read label string
                f.seek(filename_offset)
                filename_bytes = bytearray()
                while True:
                    byte = f.read(1)
                    if byte == b'\x00':
                        break
                    filename_bytes.append(byte[0])
                extracted_filename = filename_bytes.decode('utf-8')
                extracted_filenames.append(extracted_filename)

                # Output dir (sanitized so ../../../ labels stay inside destination_dir)
                rel_path = safe_rel_path(extracted_filename)
                dir_full_path = os.path.join(self.destination_dir, os.path.dirname(rel_path))
                os.makedirs(dir_full_path, exist_ok=True)
                base = os.path.basename(rel_path)

                # Byte range for texture data (trim trailing 0x5E padding before next texture)
                next_texture_offset = int.from_bytes(metadata[i*16+20:i*16+24], byteorder='big')
                if next_texture_offset == 0:
                    last_byte_address = os.path.getsize(gpb_path)
                else:
                    f.seek(next_texture_offset - 1)
                    while f.read(1) == b'\x5E':
                        next_texture_offset -= 1
                        f.seek(next_texture_offset - 1)
                    last_byte_address = next_texture_offset

                f.seek(texture_offset)
                img_data = f.read(last_byte_address - texture_offset)

                # A GPB can hold any file. Convert only recognized texture containers; dump anything
                # else verbatim under its exact label name (raw passthrough).
                magic = _peek_magic(img_data, self.destination_dir)
                if magic in TEX_MAGICS_GPB3:
                    # Scratch TXS3 binary -> a flagged editable image whose extension matches the
                    # label (".dds" label -> real DDS for lossless DXT, anything else -> PNG).
                    scratch = os.path.join(dir_full_path, os.path.splitext(base)[0] + TXS3_EXT)
                    with open(scratch, 'wb') as out_file:
                        out_file.write(img_data)
                    as_dds = extracted_filename.lower().endswith(".dds")
                    tex_dumps.append((scratch, as_dds))
                    entry_info.append(('tex', None))
                    print(f"Texture# {i+1}: '{extracted_filename}' -> {scratch}")
                else:
                    raw_path = os.path.join(dir_full_path, base)
                    with open(raw_path, 'wb') as out_file:
                        out_file.write(img_data)
                    entry_info.append(('raw', raw_path))
                    print(f"File#    {i+1}: '{extracted_filename}' -> {raw_path} (raw passthrough)")

            # Convert every extracted TXS3/Tpp1 texture to a (format-flagged) PNG/DDS first. The
            # converter appends the container + pixel format to the filename, e.g.
            # "cobra_67.3SXT.IDTEX8.png" / "custom_22.TXS3.DXT1.dds", so the rebuild reproduces
            # them exactly.
            wait_dialog = self.show_progress_dialog("Converting textures...\n\nPlease wait.")
            try:
                for t, as_dds in tex_dumps:
                    wait_dialog.update()  # animate the progress bar between textures
                    run_dump(t, as_dds)
            finally:
                wait_dialog.destroy()

            # Write config: label = original GPB name; path = the flagged PNG/DDS produced above.
            # The filename flag carries container + pixel format, so no [GPB] platform is needed.
            config = configparser.ConfigParser()
            config.add_section('Textures')
            for i, filename in enumerate(extracted_filenames):
                kind, raw_path = entry_info[i]
                if kind == 'raw':
                    # Non-texture entry: the verbatim file IS the build input (packed back as-is).
                    tex_path = raw_path
                else:
                    base = os.path.join(self.destination_dir, os.path.splitext(safe_rel_path(filename))[0])
                    # A multi-texture TXS3 (e.g. env2.txs) dumps into a "<base>.txs/" FOLDER of
                    # sub-texture images; point the config at the folder (convert-img rebuilds it).
                    txs_folder = base + ".txs"
                    if os.path.isdir(txs_folder):
                        tex_path = txs_folder
                    else:
                        # The flagged image keeps the label's extension (.dds dump or .png dump).
                        matches = glob.glob(glob.escape(base) + ".*.png") + glob.glob(glob.escape(base) + ".*.dds")
                        tex_path = matches[0] if matches else base + ".png"
                config.set('Textures', f'texture_{i+1}_path', tex_path.replace("\\", "/"))
                config.set('Textures', f'texture_{i+1}_label', filename)
            config_file_path = os.path.join(self.destination_dir, 'gpb3_config.ini')
            with open(config_file_path, 'w', encoding='utf-8') as config_file:
                config.write(config_file)

            print(f"GPB extraction completed. {num_textures} textures extracted.")
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
    
        # Collect files
        for root, _, files in os.walk(root_folder):
            for file_name in files:
                # Don't include the config or any shortcuts
                if file_name.lower().endswith('.ini') or file_name.lower().endswith('.lnk'):
                    continue # Skip
    
                rel_dir = os.path.relpath(root, root_folder)

                # Work out the GPB label and the on-disk data path for this file.
                parts = file_name.split('.')
                flagged = len(parts) >= 4 and parts[-3] in ("TXS3", "3SXT", "Tpp1")
                if flagged:
                    # ".CONTAINER.FORMAT" flagged texture (e.g. custom_22.TXS3.DXT1.dds): the label
                    # drops the flag but KEEPS the real extension the texture had in the GPB
                    # (custom_22.dds / custom_22.png). The build reads the flagged file directly.
                    label_name = ".".join(parts[:-3]) + "." + parts[-1]
                    path_name = file_name
                elif file_name.lower().endswith('.png'):
                    # Tex1 (PS2): label keeps .png, the packed data is the .img beside it.
                    label_name = file_name
                    path_name = os.path.splitext(file_name)[0] + ".img"
                else:
                    label_name = file_name
                    path_name = file_name

                label = (label_name if rel_dir == "." else os.path.join(rel_dir, label_name)).replace("\\", "/")
                abs_path = os.path.abspath(os.path.join(root, path_name)).replace("\\", "/")

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
