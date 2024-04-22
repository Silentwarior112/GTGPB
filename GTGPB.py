import os
import tkinter as tk
from tkinter import filedialog, messagebox
import struct
import configparser

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
        self.generate_button = tk.Button(self, text="Update file locations in .ini", command=self.ask_root_folder_and_update)
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
                    if os.path.getsize(full_path) > 524288:  # 512 KB in bytes
                        # Display warning message
                        user_choice = messagebox.askyesno(
                            "Incompatible file detected!",
                            f"The file `{full_path}` is larger than 512 kilobytes. The maximum filesize a texture can be is 512kb for PS2-era GT games.\nYou have likely selected the wrong root folder, and should abort this process and try again. Are you sure you want to continue?"
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
            # Step 1: Write the header
            f.write(b'gpb0')
    
            # Step 2: Write the number of textures
            f.write(struct.pack('<I', num_textures))
    
            # Step 3: Write reserved space for texture metadata
            metadata_start = f.tell()
            f.write(b'\x00' * (num_textures * 8))
    
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
    
            # Write 5E and repeat until the next address is a factor of 16 in decimal / 10 in hex
            while f.tell() % 16 != 0:
                f.write(b'\x5E')
    
            # Step 6: Insert the user's inputted texture files into the gpb file
            texture_offsets = []
    
            for path in texture_paths:
                with open(path, 'rb') as img_file:
                    img_data = img_file.read()
    
                    # Write texture data and get its offset
                    texture_offset = f.tell()
                    f.write(img_data)
    
                    # Write 5E and repeat until the next address is a factor of 16 in decimal / 10 in hex
                    while f.tell() % 16 != 0:
                        f.write(b'\x5E')
    
                    texture_offsets.append(texture_offset)

            # Step 7: Populate texture metadata
            for i in range(num_textures):
                # Write filename address
                f.seek(metadata_start + i * 8)
                f.write(struct.pack('<I', filename_offsets[i]))
    
                # Write texture data address
                f.seek(metadata_start + 4 + i * 8)
                f.write(struct.pack('<I', texture_offsets[i]))

            messagebox.showinfo("Success!", f"GPB generation completed. {num_textures} textures packed.")

    def generate_gpb1(self):
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
                    if os.path.getsize(full_path) > 524288:  # 512 KB in bytes
                        # Display warning message
                        user_choice = messagebox.askyesno(
                            "Incompatible file detected!",
                            f"The file `{full_path}` is larger than 512 kilobytes. The maximum filesize a texture can be is 512kb for PS2-era GT games.\nYou have likely selected the wrong root folder, and should abort this process and try again. Are you sure you want to continue?"
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
            # Step 1: Write the header
            f.write(b'gpb1')
            f.write(b'\x00' * 8)
            
            # Step 2: Write the number of textures
            f.write(struct.pack('<I', num_textures))
    
            # Step 3: Write reserved space for texture metadata
            metadata_start = f.tell()
            f.write(b'\x00' * (num_textures * 8))
    
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
    
            # Write 5E and repeat until the next address is a factor of 16 in decimal / 10 in hex
            while f.tell() % 16 != 0:
                f.write(b'\x5E')
    
            # Step 6: Insert the user's inputted texture files into the gpb file
            texture_offsets = []
    
            for path in texture_paths:
                with open(path, 'rb') as img_file:
                    img_data = img_file.read()
    
                    # Write texture data and get its offset
                    texture_offset = f.tell()
                    f.write(img_data)
    
                    # Write 5E and repeat until the next address is a factor of 16 in decimal / 10 in hex
                    while f.tell() % 16 != 0:
                        f.write(b'\x5E')
    
                    texture_offsets.append(texture_offset)

            # Step 7: Populate texture metadata
            for i in range(num_textures):
                # Write filename address
                f.seek(metadata_start + i * 8)
                f.write(struct.pack('<I', filename_offsets[i]))
    
                # Write texture data address
                f.seek(metadata_start + 4 + i * 8)
                f.write(struct.pack('<I', texture_offsets[i]))

            messagebox.showinfo("Success!", f"GPB generation completed. {num_textures} textures packed.")

    def generate_gpb2(self):
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
                            f"The file `{full_path}` is larger than 128 megabytes. The maximum filesize a texture can be is 512kb for PS2-era GT games, and the PS3 only has 256mb of video memory.\nYou have likely selected the wrong root folder, and should abort this process and try again. Are you sure you want to continue?"
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
            # Step 1: Write the header
            f.write(b'gpb2')
            f.write(b'\x00' * 8)
    
            # Step 2: Write the number of textures
            f.write(struct.pack('<I', num_textures))
    
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
    
            # Write 5E and repeat until the next address is a factor of 16 in decimal / 10 in hex
            while f.tell() % 16 != 0:
                f.write(b'\x5E')
    
            # Step 6: Insert the user's inputted texture files into the gpb file
            texture_offsets = []
    
            for path in texture_paths:
                with open(path, 'rb') as img_file:
                    img_data = img_file.read()
    
                    # Write texture data and get its offset
                    texture_offset = f.tell()
                    f.write(img_data)
    
                    # Write 5E and repeat until the next address is a factor of 16 in decimal / 10 in hex
                    while f.tell() % 16 != 0:
                        f.write(b'\x5E')
    
                    texture_offsets.append(texture_offset)

            # Step 7: Populate texture metadata
            for i in range(num_textures):
                # Write filename address
                f.seek(metadata_start + i * 16)
                f.write(struct.pack('<I', filename_offsets[i]))
    
                # Write texture data address
                f.seek(metadata_start + 4 + i * 16)
                f.write(struct.pack('<I', texture_offsets[i]))
    
                # Write padding (8 bytes)
                f.seek(metadata_start + 8 + i * 16)
                f.write(b'\x00' * 8)

            messagebox.showinfo("Success!", f"GPB generation completed. {num_textures} textures packed.")

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
                
        import struct
        
        # Define a variable to store the number of textures
        num_textures = None  # Initialize with None or any default value
    
        with open(gpb_path, 'rb') as f:
            # Step 1: Read the number of textures
            f.seek(0x00000004)  # Seek to the address for texture count
            texture_count_bytes = f.read(4)  # Read 4 bytes
                
            # Unpack the bytes to get the integer value
            texture_count = struct.unpack('<I', texture_count_bytes)[0]
            
            # Store the texture_count value in num_textures
            num_textures = texture_count
            print(f"Number of textures: {num_textures}")  # Debugging
                
            # List to hold metadata
            filename_offsets = []
            texture_offsets = []
            next_texture_offsets = []
            
            # Step 1.1: Calculate byte range for texture metadata
            metadata_start = 0x00000008
            metadata_end = int(metadata_start) + (8 * int(num_textures))
            print(f"Metadata start: {metadata_start}, Metadata end: {metadata_end}")
            
            # Step 1.2: Read texture metadata
            f.seek(metadata_start)
            metadata = f.read(metadata_end - metadata_start)
            print(f"Metadata length: {len(metadata)}")  # Debugging
            
            # List to hold extracted filenames
            extracted_filenames = []
        
            # Step 2 & 3: Process each texture metadata chunk
            for i in range(num_textures):
                # Adjusting to read 8 bytes ahead
                filename_offset = int.from_bytes(metadata[i*8:i*8+4], byteorder='little')
                texture_offset = int.from_bytes(metadata[i*8+4:i*8+8], byteorder='little')
                
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
                
                # Add a forward slash if dir_path does not start with it
                if not dir_path.startswith('/'):
                    dir_path = '/' + dir_path
                    
                dir_full_path = f"{self.destination_dir}{dir_path}"
                if not os.path.exists(dir_full_path):
                    os.makedirs(dir_full_path)
            
                # Determine exported filename
                exported_filename = os.path.basename(extracted_filename) + '.img'
            
                # Determine byte range for texture data
                next_texture_offset = int.from_bytes(metadata[i*8+12:i*8+16], byteorder='little')
                
                print(f"--------")
                print(f"Texture# {i+1}: `{extracted_filename}`")
                print(f"Label offset: {filename_offset}")  # Debugging
                print(f"1st byte: {texture_offset}")  # Debugging
                
                # Break out of the loop if next_texture_offset is 0
                if next_texture_offset == 0:
                    last_byte_address = os.path.getsize(gpb_path)
                    print(f"Last byte: [END OF FILE]")  # Debugging
                else:
                    # Determine the actual last byte address by checking for padding
                    f.seek(next_texture_offset - 1)  # Start one byte before next_texture_offset
                    
                    # Check if the current byte is a padding byte
                    while f.read(1) == b'\x5E':
                        next_texture_offset -= 1
                        f.seek(next_texture_offset - 1)  # Move one byte backward
                    
                    last_byte_address = next_texture_offset
                    print(f"Last byte: {next_texture_offset}")  # Debugging
                        
                # Extract texture data
                f.seek(texture_offset) # Go to this address
                img_data = f.read((last_byte_address) - texture_offset) # Read this many bytes
            
                # Write texture data to file
                output_path = os.path.join(dir_full_path, exported_filename)
                with open(output_path, 'wb') as out_file:
                    out_file.write(img_data)
            
            # Generate configuration file
            config = configparser.ConfigParser()
            config.add_section('Textures')
            
            for i, filename in enumerate(extracted_filenames):
                # Construct full path and label
                full_path = os.path.join(self.destination_dir, filename + '.img')
                full_path = full_path.replace("\\", "/")  # Replace back slashes with forwardslashes
                
                config.set('Textures', f'texture_{i+1}_path', full_path)
                config.set('Textures', f'texture_{i+1}_label', filename)
            
            # Write configuration file
            config_file_path = os.path.join(self.destination_dir, 'gpb0_config.ini')
            with open(config_file_path, 'w') as config_file:
                config.write(config_file)
            
            messagebox.showinfo("Success!", f"GPB extraction completed. {num_textures} textures extracted.")
            print(f"GPB extraction completed. {num_textures} textures extracted.")

    def extract_gpb1(self, gpb_path):
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
            texture_count = struct.unpack('<I', texture_count_bytes)[0]
            
            # Store the texture_count value in num_textures
            num_textures = texture_count
            print(f"Number of textures: {num_textures}")  # Debugging
                
            # List to hold metadata
            filename_offsets = []
            texture_offsets = []
            next_texture_offsets = []
            
            # Step 1.1: Calculate byte range for texture metadata
            metadata_start = 0x00000010
            metadata_end = int(metadata_start) + (8 * int(num_textures))
            print(f"Metadata start: {metadata_start}, Metadata end: {metadata_end}")
            
            # Step 1.2: Read texture metadata
            f.seek(metadata_start)
            metadata = f.read(metadata_end - metadata_start)
            print(f"Metadata length: {len(metadata)}")  # Debugging
            
            # List to hold extracted filenames
            extracted_filenames = []
        
            # Step 2 & 3: Process each texture metadata chunk
            for i in range(num_textures):
                # Adjusting to read 8 bytes ahead
                filename_offset = int.from_bytes(metadata[(i*8):(i*8)+4], byteorder='little')
                texture_offset = int.from_bytes(metadata[(i*8)+4:(i*8)+8], byteorder='little')
                
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
                
                # Add a forward slash if dir_path does not start with it
                if not dir_path.startswith('/'):
                    dir_path = '/' + dir_path
                    
                dir_full_path = f"{self.destination_dir}{dir_path}"
                if not os.path.exists(dir_full_path):
                    os.makedirs(dir_full_path)
            
                # Determine exported filename
                exported_filename = os.path.basename(extracted_filename) + '.img'
            
                # Determine byte range for texture data
                next_texture_offset = int.from_bytes(metadata[(i*8)+12:(i*8)+16], byteorder='little')
                
                print(f"--------")
                print(f"Texture# {i+1}: `{extracted_filename}`")
                print(f"Label offset: {filename_offset}")  # Debugging
                print(f"1st byte: {texture_offset}")  # Debugging
                
                # Break out of the loop if next_texture_offset is 0
                if next_texture_offset == 0:
                    last_byte_address = os.path.getsize(gpb_path)
                    print(f"Last byte: [END OF FILE]")  # Debugging
                else:
                    # Determine the actual last byte address by checking for padding
                    f.seek(next_texture_offset - 1)  # Start one byte before next_texture_offset
                    
                    # Check if the current byte is a padding byte
                    while f.read(1) == b'\x5E':
                        next_texture_offset -= 1
                        f.seek(next_texture_offset - 1)  # Move one byte backward
                    
                    last_byte_address = next_texture_offset
                    print(f"Last byte: {next_texture_offset}")  # Debugging
                        
                # Extract texture data
                f.seek(texture_offset) # Go to this address
                img_data = f.read((last_byte_address) - texture_offset) # Read this many bytes
            
                # Write texture data to file
                output_path = os.path.join(dir_full_path, exported_filename)
                with open(output_path, 'wb') as out_file:
                    out_file.write(img_data)
            
            # Generate configuration file
            config = configparser.ConfigParser()
            config.add_section('Textures')
            
            for i, filename in enumerate(extracted_filenames):
                # Construct full path and label
                full_path = os.path.join(self.destination_dir, filename + '.img')
                full_path = full_path.replace("\\", "/")  # Replace back slashes with forwardslashes
                
                config.set('Textures', f'texture_{i+1}_path', full_path)
                config.set('Textures', f'texture_{i+1}_label', filename)
            
            # Write configuration file
            config_file_path = os.path.join(self.destination_dir, 'gpb1_config.ini')
            with open(config_file_path, 'w') as config_file:
                config.write(config_file)
            
            messagebox.showinfo("Success!", f"GPB extraction completed. {num_textures} textures extracted.")
            print(f"GPB extraction completed. {num_textures} textures extracted.")

    def extract_gpb2(self, gpb_path):
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
            texture_count = struct.unpack('<I', texture_count_bytes)[0]
            
            # Store the texture_count value in num_textures
            num_textures = texture_count
            print(f"Number of textures: {num_textures}")  # Debugging
                
            # List to hold metadata
            filename_offsets = []
            texture_offsets = []
            next_texture_offsets = []
            
            # Step 1.1: Calculate byte range for texture metadata
            metadata_start = 0x00000010
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
                # Adjusting to read 8 bytes ahead
                filename_offset = int.from_bytes(metadata[i*16:i*16+4], byteorder='little')
                texture_offset = int.from_bytes(metadata[i*16+4:i*16+8], byteorder='little')
                
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
                
                # Add a forward slash if dir_path does not start with it
                if not dir_path.startswith('/'):
                    dir_path = '/' + dir_path
                    
                dir_full_path = f"{self.destination_dir}{dir_path}"
                if not os.path.exists(dir_full_path):
                    os.makedirs(dir_full_path)
            
                # Determine exported filename
                exported_filename = os.path.basename(extracted_filename) + '.img'
            
                # Determine byte range for texture data
                next_texture_offset = int.from_bytes(metadata[i*16+20:i*16+24], byteorder='little')
                
                print(f"--------")
                print(f"Texture# {i+1}: `{extracted_filename}`")
                print(f"Label offset: {filename_offset}")  # Debugging
                print(f"1st byte: {texture_offset}")  # Debugging
                
                # Break out of the loop if next_texture_offset is 0
                if next_texture_offset == 0:
                    last_byte_address = os.path.getsize(gpb_path)
                    print(f"Last byte: [END OF FILE]")  # Debugging
                else:
                    # Determine the actual last byte address by checking for padding
                    f.seek(next_texture_offset - 1)  # Start one byte before next_texture_offset
                    
                    # Check if the current byte is a padding byte
                    while f.read(1) == b'\x5E':
                        next_texture_offset -= 1
                        f.seek(next_texture_offset - 1)  # Move one byte backward
                    
                    last_byte_address = next_texture_offset
                    print(f"Last byte: {next_texture_offset}")  # Debugging
                        
                # Extract texture data
                f.seek(texture_offset) # Go to this address
                img_data = f.read((last_byte_address) - texture_offset) # Read this many bytes
            
                # Write texture data to file
                output_path = os.path.join(dir_full_path, exported_filename)
                with open(output_path, 'wb') as out_file:
                    out_file.write(img_data)
            
            # Generate configuration file
            config = configparser.ConfigParser()
            config.add_section('Textures')
            
            for i, filename in enumerate(extracted_filenames):
                # Construct full path and label
                full_path = os.path.join(self.destination_dir, filename + '.img')
                full_path = full_path.replace("\\", "/")  # Replace back slashes with forwardslashes
                
                config.set('Textures', f'texture_{i+1}_path', full_path)
                config.set('Textures', f'texture_{i+1}_label', filename)
            
            # Write configuration file
            config_file_path = os.path.join(self.destination_dir, 'gpb2_config.ini')
            with open(config_file_path, 'w') as config_file:
                config.write(config_file)
            
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
                
                # os.path.join doesn't work because texture labels
                # sometimes start with a forward slash and some don't in a gpb3, so instead I check
                # for a forward slash first, if it's not there we add it so the logic doesn't get fucked.
                # And then append dir_path as a simple string. Honestly all of them should probably use this but idk.
                # In any case just make sure that any texture labels in a custom gpb or loose files
                # don't use any anything other than letters, underscore, period sign, and forward slash to avoid having a bad time.
                
                # Add a forward slash if dir_path does not start with it
                if not dir_path.startswith('/'):
                    dir_path = '/' + dir_path
                    
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
                    # Determine the actual last byte address by checking for padding
                    f.seek(next_texture_offset - 1)  # Start one byte before next_texture_offset
                    
                    # Check if the current byte is a padding byte
                    while f.read(1) == b'\x5E':
                        next_texture_offset -= 1
                        f.seek(next_texture_offset - 1)  # Move one byte backward
                    
                    last_byte_address = next_texture_offset
                    print(f"Last byte: {next_texture_offset}")  # Debugging
                        
                # Extract texture data
                f.seek(texture_offset) # Go to this address
                img_data = f.read((last_byte_address) - texture_offset) # Read this many bytes
            
                # Write texture data to file
                output_path = os.path.join(dir_full_path, exported_filename)
                with open(output_path, 'wb') as out_file:
                    out_file.write(img_data)
                    
            print(f"--------")
            print(f"GPB extraction completed. {num_textures} textures extracted.")
                
            # Generate configuration file
            config = configparser.ConfigParser()
            config.add_section('Textures')
            
            for i, filename in enumerate(extracted_filenames):
                # Construct full path and label
                full_path = os.path.join(self.destination_dir, filename + '.img')
                full_path = full_path.replace("\\", "/")  # Replace back slashes with forwardslashes
                
                config.set('Textures', f'texture_{i+1}_path', full_path)
                config.set('Textures', f'texture_{i+1}_label', filename)
            
            # Write configuration file
            config_file_path = os.path.join(self.destination_dir, 'gpb3_config.ini')
            with open(config_file_path, 'w') as config_file:
                config.write(config_file)
            
            messagebox.showinfo("Success!", f"GPB extraction completed. {num_textures} textures extracted.")

    def ask_root_folder_and_update(self):
        root_folder = filedialog.askdirectory(title="Select Root Folder")
        
        # Check if root folder is selected
        if root_folder:
            self.update_texture_paths(root_folder)  # Provide the root folder as an argument
        else:
            messagebox.showerror("Error", "No root folder selected.")
            
    def update_texture_paths(self, root_folder):
        # Walk through the directory tree starting from root_folder
        for root, dirs, files in os.walk(root_folder):
            # Check for any .ini files in the current directory
            for file_name in files:
                if file_name.endswith('.ini'):
                    config_file_path = os.path.join(root, file_name)
                    
                    # Read the existing configuration
                    config = configparser.ConfigParser()
                    config.read(config_file_path)
                    
                    # Check if 'Textures' section exists, if not, create it
                    if 'Textures' not in config:
                        config.add_section('Textures')
                    
                    # Update texture paths based on .img files in the directory
                    for key, value in config.items('Textures'):
                        if key.startswith('texture_') and key.endswith('_label'):
                            label = value
                            img_filename = f"{label}.img"
                            img_path = os.path.join(root, img_filename)
                            
                            # Check if .img file exists
                            if os.path.exists(img_path):
                                config.set('Textures', key.replace('_label', '_path'), img_path)
                            else:
                                print(f"Warning: {img_filename} not found in {root}")
    
                    # Save the updated configuration by overwriting the original file
                    with open(config_file_path, 'w') as config_file:
                        config.write(config_file)
    
        messagebox.showinfo("Success!", "Texture paths updated successfully.")



if __name__ == "__main__":
    app = AssetPackageGenerator()
    app.mainloop()
