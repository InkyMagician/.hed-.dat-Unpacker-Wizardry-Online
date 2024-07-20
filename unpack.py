import struct
import os
from typing import List, Dict

class FpmfArchiveFile:
    def __init__(self):
        self.size: int = 0
        self.offset: int = 0
        self.file_path: str = ""
        self.file_path_size: int = 0
        self.directory_path: str = ""
        self.directory_path_size: int = 0
        self.dat_number: int = 0
        self.data: bytes = b''
        self.unknown0: int = 0
        self.unknown1: int = 0

class FpmfArchive:
    def __init__(self):
        self.size: int = 0
        self.num_files: int = 0
        self.dat_path_len: int = 0
        self.dat_path: str = ""
        self.key_len: int = 0
        self.key: bytes = bytes([
            0xB4, 0xB4, 0xDA, 0xDD, 0x1A, 0x88, 0xAB, 0xFB, 0x79, 0xF1, 0xF6, 0x5F, 0x19, 0xB1, 0x39, 0xB3,
            # ... (rest of the key)
        ])
        self.header: bytes = b''
        self.unknown0: int = 4
        self.unknown1: int = 1
        self.unknown2: int = 2
        self.unknown3: int = 1
        self.unknown4: int = 1
        self.unknown5: int = 2
        self.unknown6: int = 0
        self.unknown7: int = 0
        self.unknown8: int = 0x400000
        self.unknown9: int = 3
        self.unknown10: int = 261
        self.unknown11: int = 4
        self.file_info_size: int = 0
        self.files: List[FpmfArchiveFile] = []

def decrypt_hed(data: bytes) -> bytes:
    dl = 0x67  # For JP client
    sub = 0xC7  # For JP client
    al = 0
    result = bytearray()

    for cl in data[12:]:
        bl = (al + dl) & 0xFF
        bl = (bl ^ cl) & 0xFF
        bl = (bl - sub) & 0xFF
        al = (al + 1) & 0xFF
        dl = cl
        result.append(bl)

    return bytes(result)

def decrypt_dat(dat_content: bytes, file_offset: int, size: int, key: bytes) -> bytes:
    dl = 0x67  # For JP client
    sub = 0xC7  # For JP client
    al = 0
    result = bytearray()
    key_len = len(key)
    key_index = 0

    for i in range(size):
        cl = dat_content[file_offset + i]
        bl = (al + dl) & 0xFF
        bl = (bl ^ cl) & 0xFF
        bl = (bl - sub) & 0xFF
        al = (al + 1) & 0xFF
        dl = cl
        decrypted = (bl - key[key_index]) & 0xFF
        result.append(decrypted)
        key_index = (key_index + 1) % key_len

    return bytes(result)

def unpack_fpmf(hed_file_path: str, output_dir: str):
    with open(hed_file_path, 'rb') as f:
        hed_data = f.read()

    if hed_data[:4] != b'FPMF':
        raise ValueError("Invalid HED file")

    archive = FpmfArchive()
    archive.size = struct.unpack('<I', hed_data[4:8])[0]

    decrypted_hed = decrypt_hed(hed_data)
    print(f"Decrypted HED size: {len(decrypted_hed)} bytes")

    # Parse decrypted HED data
    offset = 0
    archive.unknown0, archive.unknown1, archive.unknown2 = struct.unpack('<III', decrypted_hed[offset:offset+12])
    offset += 12
    archive.unknown3, archive.unknown4 = decrypted_hed[offset:offset+2]
    offset += 2
    archive.unknown5, = struct.unpack('<I', decrypted_hed[offset:offset+4])
    offset += 4

    archive.dat_path_len = decrypted_hed[offset]
    offset += 1
    archive.dat_path = decrypted_hed[offset:offset+archive.dat_path_len].decode('utf-8')
    offset += archive.dat_path_len

    print(f"DAT path: {archive.dat_path}")

    archive.unknown8, archive.unknown9, archive.unknown10 = struct.unpack('<III', decrypted_hed[offset:offset+12])
    offset += 12

    archive.key_len, = struct.unpack('<I', decrypted_hed[offset:offset+4])
    offset += 4
    archive.key = decrypted_hed[offset:offset+archive.key_len]
    offset += archive.key_len

    archive.unknown11, archive.file_info_size, archive.num_files = struct.unpack('<III', decrypted_hed[offset:offset+12])
    offset += 12

    print(f"Number of files: {archive.num_files}")

    for i in range(archive.num_files):
        file = FpmfArchiveFile()
        file.directory_path_size = decrypted_hed[offset]
        offset += 1
        file.directory_path = decrypted_hed[offset:offset+file.directory_path_size].decode('utf-8')
        offset += file.directory_path_size

        file.file_path_size = decrypted_hed[offset]
        offset += 1
        file.file_path = decrypted_hed[offset:offset+file.file_path_size].decode('utf-8')
        offset += file.file_path_size

        file.dat_number, file.offset, file.size, file.unknown0, file.unknown1 = struct.unpack('<IIIII', decrypted_hed[offset:offset+20])
        offset += 20

        print(f"File {i+1}: {file.file_path}, Size: {file.size}, Offset: {file.offset}")

        archive.files.append(file)

    print(f"Successfully parsed {len(archive.files)} files")

    # Process DAT files
    dat_directory = os.path.dirname(hed_file_path)
    dat_files = sorted([f for f in os.listdir(dat_directory) if f.endswith('.dat')])
    
    if not dat_files:
        raise FileNotFoundError(f"No .dat files found in {dat_directory}")

    print(f"Found {len(dat_files)} DAT files")

    dat_data: Dict[str, bytes] = {}
    total_dat_size = 0
    for dat_file in dat_files:
        with open(os.path.join(dat_directory, dat_file), 'rb') as f:
            dat_content = f.read()
            dat_data[dat_file] = dat_content
            total_dat_size += len(dat_content)
            print(f"Loaded {dat_file}: {len(dat_content)} bytes")

    print(f"Total DAT data size: {total_dat_size} bytes")

    for file in archive.files:
        try:
            # Find the correct DAT file
            current_offset = 0
            for dat_file, content in dat_data.items():
                if current_offset + len(content) > file.offset:
                    # This is the correct DAT file
                    file_offset = file.offset - current_offset
                    decrypted_data = decrypt_dat(content, file_offset, file.size, archive.key)
                    break
                current_offset += len(content)
            else:
                raise ValueError(f"Could not find DAT file for offset {file.offset}")
            
            output_path = os.path.join(output_dir, file.file_path.lstrip('./\\'))
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
        except Exception as e:
            print(f"Error unpacking file {file.file_path}: {str(e)}")

    print(f"Unpacked {len(archive.files)} files to {output_dir}")

# Usage
if __name__ == "__main__":
    hed_file_path = r"C:\Users\Inky\Desktop\data\world\field\field.hed"  # Update this path
    output_dir = r"C:\Users\Inky\Desktop\decrypt"  # Update this path
    unpack_fpmf(hed_file_path, output_dir)
