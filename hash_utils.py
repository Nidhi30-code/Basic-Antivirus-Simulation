import hashlib
import os

CHUNK_SIZE = 65536  # 64KB chunks for efficient memory usage when hashing large files

def calculate_sha256(filepath):
    """
    Safely calculates the SHA-256 cryptographic hash of a given file.
    
    Reads the file in binary mode ('rb') in fixed-size chunks to prevent
    high memory usage on large files. Handles permission and IO errors gracefully.

    :param filepath: Path to the target file.
    :return: (sha256_hex_string, error_message)
             If successful, sha256_hex_string is hex string and error_message is None.
             If failed, sha256_hex_string is None and error_message describes the issue.
    """
    if not os.path.exists(filepath):
        return None, "File does not exist"
    
    if os.path.isdir(filepath):
        return None, "Path is a directory, not a file"

    sha256_hash = hashlib.sha256()

    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest().lower(), None

    except PermissionError:
        return None, "Permission denied (Access Restricted)"
    except FileNotFoundError:
        return None, "File not found"
    except OSError as e:
        return None, f"I/O Error: {str(e)}"
    except Exception as e:
        return None, f"Read error: {str(e)}"

def hash_string(data_bytes):
    """
    Calculates SHA-256 hash of raw byte data.
    Useful for testing or memory-buffered content.
    """
    return hashlib.sha256(data_bytes).hexdigest().lower()
