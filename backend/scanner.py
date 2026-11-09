import os
import re
import json
import hashlib
import urllib.parse
from backend.parser import parse_sor_file

# Global cache of parsed files
# Structure: { file_id: { "full_path": path, "metadata": ..., "link_parameters": ..., "events": ... } }
SCAN_CACHE = {}

BAHASA_MONTHS_RE = re.compile(
    r'\b(Januari|Februari|Maret|April|Mei|Juni|Juli|Agustus|September|Oktober|November|Desember)\b\s+\d{4}',
    re.IGNORECASE
)

def extract_month_year(dirpath, root_path):
    """
    Traverses up the directory path to find any parent folder
    that matches Month & Year in Bahasa Indonesia (e.g. 'Januari 2026').
    """
    current = os.path.abspath(dirpath)
    root_abs = os.path.abspath(root_path)
    
    path_to_check = current
    while True:
        folder_name = os.path.basename(path_to_check)
        if BAHASA_MONTHS_RE.search(folder_name):
            return folder_name
            
        parent = os.path.dirname(path_to_check)
        if path_to_check == parent or path_to_check == root_abs:
            # Check if root folder itself has month-year
            root_name = os.path.basename(root_abs)
            if BAHASA_MONTHS_RE.search(root_name):
                return root_name
            break
        path_to_check = parent
        
    return "Other"

def get_file_id(file_path):
    """
    Generates a safe, URL-friendly unique ID for a file path.
    """
    return hashlib.md5(file_path.encode("utf-8")).hexdigest()

CACHE_DIR = os.path.join(os.path.dirname(__file__), ".parse_cache")

def get_parsed_sor(full_path):
    """
    Retrieves the parsed result for a .sor file from a persistent disk cache
    if the file hasn't been modified (verifying mtime and size).
    Otherwise, parses and updates the cache.
    """
    os.makedirs(CACHE_DIR, exist_ok=True)
    
    file_id = get_file_id(full_path)
    cache_path = os.path.join(CACHE_DIR, f"{file_id}.json")
    
    try:
        stat = os.stat(full_path)
        actual_mtime = stat.st_mtime
        actual_size = stat.st_size
    except Exception as e:
        raise e
        
    # Check cache
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cached = json.load(f)
            
            # Verify cache validity
            if (cached.get("file_path") == full_path and
                    cached.get("mtime") == actual_mtime and
                    cached.get("size") == actual_size):
                return cached["parsed_data"]
        except Exception:
            # If cache reading/parsing fails, ignore it and re-parse
            pass
            
    # Parse the raw file
    parsed = parse_sor_file(full_path)
    
    # Save to cache
    try:
        cache_data = {
            "file_path": full_path,
            "mtime": actual_mtime,
            "size": actual_size,
            "parsed_data": parsed
        }
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(cache_data, f, ensure_ascii=False)
    except Exception as e:
        print(f"Error saving parse cache for {full_path}: {e}")
        
    return parsed

def scan_directory(root_path):
    """
    Recursively scans the directory for .sor files,
    parses metadata (shallow scan), and caches results.
    Returns grouped stats by folder.
    """
    global SCAN_CACHE
    SCAN_CACHE.clear() # Reset cache on new scan
    
    if not os.path.exists(root_path):
        return {"error": f"Path does not exist: {root_path}", "folders": {}}
        
    folders_data = {}
    
    # Traverse directories recursively
    for dirpath, _, filenames in os.walk(root_path):
        # Skip hidden folders (but allow relative path dot references)
        if any(part.startswith('.') and part not in ['.', '..'] for part in dirpath.split(os.sep)):
            continue
            
        sor_files = [f for f in filenames if f.lower().endswith('.sor')]
        if not sor_files:
            continue
            
        # Parent folder name serves as the Cable/Route Group
        folder_name = os.path.basename(dirpath)
        if not folder_name:
            folder_name = "Root"
            
        relative_path = os.path.relpath(dirpath, root_path)
        
        folder_item = {
            "folder_name": folder_name,
            "relative_path": relative_path,
            "absolute_path": os.path.abspath(dirpath),
            "month_year": extract_month_year(dirpath, root_path),
            "files": []
        }
        
        for fname in sor_files:
            full_path = os.path.join(dirpath, fname)
            file_id = get_file_id(full_path)
            
            try:
                # Perform the parse (utilizing persistent disk cache)
                parsed = get_parsed_sor(full_path)
                
                # Shallow cache entry (keep everything except the trace points to save RAM)
                cache_entry = {
                    "id": file_id,
                    "file_path": full_path,
                    "file_name": fname,
                    "is_mock": parsed["is_mock"],
                    "metadata": parsed["metadata"],
                    "link_parameters": parsed["link_parameters"],
                    "events": parsed["events"]
                }
                
                # Store full parsed details in SCAN_CACHE (including trace points for deep loading)
                SCAN_CACHE[file_id] = parsed
                
                # Append shallow metadata to folder files list for index APIs
                folder_item["files"].append({
                    "id": file_id,
                    "file_path": full_path,
                    "file_name": fname,
                    "is_mock": parsed["is_mock"],
                    "metadata": parsed["metadata"],
                    "link_parameters": parsed["link_parameters"],
                    "events": parsed["events"],
                    "events_count": len(parsed["events"])
                })
            except Exception as e:
                print(f"Error parsing file {full_path}: {e}")
                # Log corrupted file, but don't break the scanner
                folder_item["files"].append({
                    "id": file_id,
                    "file_name": fname,
                    "error": str(e),
                    "is_corrupted": True
                })
                
        if folder_item["files"]:
            folder_id = hashlib.md5(relative_path.encode("utf-8")).hexdigest()
            folder_item["folder_id"] = folder_id
            folders_data[folder_id] = folder_item
            
    return folders_data

def get_cached_file(file_id):
    """
    Returns full details (including trace points) of a single file from cache.
    First checks in-memory SCAN_CACHE.
    If not present, checks if a persistent cache file exists on disk, reads it,
    populates SCAN_CACHE, and returns it.
    """
    if file_id in SCAN_CACHE:
        return SCAN_CACHE[file_id]
        
    # Check disk cache
    cache_path = os.path.join(CACHE_DIR, f"{file_id}.json")
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cached = json.load(f)
            
            # Verify file exists and match parameters
            full_path = cached.get("file_path")
            if full_path and os.path.exists(full_path):
                stat = os.stat(full_path)
                if (cached.get("mtime") == stat.st_mtime and
                        cached.get("size") == stat.st_size):
                    parsed = cached["parsed_data"]
                    SCAN_CACHE[file_id] = parsed
                    return parsed
        except Exception:
            pass
            
    return None
