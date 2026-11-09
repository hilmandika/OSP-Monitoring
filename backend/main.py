import os
import json
import re
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, Dict, Any, List

from backend.scanner import scan_directory, get_cached_file

app = FastAPI(title="OTDR .sor Dashboard API", version="1.0.0")

# Enable CORS for frontend local serving
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")

# Default Quality Thresholds & Parameters
DEFAULT_CONFIG = {
    "last_scan_path": "./otdr_data_samples",
    "thresholds": {
        "max_splice_loss_db": 0.10,
        "max_connector_loss_db": 0.50,
        "max_attenuation_1310_db_km": 0.40,
        "max_attenuation_1550_db_km": 0.25,
        "max_total_loss_db": 15.0
    },
    "auto_commands": {
        "Nokia": "environment no more",
        "ZTE": "terminal length 0",
        "Cisco": "terminal length 0",
        "Huawei": "screen-length 0 temporary"
    },
    "ssh_rules": {
        "Nokia 7450 ESS-6": "ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-rsa {ip}"
    }
}

class Thresholds(BaseModel):
    max_splice_loss_db: float
    max_connector_loss_db: float
    max_attenuation_1310_db_km: float
    max_attenuation_1550_db_km: float
    max_total_loss_db: float

class ScanRequest(BaseModel):
    path: str

def load_config():
    """
    Loads threshold configurations from config.json.
    """
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                config = json.load(f)
                # Merge defaults to handle missing keys gracefully
                merged = DEFAULT_CONFIG.copy()
                merged.update(config)
                return merged
        except Exception as e:
            print(f"Error reading config: {e}")
    return DEFAULT_CONFIG.copy()

def save_config(config):
    """
    Saves configurations to config.json.
    """
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        print(f"Error saving config: {e}")

# Global state
ACTIVE_CONFIG = load_config()
SCANNED_FOLDERS = {}

def evaluate_fiber_status(fiber, thresholds, folder_name=None):
    """
    Evaluates fiber measurements against active thresholds on the fly.
    Returns status: "Pass" or "Fail", and a list of detailed failure reasons.
    """
    # If the file was corrupted
    if fiber.get("is_corrupted"):
        return {
            "status": "Fail",
            "reasons": [fiber.get("error", "Corrupted .sor file format")],
            "highest_splice_db": 0.0,
            "highest_connector_db": 0.0
        }
        
    meta = fiber.get("metadata", {})
    link = fiber.get("link_parameters", {})
    events = fiber.get("events", [])
    
    wavelength = meta.get("wavelength_nm", 1550)
    total_loss = link.get("total_loss_db", 0.0)
    avg_att = link.get("average_attenuation_db_km", 0.0)
    total_length = link.get("total_length_km", 0.0)
    
    status = "Pass"
    reasons = []
    
    # 0. Folder-name desired length check
    if not folder_name and fiber.get("file_path"):
        import os
        folder_name = os.path.basename(os.path.dirname(fiber["file_path"]))
        
    desired_length = None
    if folder_name:
        import re
        match = re.search(r'\((\d+(?:\.\d+)?)\s*km\)', folder_name, re.IGNORECASE)
        if match:
            try:
                desired_length = float(match.group(1))
            except ValueError:
                pass
                
    if desired_length is not None:
        if total_length < desired_length:
            status = "Fail"
            reasons.append(f"Fiber length ({total_length} km) is less than required ({desired_length} km) based on folder name")
            
    # 1. Total Loss check
    if total_loss > thresholds["max_total_loss_db"]:
        status = "Fail"
        reasons.append(f"Total loss ({total_loss} dB) exceeds max ({thresholds['max_total_loss_db']} dB)")
        
    # 2. Attenuation check (wavelength dependent)
    if wavelength == 1310:
        limit = thresholds["max_attenuation_1310_db_km"]
        if avg_att > limit:
            status = "Fail"
            reasons.append(f"Attenuation ({avg_att} dB/km) exceeds limit for 1310nm ({limit} dB/km)")
    else: # 1550 nm or others
        limit = thresholds["max_attenuation_1550_db_km"]
        if avg_att > limit:
            status = "Fail"
            reasons.append(f"Attenuation ({avg_att} dB/km) exceeds limit for 1550nm ({limit} dB/km)")
            
    # 3. Check individual event losses (Splice & Connector check)
    max_splice = thresholds["max_splice_loss_db"]
    max_conn = thresholds["max_connector_loss_db"]
    
    highest_splice = 0.0
    highest_connector = 0.0
    
    for ev in events:
        ev_type = ev.get("type", "").lower()
        ev_loss = ev.get("loss_db", 0.0)
        ev_dist = ev.get("distance_km", 0.0)
        
        # Skip launching/end events in mid-span quality checks if they are large reflections
        if "launch" in ev_type or "end" in ev_type:
            continue
            
        if "connector" in ev_type or "reflection" in ev_type:
            highest_connector = max(highest_connector, ev_loss)
            if ev_loss > max_conn:
                status = "Fail"
                reasons.append(f"Connector loss ({ev_loss} dB) at {ev_dist}km exceeds limit ({max_conn} dB)")
        elif "splice" in ev_type or "non-reflective" in ev_type or ev_loss > 0.0:
            highest_splice = max(highest_splice, ev_loss)
            if ev_loss > max_splice:
                status = "Fail"
                reasons.append(f"Splice loss ({ev_loss} dB) at {ev_dist}km exceeds limit ({max_splice} dB)")
                
    return {
        "status": status,
        "reasons": reasons,
        "highest_splice_db": round(highest_splice, 3),
        "highest_connector_db": round(highest_connector, 3)
    }

@app.get("/api/settings")
def get_settings():
    return ACTIVE_CONFIG

@app.post("/api/settings")
def update_settings(thresholds: Thresholds):
    global ACTIVE_CONFIG
    ACTIVE_CONFIG["thresholds"] = thresholds.model_dump()
    save_config(ACTIVE_CONFIG)
    return {"message": "Threshold settings updated successfully", "config": ACTIVE_CONFIG}

@app.post("/api/scan")
def trigger_scan(req: ScanRequest):
    global SCANNED_FOLDERS, ACTIVE_CONFIG
    path = req.path.strip()
    
    # Save the scanned path for convenience
    ACTIVE_CONFIG["last_scan_path"] = path
    save_config(ACTIVE_CONFIG)
    
    folders_data = scan_directory(path)
    
    if "error" in folders_data:
        raise HTTPException(status_code=400, detail=folders_data["error"])
        
    SCANNED_FOLDERS = folders_data
    
    # Return brief aggregate summaries of each folder
    return get_folders_summary()

@app.get("/api/folders")
def get_folders():
    """
    Returns folder-level summary cards.
    Calculates Pass/Fail tallies in real-time.
    """
    global SCANNED_FOLDERS
    if not SCANNED_FOLDERS:
        # Auto-trigger scan on the last saved path if it exists
        last_path = ACTIVE_CONFIG.get("last_scan_path", "./otdr_data_samples")
        if os.path.exists(last_path):
            SCANNED_FOLDERS = scan_directory(last_path)
            
    return get_folders_summary()

def get_folders_summary():
    """
    Helper to calculate real-time aggregated summary stats for each scanned folder.
    """
    thresholds = ACTIVE_CONFIG["thresholds"]
    summary = []
    
    for folder_id, data in SCANNED_FOLDERS.items():
        folder_name = data["folder_name"]
        total_files = len(data["files"])
        pass_count = 0
        fail_count = 0
        wavelengths = set()
        total_loss_sum = 0.0
        length_sum = 0.0
        
        for f in data["files"]:
            # Evaluate dynamically
            eval_res = evaluate_fiber_status(f, thresholds, folder_name)
            if eval_res["status"] == "Pass":
                pass_count += 1
            else:
                fail_count += 1
                
            meta = f.get("metadata", {})
            if "wavelength_nm" in meta:
                wavelengths.add(meta["wavelength_nm"])
                
            link = f.get("link_parameters", {})
            total_loss_sum += link.get("total_loss_db", 0.0)
            length_sum += link.get("total_length_km", 0.0)
            
        avg_attenuation = 0.0
        if length_sum > 0:
            avg_attenuation = total_loss_sum / length_sum
            
        summary.append({
            "folder_id": folder_id,
            "folder_name": folder_name,
            "relative_path": data["relative_path"],
            "absolute_path": data["absolute_path"],
            "month_year": data.get("month_year", "Other"),
            "total_fibers": total_files,
            "passed_fibers": pass_count,
            "failed_fibers": fail_count,
            "wavelengths": sorted(list(wavelengths)),
            "average_attenuation_db_km": round(avg_attenuation, 4),
            "total_length_km": round(length_sum, 2),
            "average_length_km": round(length_sum / total_files, 2) if total_files > 0 else 0.0
        })
        
    return summary

@app.get("/api/folders/{folder_id}/fibers")
def get_folder_fibers(folder_id: str):
    """
    Returns lists of all fibers in a specific folder,
    with dynamically evaluated pass/fail status.
    """
    if folder_id not in SCANNED_FOLDERS:
        raise HTTPException(status_code=404, detail=f"Folder {folder_id} not found")
        
    thresholds = ACTIVE_CONFIG["thresholds"]
    folder_data = SCANNED_FOLDERS[folder_id]
    folder_name = folder_data["folder_name"]
    
    fibers_list = []
    for f in folder_data["files"]:
        # Deeply evaluate using active thresholds
        evaluation = evaluate_fiber_status(f, thresholds, folder_name)
        
        fibers_list.append({
            "id": f["id"],
            "file_name": f["file_name"],
            "is_mock": f.get("is_mock", False),
            "metadata": f.get("metadata", {}),
            "link_parameters": f.get("link_parameters", {}),
            "highest_splice_db": evaluation["highest_splice_db"],
            "highest_connector_db": evaluation["highest_connector_db"],
            "status": evaluation["status"],
            "reasons": evaluation["reasons"]
        })
        
    return {
        "folder_id": folder_id,
        "folder_name": folder_name,
        "relative_path": folder_data["relative_path"],
        "absolute_path": folder_data["absolute_path"],
        "fibers": fibers_list
    }

@app.get("/api/files/{file_id}")
def get_file_details(file_id: str):
    """
    Deep-loads a single file from memory cache (contains high-fidelity trace points).
    """
    file_data = get_cached_file(file_id)
    if not file_data:
        raise HTTPException(status_code=404, detail="File details not found. Please scan directory first.")
        
    # Re-evaluate status in real-time
    thresholds = ACTIVE_CONFIG["thresholds"]
    evaluation = evaluate_fiber_status(file_data, thresholds)
    
    file_data_copy = file_data.copy()
    file_data_copy["status"] = evaluation["status"]
    file_data_copy["reasons"] = evaluation["reasons"]
    file_data_copy["highest_splice_db"] = evaluation["highest_splice_db"]
    file_data_copy["highest_connector_db"] = evaluation["highest_connector_db"]
    
    return file_data_copy

# --- Topology NMS Endpoints ---

TOPOLOGY_PATH = os.path.join(os.path.dirname(__file__), "data", "topology.json")

class DeviceModel(BaseModel):
    id: str
    name: str
    type: str
    brand: str
    model: str
    ip: str
    status: str
    x: float
    y: float
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    hidden: Optional[bool] = False
    outside_managed: Optional[bool] = False

class ConnectionModel(BaseModel):
    id: str
    source: str
    source_interface: str
    target: str
    target_interface: str
    bitrate: int
    link: str
    type: str  # "Uplink" or "Interlink"
    status: str
    dual_track: Optional[bool] = False
    hidden: Optional[bool] = False
    source_lag: Optional[str] = ""
    target_lag: Optional[str] = ""
    multipath_lag: Optional[bool] = False

class TopologyModel(BaseModel):
    devices: List[DeviceModel]
    connections: List[ConnectionModel]

def load_topology():
    if os.path.exists(TOPOLOGY_PATH):
        try:
            with open(TOPOLOGY_PATH, "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error reading topology: {e}")
    
    # Fallback to empty if reading fails or file doesn't exist
    return {"devices": [], "connections": []}

@app.get("/api/topology")
def get_topology():
    """
    Retrieves the current network equipment and connection topology.
    """
    return load_topology()

@app.post("/api/topology")
def save_topology(topology: TopologyModel):
    """
    Updates the entire network topology list and saves it to disk.
    """
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(TOPOLOGY_PATH), exist_ok=True)
        
        # Convert to dict and save
        data = topology.dict()
        with open(TOPOLOGY_PATH, "w") as f:
            json.dump(data, f, indent=2)
        return {"status": "success", "message": "Topology saved successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save topology: {str(e)}")

class ConsoleSettingsModel(BaseModel):
    router_ip: str
    olt_ip: str

class CommandRequest(BaseModel):
    device_ip: str
    device_type: str
    device_username: str
    device_password: str
    command: str
    jumpbox_ip: str
    jumpbox_username: str
    jumpbox_password: str
    device_brand: Optional[str] = None
    device_model: Optional[str] = None

@app.get("/api/console/settings")
def get_console_settings():
    global ACTIVE_CONFIG
    return ACTIVE_CONFIG.get("jumpbox", {"router_ip": "10.0.0.1", "olt_ip": "10.0.0.2"})

@app.post("/api/console/settings")
def save_console_settings(settings: ConsoleSettingsModel):
    global ACTIVE_CONFIG
    ACTIVE_CONFIG["jumpbox"] = settings.dict()
    save_config(ACTIVE_CONFIG)
    return {"status": "success", "message": "Console settings updated successfully.", "config": ACTIVE_CONFIG}

@app.get("/api/console/auto-commands")
def get_auto_commands():
    global ACTIVE_CONFIG
    return ACTIVE_CONFIG.get("auto_commands", {})

@app.post("/api/console/auto-commands")
def save_auto_commands(commands: Dict[str, str]):
    global ACTIVE_CONFIG
    ACTIVE_CONFIG["auto_commands"] = commands
    save_config(ACTIVE_CONFIG)
    return {"status": "success", "message": "Auto commands updated successfully.", "auto_commands": ACTIVE_CONFIG["auto_commands"]}

@app.get("/api/console/ssh-rules")
def get_ssh_rules():
    global ACTIVE_CONFIG
    return ACTIVE_CONFIG.get("ssh_rules", {})

@app.post("/api/console/ssh-rules")
def save_ssh_rules(rules: Dict[str, str]):
    global ACTIVE_CONFIG
    ACTIVE_CONFIG["ssh_rules"] = rules
    save_config(ACTIVE_CONFIG)
    return {"status": "success", "message": "SSH rules updated successfully.", "ssh_rules": ACTIVE_CONFIG["ssh_rules"]}


# --- Optical Power Scan Persistence & Static GitHub Pages Publisher ---

OPTICAL_SCAN_PATH = os.path.join(os.path.dirname(__file__), "data", "optical_scan.json")
PAGES_AUTH_PATH = os.path.join(os.path.dirname(__file__), "data", "pages_auth.json")
STATIC_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "static_data")


class PagesUserModel(BaseModel):
    username: str
    password: str
    note: Optional[str] = ""


class PagesAuthUpdateRequest(BaseModel):
    users: List[PagesUserModel]


def load_pages_auth():
    os.makedirs(os.path.dirname(PAGES_AUTH_PATH), exist_ok=True)
    if os.path.exists(PAGES_AUTH_PATH):
        try:
            with open(PAGES_AUTH_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "master_key_hex" in data and "users" in data:
                    return data
        except Exception as e:
            print(f"Error reading pages_auth.json: {e}")

    default_auth = {
        "master_key_hex": os.urandom(32).hex(),
        "users": [
            {
                "username": "admin",
                "password": "telkom123",
                "note": "Default Administrator"
            }
        ]
    }
    save_pages_auth(default_auth)
    return default_auth


def save_pages_auth(auth_cfg):
    os.makedirs(os.path.dirname(PAGES_AUTH_PATH), exist_ok=True)
    with open(PAGES_AUTH_PATH, "w", encoding="utf-8") as f:
        json.dump(auth_cfg, f, indent=2)


def encrypt_json_payload(data_obj, master_key_bytes: bytes, key_id: str):
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    iv = os.urandom(12)
    aesgcm = AESGCM(master_key_bytes)
    plaintext = json.dumps(data_obj, ensure_ascii=False).encode("utf-8")
    ct = aesgcm.encrypt(iv, plaintext, None)
    return {
        "enc": True,
        "kid": key_id,
        "iv": base64.b64encode(iv).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii")
    }


def decrypt_or_read_json(file_path: str, master_key_bytes: bytes):
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    with open(file_path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    if isinstance(raw, dict) and raw.get("enc") is True:
        iv = base64.b64decode(raw["iv"])
        ct = base64.b64decode(raw["ct"])
        aesgcm = AESGCM(master_key_bytes)
        pt = aesgcm.decrypt(iv, ct, None)
        return json.loads(pt.decode("utf-8"))
    return raw


def write_encrypted_json(file_path: str, data_obj, master_key_bytes: bytes, key_id: str):
    enc_obj = encrypt_json_payload(data_obj, master_key_bytes, key_id)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(enc_obj, f)


def build_auth_manifest(auth_cfg):
    import base64
    import hashlib
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    master_key_bytes = bytes.fromhex(auth_cfg["master_key_hex"])
    key_id = hashlib.sha256(master_key_bytes).hexdigest()[:12]
    iterations = 100000
    slots = []

    for u in auth_cfg.get("users", []):
        uname = (u.get("username") or "").strip().lower()
        pw = u.get("password") or ""
        if not uname or not pw:
            continue
        salt = os.urandom(16)
        derived_key = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, iterations, dklen=32)
        wrap_iv = os.urandom(12)
        wrapped_mk = AESGCM(derived_key).encrypt(wrap_iv, master_key_bytes, None)
        slots.append({
            "username": uname,
            "salt": base64.b64encode(salt).decode("ascii"),
            "iterations": iterations,
            "iv": base64.b64encode(wrap_iv).decode("ascii"),
            "wrapped_key": base64.b64encode(wrapped_mk).decode("ascii")
        })

    manifest = {
        "version": 1,
        "kid": key_id,
        "users": slots
    }
    os.makedirs(STATIC_DATA_DIR, exist_ok=True)
    with open(os.path.join(STATIC_DATA_DIR, "auth_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    return master_key_bytes, key_id


@app.get("/api/pages-auth")
def get_pages_auth():
    auth_cfg = load_pages_auth()
    return {"users": auth_cfg.get("users", [])}


@app.post("/api/pages-auth")
def update_pages_auth(req: PagesAuthUpdateRequest):
    clean_users = []
    seen = set()
    for u in req.users:
        uname = u.username.strip()
        pw = u.password.strip()
        if not uname or not pw:
            continue
        if uname.lower() in seen:
            continue
        seen.add(uname.lower())
        clean_users.append({
            "username": uname,
            "password": pw,
            "note": (u.note or "").strip()
        })

    if not clean_users:
        raise HTTPException(status_code=400, detail="At least one authorized user is required.")

    auth_cfg = load_pages_auth()
    auth_cfg["users"] = clean_users
    save_pages_auth(auth_cfg)
    build_auth_manifest(auth_cfg)
    return {"status": "success", "users": clean_users}


class OpticalScanItem(BaseModel):
    router: str
    target: str
    port: str
    status: str  # "success", "unsupported", "failed", "unreachable"
    displayText: Optional[str] = ""
    toolTip: Optional[str] = ""
    value: Optional[float] = None
    lowAlarm: Optional[float] = None
    lowWarn: Optional[float] = None
    highWarn: Optional[float] = None
    highAlarm: Optional[float] = None
    thresholdStatus: Optional[str] = ""
    errorMsg: Optional[str] = ""


class OpticalScanSaveRequest(BaseModel):
    results: List[OpticalScanItem]
    replace_all: Optional[bool] = False


def load_optical_scan():
    if os.path.exists(OPTICAL_SCAN_PATH):
        try:
            with open(OPTICAL_SCAN_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error reading optical_scan.json: {e}")
    return {"updated_at": None, "results": []}


@app.get("/api/console/optical-scan")
def get_optical_scan():
    return load_optical_scan()


@app.post("/api/console/optical-scan")
def save_optical_scan(req: OpticalScanSaveRequest):
    from datetime import datetime
    os.makedirs(os.path.dirname(OPTICAL_SCAN_PATH), exist_ok=True)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    existing_data = load_optical_scan()
    if req.replace_all or not existing_data.get("results"):
        merged_list = [item.dict() for item in req.results]
    else:
        # Merge by router + port key so single-device scans update the master report
        merged_map = {}
        order_keys = []
        for item in existing_data.get("results", []):
            key = f"{item.get('router')}||{item.get('port')}"
            if key not in merged_map:
                order_keys.append(key)
            merged_map[key] = item
        for item in req.results:
            d = item.dict()
            key = f"{d.get('router')}||{d.get('port')}"
            if key not in merged_map:
                order_keys.append(key)
            merged_map[key] = d
        merged_list = [merged_map[k] for k in order_keys]

    payload = {
        "updated_at": now_str,
        "results": merged_list
    }
    with open(OPTICAL_SCAN_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    return {"status": "success", "updated_at": now_str, "count": len(merged_list)}


def is_already_encrypted_with_kid(file_path: str, key_id: str) -> bool:
    if not os.path.exists(file_path):
        return False
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            head = f.read(120)
        return '"enc": true' in head and f'"kid": "{key_id}"' in head
    except Exception:
        return False


def generate_static_snapshot():
    """
    Exports all OTDR folders, individual fiber details/traces, Network Topology,
    Settings, and Optical Power Scan results into frontend/static_data/ encrypted
    with AES-256-GCM so only authenticated users can view the data on GitHub Pages.
    """
    from datetime import datetime

    global SCANNED_FOLDERS
    folders_dir = os.path.join(STATIC_DATA_DIR, "folders")
    files_dir = os.path.join(STATIC_DATA_DIR, "files")
    folders_json_path = os.path.join(STATIC_DATA_DIR, "folders.json")

    os.makedirs(folders_dir, exist_ok=True)
    os.makedirs(files_dir, exist_ok=True)

    # Load encryption configuration & write auth_manifest.json
    auth_cfg = load_pages_auth()
    master_key_bytes, key_id = build_auth_manifest(auth_cfg)

    # Only scan disk if SCANNED_FOLDERS is empty AND no prior static OTDR snapshot exists
    if not SCANNED_FOLDERS and not os.path.exists(folders_json_path):
        last_path = ACTIVE_CONFIG.get("last_scan_path", "./otdr_data")
        if os.path.exists(last_path):
            SCANNED_FOLDERS = scan_directory(last_path)
        elif os.path.exists("./otdr_data"):
            SCANNED_FOLDERS = scan_directory("./otdr_data")
        elif os.path.exists("./otdr_data_samples"):
            SCANNED_FOLDERS = scan_directory("./otdr_data_samples")

    # 1. Settings (encrypted)
    write_encrypted_json(os.path.join(STATIC_DATA_DIR, "settings.json"), ACTIVE_CONFIG, master_key_bytes, key_id)

    # 2. Topology (encrypted)
    topo = load_topology()
    write_encrypted_json(os.path.join(STATIC_DATA_DIR, "topology.json"), topo, master_key_bytes, key_id)

    # 3. Optical Power Scan (encrypted)
    opt_scan = load_optical_scan()
    write_encrypted_json(os.path.join(STATIC_DATA_DIR, "optical_scan.json"), opt_scan, master_key_bytes, key_id)

    # 4. OTDR Folders Summary + Per-Folder Fiber Lists + Individual Fiber Trace JSONs (all encrypted)
    if isinstance(SCANNED_FOLDERS, dict) and SCANNED_FOLDERS and "error" not in SCANNED_FOLDERS:
        folders_summary = get_folders_summary()
        write_encrypted_json(folders_json_path, folders_summary, master_key_bytes, key_id)

        exported_files_count = 0
        for folder_id, folder_data in SCANNED_FOLDERS.items():
            folder_detail = get_folder_fibers(folder_id)
            write_encrypted_json(os.path.join(folders_dir, f"{folder_id}.json"), folder_detail, master_key_bytes, key_id)

            for fiber_entry in folder_data.get("files", []):
                fid = fiber_entry.get("id")
                if not fid:
                    continue
                target_file_json = os.path.join(files_dir, f"{fid}.json")
                try:
                    if not is_already_encrypted_with_kid(target_file_json, key_id):
                        full_fiber = get_file_details(fid)
                        write_encrypted_json(target_file_json, full_fiber, master_key_bytes, key_id)
                    exported_files_count += 1
                except Exception as e:
                    print(f"Skipping static export for fiber {fid}: {e}")
        otdr_folders_count = len(folders_summary)
    else:
        # Ensure any existing static OTDR files are encrypted with current key_id
        otdr_folders_count = 0
        if os.path.exists(folders_json_path):
            try:
                folders_summary = decrypt_or_read_json(folders_json_path, master_key_bytes)
                otdr_folders_count = len(folders_summary) if isinstance(folders_summary, list) else 0
                if not is_already_encrypted_with_kid(folders_json_path, key_id):
                    write_encrypted_json(folders_json_path, folders_summary, master_key_bytes, key_id)
            except Exception as e:
                print(f"Error encrypting folders.json: {e}")

        for fname in os.listdir(folders_dir):
            if fname.endswith(".json"):
                fpath = os.path.join(folders_dir, fname)
                if not is_already_encrypted_with_kid(fpath, key_id):
                    try:
                        obj = decrypt_or_read_json(fpath, master_key_bytes)
                        write_encrypted_json(fpath, obj, master_key_bytes, key_id)
                    except Exception as e:
                        print(f"Error encrypting folder {fname}: {e}")

        exported_files_count = 0
        for fname in os.listdir(files_dir):
            if fname.endswith(".json"):
                exported_files_count += 1
                fpath = os.path.join(files_dir, fname)
                if not is_already_encrypted_with_kid(fpath, key_id):
                    try:
                        obj = decrypt_or_read_json(fpath, master_key_bytes)
                        write_encrypted_json(fpath, obj, master_key_bytes, key_id)
                    except Exception as e:
                        print(f"Error encrypting file {fname}: {e}")

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    meta = {
        "published_at": now_str,
        "encrypted": True,
        "otdr_folders_count": otdr_folders_count,
        "otdr_files_count": exported_files_count,
        "devices_count": len(topo.get("devices", [])),
        "connections_count": len(topo.get("connections", [])),
        "optical_ports_count": len(opt_scan.get("results", [])),
        "optical_scan_updated_at": opt_scan.get("updated_at")
    }
    with open(os.path.join(STATIC_DATA_DIR, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    return meta


@app.post("/api/export-static")
def export_static_endpoint():
    try:
        meta = generate_static_snapshot()
        return {
            "status": "success",
            "message": "Static snapshot generated in frontend/static_data/.",
            "meta": meta
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate static snapshot: {str(e)}")


@app.post("/api/publish-github")
def publish_to_github():
    """
    Generates the latest static snapshot (OTDR data, Topology, Optical Scan)
    and commits + pushes to GitHub origin/main to trigger GitHub Pages deployment.
    """
    import subprocess
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    try:
        meta = generate_static_snapshot()

        # Stage relevant project and encrypted static data files (never stage plaintext backend/data/)
        subprocess.run(
            ["git", "add", "frontend/", "backend/main.py", "backend/parser.py", "backend/scanner.py", ".github/", ".gitignore", "requirements.txt", "Start_Collector_Mac.command", "Start_Collector_Windows.bat", "README.md"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True
        )

        # Check if there are staged changes
        status_proc = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True
        )

        committed = False
        if status_proc.stdout.strip():
            commit_msg = f"Publish dashboard snapshot ({meta['published_at']})"
            subprocess.run(
                ["git", "commit", "-m", commit_msg],
                cwd=repo_root,
                check=True,
                capture_output=True,
                text=True
            )
            committed = True

        push_proc = subprocess.run(
            ["git", "push", "origin", "main"],
            cwd=repo_root,
            capture_output=True,
            text=True
        )
        if push_proc.returncode != 0:
            # Another team member's laptop may have pushed first; merge preferring our latest snapshot and push again
            subprocess.run(
                ["git", "pull", "--no-rebase", "-X", "ours", "origin", "main"],
                cwd=repo_root,
                check=True,
                capture_output=True,
                text=True
            )
            push_proc = subprocess.run(
                ["git", "push", "origin", "main"],
                cwd=repo_root,
                check=True,
                capture_output=True,
                text=True
            )

        # Also publish frontend/ root directly to the gh-pages branch so GitHub Pages works automatically
        tree_proc = subprocess.run(
            ["git", "rev-parse", "HEAD:frontend"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True
        )
        tree_hash = tree_proc.stdout.strip()
        commit_tree_proc = subprocess.run(
            ["git", "commit-tree", tree_hash, "-m", f"Deploy GitHub Pages ({meta['published_at']})"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True
        )
        gh_pages_commit = commit_tree_proc.stdout.strip()
        subprocess.run(
            ["git", "push", "-f", "origin", f"{gh_pages_commit}:refs/heads/gh-pages"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True
        )

        return {
            "status": "success",
            "committed": committed,
            "meta": meta,
            "pages_url": "https://hilmandika.github.io/OSP-Monitoring/",
            "git_output": (push_proc.stdout or push_proc.stderr or "Pushed to origin/main and origin/gh-pages").strip()
        }
    except subprocess.CalledProcessError as git_err:
        err_msg = (git_err.stderr or git_err.stdout or str(git_err)).strip()
        return {
            "status": "partial",
            "message": f"Static snapshot was generated in frontend/static_data/, but Git push encountered an issue: {err_msg}",
            "meta": meta if 'meta' in locals() else None,
            "pages_url": "https://hilmandika.github.io/OSP-Monitoring/"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to publish to GitHub: {str(e)}")


class JumpboxConnectRequest(BaseModel):
    jumpbox_ip: str
    username: str
    password: str

@app.post("/api/console/jumpbox/connect")
def test_jumpbox_connection(req: JumpboxConnectRequest):
    try:
        import paramiko
        jb_client = paramiko.SSHClient()
        jb_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        jb_client.connect(hostname=req.jumpbox_ip, username=req.username, password=req.password, port=22, timeout=15, banner_timeout=30)
        jb_client.close()
        return {
            "status": "success",
            "message": f"Successfully authenticated with Jumpbox gateway at {req.jumpbox_ip}.",
            "is_simulation": False
        }
    except ImportError:
        return {
            "status": "success",
            "message": f"Successfully connected to simulated Jumpbox gateway at {req.jumpbox_ip} (Simulation Mode).",
            "is_simulation": True
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to connect to Jumpbox gateway: {str(e)}",
            "is_simulation": False
        }

@app.websocket("/api/console/ws")
async def websocket_console_endpoint(websocket: WebSocket):
    await websocket.accept()
    import asyncio
    jb_client = None
    shell = None
    
    try:
        # 1. Receive credentials configuration message
        init_data = await websocket.receive_json()
        jb_ip = init_data.get("jumpbox_ip")
        jb_user = init_data.get("jumpbox_username")
        jb_pass = init_data.get("jumpbox_password")
        dev_ip = init_data.get("device_ip")
        dev_user = init_data.get("device_username")
        dev_pass = init_data.get("device_password")
        dev_type = init_data.get("device_type", "Router")
        
        # Check if paramiko is installed
        try:
            import paramiko
            paramiko_available = True
        except ImportError:
            paramiko_available = False
            
        if not paramiko_available:
            # Fallback Simulation Mode
            await websocket.send_json({"type": "status", "data": "SSH: Running in Simulation Mode...\r\n"})
            await websocket.send_json({"type": "status", "data": f"SSH: Connecting to simulated Jumpbox ({jb_ip})...\r\n"})
            await asyncio.sleep(0.4)
            await websocket.send_json({"type": "status", "data": "SSH: Authentication successful.\r\n"})
            await websocket.send_json({"type": "status", "data": f"SSH: Establishing connection to Target ({dev_ip})...\r\n"})
            await asyncio.sleep(0.4)
            
            prompt = f"{dev_ip.split('.')[-1]}#"
            await websocket.send_json({"type": "output", "data": f"Connected successfully to simulated target.\r\n\r\n{prompt} "})
            
            # Execute simulated auto first command if found
            device_brand = init_data.get("device_brand", "")
            device_model = init_data.get("device_model", "")
            auto_commands = ACTIVE_CONFIG.get("auto_commands", {})
            combined_info = f"{device_brand} {device_model}".lower()
            auto_cmd = None
            best_match_len = 0
            for pattern, cmd in auto_commands.items():
                pattern_lower = pattern.lower()
                if pattern_lower in combined_info or pattern_lower in device_brand.lower() or pattern_lower in device_model.lower():
                    if len(pattern) > best_match_len:
                        auto_cmd = cmd
                        best_match_len = len(pattern)
            if auto_cmd:
                await websocket.send_json({"type": "status", "data": f"SSH: Automatically executing initial command: '{auto_cmd}'...\r\n"})
                await websocket.send_json({"type": "output", "data": f"{auto_cmd}\r\n{prompt} "})
            
            while True:
                msg_json = await websocket.receive_json()
                if msg_json.get("type") == "input":
                    cmd_line = msg_json.get("data", "").strip()
                    cmd = cmd_line.lower()
                    
                    if not cmd_line:
                        await websocket.send_json({"type": "output", "data": f"\r\n{prompt} "})
                        continue
                        
                    await websocket.send_json({"type": "output", "data": f"\r\n"})
                    
                    if cmd == "exit":
                        await websocket.send_json({"type": "output", "data": "Connection closed.\r\n"})
                        break
                    elif cmd == "help":
                        output = "Available commands: show version, show ip interface brief, show ip route, show port <port> optical, show pon power, ping <ip>, help, exit\r\n"
                        await websocket.send_json({"type": "output", "data": f"{output}{prompt} "})
                    elif cmd == "show version":
                        if dev_type == "Router":
                            output = "Nokia 7750 Service Router - Version 21.10.R1\r\nSystem Boot Time: 2026-07-01 04:12:10\r\n"
                        else:
                            output = "ZTE C300 GPON OLT - Version 12.1.2\r\nSystem Boot Time: 2026-06-15 10:20:45\r\n"
                        await websocket.send_json({"type": "output", "data": f"{output}{prompt} "})
                    elif cmd in ["show ip interface brief", "show interface description"]:
                        if dev_type == "Router":
                            output = (
                                "Interface             IP-Address      Status     Protocol\r\n"
                                "system                172.30.65.1     up         up\r\n"
                                "to-Aggregation-1      10.10.12.1      up         up\r\n"
                                "to-OLT-Cabinet-4      192.168.4.1     up         up\r\n"
                            )
                        else:
                            output = (
                                "Interface             IP-Address      Status     Protocol\r\n"
                                "mng1                  172.30.70.5     up         up\r\n"
                                "gpon-olt_1/1/1        unassigned      up         up\r\n"
                                "gpon-olt_1/1/2        unassigned      up         up\r\n"
                            )
                        await websocket.send_json({"type": "output", "data": f"{output}{prompt} "})
                    elif "show port" in cmd and "optical" in cmd:
                        port_match = re.search(r'show port\s+([0-9a-zA-Z\/]+)\s+optical', cmd)
                        port_id = port_match.group(1) if port_match else "5/2/9"
                        
                        # Determine if we simulate a 100G multi-lane CFP2 port (e.g. starting with 2/)
                        is_100g = port_id.startswith("2/") or "1/1" in port_id
                        
                        if is_100g:
                            output = (
                                "===============================================================================\r\n"
                                "Optical Interface\r\n"
                                "===============================================================================\r\n"
                                "Transceiver Data\r\n\r\n"
                                "Transceiver Status : operational\r\n"
                                "Transceiver Type   : CFP2                   DCO                  : Disabled\r\n"
                                "Model Number       : 3HE08217AARA01  NOK  IPUIBVJDAA\r\n"
                                "TX Laser Wavelength: 1294 nm                Diag Capable         : yes\r\n"
                                "Number of Lanes    : 4                      \r\n"
                                "Connector Code     : LC                     Vendor OUI           : 00:90:65\r\n"
                                "Manufacture date   : 2022/12/22             Media                : Ethernet\r\n"
                                "Serial Number      : U8SAFXE         \r\n"
                                "Part Number        : FTLC1122RDNL-A5 \r\n"
                                "Optical Compliance : 100GBASE-LR4 \r\n"
                                "Link Length support: 10km for SMF\r\n\r\n"
                                "===============================================================================\r\n"
                                "Transceiver Digital Diagnostic Monitoring (DDM)\r\n"
                                "===============================================================================\r\n"
                                "                              Value High Alarm  High Warn   Low Warn  Low Alarm\r\n"
                                "-------------------------------------------------------------------------------\r\n"
                                "Temperature (C)               +41.3     +70.0      +68.0       +2.0       +0.0 \r\n"
                                "Supply Voltage (V)             3.28      3.46       3.43       3.17       3.13 \r\n"
                                "===============================================================================\r\n\r\n"
                                "===============================================================================\r\n"
                                "Transceiver Lane Digital Diagnostic Monitoring (DDM)\r\n"
                                "===============================================================================\r\n"
                                "                                 High Alarm   High Warn    Low Warn   Low Alarm\r\n"
                                "-------------------------------------------------------------------------------\r\n"
                                "Lane Temperature (C)                  +57.0       +55.0       +27.0       +25.0\r\n"
                                "Lane Tx Bias Current (mA)              70.0        65.0        35.0        30.0\r\n"
                                "Lane Tx Output Power (dBm)             4.50        4.00       -3.80       -4.30\r\n"
                                "Lane Rx Optical Pwr (avg dBm)          4.50        4.00      -13.00      -16.00\r\n\r\n"
                                "-------------------------------------------------------------------------------\r\n"
                                "Lane ID Temp(C)/Alm       Tx Bias(mA)/Alm   Tx Pwr(dBm)/Alm   Rx Pwr(dBm)/Alm \r\n"
                                "-------------------------------------------------------------------------------\r\n"
                            )
                            # Generate simulated levels: default normal, vary for alarm warning test coverage
                            rx_levels = [0.58, 0.91, -0.03, 0.05]
                            try:
                                digits = [int(s) for s in re.findall(r'\d+', port_id)]
                                if digits and (sum(digits) % 5 == 0):
                                    rx_levels = [0.58, 0.91, -14.20, 0.05] # Low Warning
                                elif digits and (sum(digits) % 5 == 1):
                                    rx_levels = [0.58, 0.91, -17.50, 0.05] # Low Alarm
                            except Exception:
                                pass
                                
                            output += f"    1          +49.9              51.5              0.55              {rx_levels[0]:.2f}     \r\n"
                            output += f"    2          +49.9              49.8              0.63              {rx_levels[1]:.2f}     \r\n"
                            output += f"    3          +49.9              49.9              1.01             {rx_levels[2]:.2f}     \r\n"
                            output += f"    4          +49.9              49.8              1.17              {rx_levels[3]:.2f}     \r\n"
                            output += "===============================================================================\r\n"
                        else:
                            # Vary simulated optical power based on port digits for realistic warning states
                            rx_val = -4.12
                            try:
                                digits = [int(s) for s in re.findall(r'\d+', port_id)]
                                if digits:
                                    rx_val = -3.5 - (sum(digits) % 15) * 1.3
                            except Exception:
                                pass
                                
                            output = (
                                "===============================================================================\r\n"
                                f"Transceiver Digital Diagnostic Monitoring (DDM), Port {port_id}\r\n"
                                "===============================================================================\r\n"
                                "                              Value High Alarm  High Warn   Low Warn  Low Alarm\r\n"
                                "-------------------------------------------------------------------------------\r\n"
                                "Temperature (C)               +32.4     +75.0      +70.0       -5.0      -10.0\r\n"
                                "Supply Voltage (V)             3.29      3.63       3.47       3.13       2.97\r\n"
                                "Tx Bias Current (mA)           35.2      90.0       80.0       10.0        5.0\r\n"
                                "Tx Output Power (dBm)         -2.45     +1.00      -1.00      -8.00     -10.00\r\n"
                                f"Rx Optical Power (dBm)        {rx_val:.2f}     -1.00      -3.00     -18.00     -20.00\r\n"
                                "===============================================================================\r\n"
                            )
                        await websocket.send_json({"type": "output", "data": f"{output}{prompt} "})
                    elif "show pon power" in cmd or "pon power" in cmd:
                        output = (
                            "OLT RX PON Power Diagnostics:\r\n"
                            "--------------------------------------------------\r\n"
                            "PON Port        ONU ID   RxPower(dBm)  Distance(m)  Status\r\n"
                            "gpon_olt-1/1/1  1        -19.45        1254         online\r\n"
                            "gpon_olt-1/1/1  2        -21.12        2410         online\r\n"
                            "gpon_olt-1/1/1  3        -18.90        850          online\r\n"
                            "--------------------------------------------------\r\n"
                        )
                        await websocket.send_json({"type": "output", "data": f"{output}{prompt} "})
                    elif cmd.startswith("ping "):
                        target_ping = cmd_line.split(" ")[1] if len(cmd_line.split(" ")) > 1 else "8.8.8.8"
                        output = (
                            f"PING {target_ping} ({target_ping}): 56 data bytes\r\n"
                            f"64 bytes from {target_ping}: icmp_seq=0 ttl=64 time=4.32 ms\r\n"
                            f"64 bytes from {target_ping}: icmp_seq=1 ttl=64 time=4.11 ms\r\n"
                            f"64 bytes from {target_ping}: icmp_seq=2 ttl=64 time=4.25 ms\r\n"
                            f"\r\n--- {target_ping} ping statistics ---\r\n"
                            "3 packets transmitted, 3 packets received, 0% packet loss\r\n"
                            "round-trip min/avg/max = 4.11/4.22/4.32 ms\r\n"
                        )
                        await websocket.send_json({"type": "output", "data": f"{output}{prompt} "})
                    else:
                        output = f"Command executed: '{cmd_line}'\r\n(Simulated Output - Paramiko is not installed)\r\n"
                        await websocket.send_json({"type": "output", "data": f"{output}{prompt} "})
            return

        # Real SSH Connection via Jumpbox
        await websocket.send_json({"type": "status", "data": f"SSH: Connecting to Jumpbox ({jb_ip})...\r\n"})
        jb_client = paramiko.SSHClient()
        jb_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            jb_client.connect(hostname=jb_ip, username=jb_user, password=jb_pass, port=22, timeout=15, banner_timeout=30)
        except Exception as e:
            await websocket.send_json({"type": "error", "data": f"Failed to connect to Jumpbox gateway: {str(e)}"})
            await websocket.close()
            return
            
        await websocket.send_json({"type": "status", "data": "SSH: Connected successfully to Jumpbox. Initiating SSH shell to Target Device...\r\n"})
        
        # Invoke interactive shell
        shell = jb_client.invoke_shell(width=120, height=40)
        shell.setblocking(0)
        
        await asyncio.sleep(0.5)
        if shell.recv_ready():
            shell.recv(4096)
            
        # Check SSH Rules overrides
        device_brand = init_data.get("device_brand", "")
        device_model = init_data.get("device_model", "")
        combined_info = f"{device_brand} {device_model}".lower()
        
        ssh_rules = ACTIVE_CONFIG.get("ssh_rules", {})
        ssh_cmd_template = "ssh {ip}"
        best_match_len = 0
        for pattern, template in ssh_rules.items():
            pattern_lower = pattern.lower()
            if pattern_lower in combined_info or pattern_lower in device_brand.lower() or pattern_lower in device_model.lower():
                if len(pattern) > best_match_len:
                    ssh_cmd_template = template
                    best_match_len = len(pattern)
        
        target_ssh_cmd = ssh_cmd_template.replace("{ip}", dev_ip)
        shell.send(f"{target_ssh_cmd}\n")
        
        # Wait for password prompt
        password_prompted = False
        buffer = ""
        start_time = asyncio.get_event_loop().time()
        while asyncio.get_event_loop().time() - start_time < 10:
            try:
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode('utf-8', errors='replace')
                    buffer += chunk
                    await websocket.send_json({"type": "output", "data": chunk})
                    if "continue connecting" in chunk.lower() or "yes/no" in chunk.lower():
                        shell.send("yes\n")
                    if "password:" in chunk.lower():
                        password_prompted = True
                        break
                    if "connection refused" in chunk.lower() or "connection timed out" in chunk.lower() or "host unreachable" in chunk.lower():
                        await websocket.send_json({"type": "error", "data": f"Connection error from jumpbox to device:\r\n{buffer}"})
                        shell.close()
                        jb_client.close()
                        await websocket.close()
                        return
            except Exception:
                pass
            await asyncio.sleep(0.1)
            
        if not password_prompted:
            await websocket.send_json({"type": "error", "data": f"Timeout waiting for target device password prompt. Buffer:\r\n{buffer}"})
            shell.close()
            jb_client.close()
            await websocket.close()
            return
            
        # Send target password
        shell.send(f"{dev_pass}\n")
        
        # Wait for target prompt
        logged_in = False
        buffer = ""
        start_time = asyncio.get_event_loop().time()
        while asyncio.get_event_loop().time() - start_time < 10:
            try:
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode('utf-8', errors='replace')
                    buffer += chunk
                    await websocket.send_json({"type": "output", "data": chunk})
                    clean_chunk = chunk.strip()
                    if clean_chunk and clean_chunk[-1] in ["#", ">", "$"]:
                        logged_in = True
                        break
            except Exception:
                pass
            await asyncio.sleep(0.1)
            
        if not logged_in:
            await websocket.send_json({"type": "error", "data": f"Failed to authenticate with target device. Buffer:\r\n{buffer}"})
            shell.close()
            jb_client.close()
            await websocket.close()
            return
            
        # Execute auto first command if found
        auto_cmd = None
        device_brand = init_data.get("device_brand", "")
        device_model = init_data.get("device_model", "")
        auto_commands = ACTIVE_CONFIG.get("auto_commands", {})
        combined_info = f"{device_brand} {device_model}".lower()
        best_match_len = 0
        for pattern, cmd in auto_commands.items():
            pattern_lower = pattern.lower()
            if pattern_lower in combined_info or pattern_lower in device_brand.lower() or pattern_lower in device_model.lower():
                if len(pattern) > best_match_len:
                    auto_cmd = cmd
                    best_match_len = len(pattern)
        if auto_cmd:
            await websocket.send_json({"type": "status", "data": f"SSH: Automatically executing initial command: '{auto_cmd}'...\r\n"})
            shell.send(auto_cmd + "\n")
            # Wait a moment for command execution to complete and show prompt
            await asyncio.sleep(0.3)
            
        # Success! Start bi-directional loop
        async def read_from_ssh():
            while True:
                try:
                    if shell.recv_ready():
                        data = shell.recv(4096).decode('utf-8', errors='replace')
                        if data:
                            await websocket.send_json({"type": "output", "data": data})
                except Exception:
                    pass
                await asyncio.sleep(0.05)
                
        read_task = asyncio.create_task(read_from_ssh())
        
        try:
            while True:
                client_msg = await websocket.receive_json()
                if client_msg.get("type") == "input":
                    cmd_data = client_msg.get("data", "")
                    shell.send(cmd_data)
        except WebSocketDisconnect:
            pass
        finally:
            read_task.cancel()
            
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "data": f"SSH connection execution error: {str(e)}"})
        except Exception:
            pass
    finally:
        if shell:
            try:
                shell.send("exit\n")
                await asyncio.sleep(0.1)
                shell.send("exit\n")
                await asyncio.sleep(0.1)
                shell.close()
            except Exception:
                pass
        if jb_client:
            try:
                jb_client.close()
            except Exception:
                pass
        try:
            await websocket.close()
        except Exception:
            pass

@app.post("/api/console/command")
def execute_console_command(req: CommandRequest):
    try:
        # Check if paramiko is installed
        import paramiko
        # Try real SSH connection
        import time
        jb_client = paramiko.SSHClient()
        jb_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect to jumpbox
        try:
            jb_client.connect(hostname=req.jumpbox_ip, username=req.jumpbox_username, password=req.jumpbox_password, port=22, timeout=15, banner_timeout=30)
        except Exception as jb_err:
            return {
                "status": "error",
                "message": f"Failed to connect to Jumpbox ({req.jumpbox_ip}): {str(jb_err)}",
                "output": "",
                "is_simulation": False
            }
            
        # Connect to target through interactive shell on jumpbox
        try:
            shell = jb_client.invoke_shell(width=120, height=40)
            time.sleep(0.5)
            
            # Clear initial shell message
            if shell.recv_ready():
                shell.recv(4096)
                
            # Check SSH Rules overrides
            device_brand = req.device_brand or ""
            device_model = req.device_model or ""
            combined_info = f"{device_brand} {device_model}".lower()
            
            ssh_rules = ACTIVE_CONFIG.get("ssh_rules", {})
            ssh_cmd_template = "ssh {ip}"
            best_match_len = 0
            for pattern, template in ssh_rules.items():
                pattern_lower = pattern.lower()
                if pattern_lower in combined_info or pattern_lower in device_brand.lower() or pattern_lower in device_model.lower():
                    if len(pattern) > best_match_len:
                        ssh_cmd_template = template
                        best_match_len = len(pattern)
            
            target_ssh_cmd = ssh_cmd_template.replace("{ip}", req.device_ip)
            shell.send(f"{target_ssh_cmd}\n")
            
            # Wait for password prompt
            password_prompted = False
            buffer = ""
            start_time = time.time()
            while time.time() - start_time < 10:
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode('utf-8', errors='replace')
                    buffer += chunk
                    if "continue connecting" in chunk.lower() or "yes/no" in chunk.lower():
                        shell.send("yes\n")
                    if "password:" in chunk.lower():
                        password_prompted = True
                        break
                    if "connection refused" in chunk.lower() or "connection timed out" in chunk.lower() or "host unreachable" in chunk.lower():
                        jb_client.close()
                        return {
                            "status": "error",
                            "message": f"Connection error from jumpbox to device: {buffer}",
                            "output": "",
                            "is_simulation": False
                        }
                time.sleep(0.1)
                
            if not password_prompted:
                jb_client.close()
                return {
                    "status": "error",
                    "message": f"Timeout waiting for target device password prompt. Buffer:\n{buffer}",
                    "output": "",
                    "is_simulation": False
                }
                
            # Send target password
            shell.send(f"{req.device_password}\n")
            
            # Wait for device prompt
            logged_in = False
            buffer = ""
            start_time = time.time()
            while time.time() - start_time < 10:
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode('utf-8', errors='replace')
                    buffer += chunk
                    if any(p in chunk for p in ["#", ">", "]", "$"]):
                        if "password" not in chunk.lower():
                            logged_in = True
                            break
                time.sleep(0.1)
                
            if not logged_in:
                jb_client.close()
                return {
                    "status": "error",
                    "message": f"Failed to authenticate with target device. Buffer:\n{buffer}",
                    "output": "",
                    "is_simulation": False
                }
                
            # Clear intermediate shell login text buffer
            time.sleep(0.2)
            if shell.recv_ready():
                shell.recv(4096)
                
            # Send command
            shell.send(f"{req.command}\n")
            
            # Read output
            time.sleep(1.5)
            output_buffer = ""
            start_time = time.time()
            while time.time() - start_time < 5:
                if shell.recv_ready():
                    chunk = shell.recv(8192).decode('utf-8', errors='replace')
                    output_buffer += chunk
                    if any(p in chunk for p in ["#", ">"]):
                        time.sleep(0.1)
                        if shell.recv_ready():
                            output_buffer += shell.recv(8192).decode('utf-8', errors='replace')
                        break
                else:
                    time.sleep(0.1)
                    
            # Cleanup exit
            shell.send("exit\n")
            time.sleep(0.2)
            shell.send("exit\n")
            time.sleep(0.1)
            
            shell.close()
            jb_client.close()
            
            return {
                "status": "success",
                "output": output_buffer,
                "is_simulation": False
            }
            
        except Exception as e:
            jb_client.close()
            return {
                "status": "error",
                "message": f"Interactive SSH execution error: {str(e)}",
                "output": "",
                "is_simulation": False
            }
            
    except ImportError:
        # Fallback simulation mode
        # Return realistic responses for basic router/OLT commands
        cmd = req.command.strip().lower()
        output = ""
        
        # Simulate connection flow log prefix
        conn_log = f"SSH: Connecting to Jumpbox ({req.jumpbox_ip})...\n"
        conn_log += "SSH: Authentication successful.\n"
        conn_log += f"SSH: Establishing tunnel to Target ({req.device_ip})...\n"
        conn_log += "SSH: Connected successfully to target device.\n\n"
        
        if cmd == "show version":
            if req.device_type == "Router":
                output = (
                    "Nokia 7750 Service Router - Version 21.10.R1\n"
                    "Copyright (c) 2001-2026 Nokia. All rights reserved.\n"
                    "System Boot Time: 2026-07-01 04:12:10\n"
                )
            else:
                output = (
                    "ZTE C300 GPON OLT - Version 12.1.2\n"
                    "Copyright (c) ZTE Corp. All rights reserved.\n"
                    "System Boot Time: 2026-06-15 10:20:45\n"
                )
        elif cmd in ["show ip interface brief", "show interface description"]:
            if req.device_type == "Router":
                output = (
                    "Interface             IP-Address      Status     Protocol\n"
                    "system                172.30.65.1     up         up\n"
                    "to-Aggregation-1      10.10.12.1      up         up\n"
                    "to-OLT-Cabinet-4      192.168.4.1     up         up\n"
                )
            else:
                output = (
                    "Interface             IP-Address      Status     Protocol\n"
                    "mng1                  172.30.70.5     up         up\n"
                    "gpon-olt_1/1/1        unassigned      up         up\n"
                    "gpon-olt_1/1/2        unassigned      up         up\n"
                )
        elif cmd in ["show route", "show ip route"]:
            output = (
                "Route Table: Base\n"
                "Dest/Prefix          Type      Proto     Age       NextHop\n"
                "0.0.0.0/0            Active    Static    45d12h    172.30.65.254\n"
                f"172.30.65.0/24       Active    Local     45d12h    {req.device_ip}\n"
            )
        elif cmd.startswith("ping "):
            target_ping = cmd.split(" ")[1] if len(cmd.split(" ")) > 1 else "8.8.8.8"
            output = (
                f"PING {target_ping} ({target_ping}): 56 data bytes\n"
                f"64 bytes from {target_ping}: icmp_seq=0 ttl=64 time=4.32 ms\n"
                f"64 bytes from {target_ping}: icmp_seq=1 ttl=64 time=4.11 ms\n"
                f"64 bytes from {target_ping}: icmp_seq=2 ttl=64 time=4.25 ms\n"
                f"\n--- {target_ping} ping statistics ---\n"
                "3 packets transmitted, 3 packets received, 0% packet loss\n"
                "round-trip min/avg/max = 4.11/4.22/4.32 ms\n"
            )
        elif "show port" in cmd and "optical" in cmd:
            port_match = re.search(r'show port\s+([0-9a-zA-Z\/]+)\s+optical', cmd)
            port_id = port_match.group(1) if port_match else "5/2/9"
            output = (
                "===============================================================================\n"
                f"Transceiver Digital Diagnostic Monitoring (DDM), Port {port_id}\n"
                "===============================================================================\n"
                "                              Value High Alarm  High Warn   Low Warn  Low Alarm\n"
                "-------------------------------------------------------------------------------\n"
                "Temperature (C)               +32.4     +75.0      +70.0       -5.0      -10.0\n"
                "Supply Voltage (V)             3.29      3.63       3.47       3.13       2.97\n"
                "Tx Bias Current (mA)           35.2      90.0       80.0       10.0        5.0\n"
                "Tx Output Power (dBm)         -2.45     +1.00      -1.00      -8.00     -10.00\n"
                "Rx Optical Power (dBm)        -4.12     -1.00      -3.00     -18.00     -20.00\n"
                "===============================================================================\n"
            )
        elif "show pon power" in cmd or "pon power" in cmd:
            output = (
                "OLT RX PON Power Diagnostics:\n"
                "--------------------------------------------------\n"
                "PON Port        ONU ID   RxPower(dBm)  Distance(m)  Status\n"
                "gpon_olt-1/1/1  1        -19.45        1254         online\n"
                "gpon_olt-1/1/1  2        -21.12        2410         online\n"
                "gpon_olt-1/1/1  3        -18.90        850          online\n"
                "--------------------------------------------------\n"
            )
        elif cmd == "exit":
            output = "Connection closed by foreign host.\n"
        elif cmd == "help":
            output = "Available commands: show version, show ip interface brief, show ip route, show port <port> optical, show pon power, ping <ip>, help, exit\n"
        else:
            output = f"Command executed: '{req.command}'\n(Simulated Output - Paramiko is not installed)\n"
            
        return {
            "status": "success",
            "output": conn_log + output,
            "is_simulation": True
        }
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
