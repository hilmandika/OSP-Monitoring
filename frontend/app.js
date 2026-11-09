/* ==========================================================================
   OTDR Core Analytics - Frontend JS Application Controller
   ========================================================================== */

const API_BASE = "/api";

// App Global State
let appState = {
    isStaticMode: window.location.hostname.endsWith("github.io"),
    staticMeta: null,
    settings: {
        last_scan_path: "./otdr_data_samples",
        thresholds: {}
    },
    activeFolders: [],
    selectedMonthYear: "all",
    currentFolder: null, // { folder_name: "", absolute_path: "", fibers: [] }
    selectedFiberIds: new Set(), // Set of fiber IDs selected for multi-trace overlay
    searchQuery: "",
    filterStatus: "all",
    filterWavelength: "all",
    sortColumn: "fiber_id",
    sortDirection: "asc", // 'asc' or 'desc'
    lockYAxis: true,
    currentModalFile: null,

    // NMS Global State
    nms: {
        devices: [],
        connections: [],
        activeTab: "devices", // "devices" or "connections"
        selectedNodeId: null,
        zoom: 1,
        pan: { x: 0, y: 0 },
        draggedNode: null,
        dragStartPos: { x: 0, y: 0 },
        isPanning: false,
        panStart: { x: 0, y: 0 },
        hasChanges: false,
        layoutMode: "geo", // "logical" or "geo"
        editModeEnabled: false
    }
};

// DOM Elements Cache
const elements = {
    scanPathInput: document.getElementById("scan-path-input"),
    scanBtn: document.getElementById("scan-btn"),
    settingsToggleBtn: document.getElementById("settings-toggle-btn"),
    settingsDrawer: document.getElementById("settings-drawer"),
    closeSettingsBtn: document.getElementById("close-settings-btn"),
    drawerBackdrop: document.getElementById("drawer-backdrop"),
    saveSettingsBtn: document.getElementById("save-settings-btn"),
    
    // Settings inputs
    setSplice: document.getElementById("set-max-splice"),
    setConnector: document.getElementById("set-max-connector"),
    setAtt1310: document.getElementById("set-max-att-1310"),
    setAtt1550: document.getElementById("set-max-att-1550"),
    setTotalLoss: document.getElementById("set-max-total-loss"),
    
    // View Panels
    loader: document.getElementById("global-loader"),
    folderGridView: document.getElementById("folder-grid-view"),
    foldersGrid: document.getElementById("folders-grid"),
    monthYearFilter: document.getElementById("month-year-filter"),
    
    folderDetailView: document.getElementById("folder-detail-view"),
    backToGridBtn: document.getElementById("back-to-grid-btn"),
    currentFolderTitle: document.getElementById("current-folder-title"),
    currentFolderPath: document.getElementById("current-folder-path"),
    
    // Stats Ribbon
    statTotal: document.getElementById("stat-total-fibers"),
    statPassed: document.getElementById("stat-passed-fibers"),
    statFailed: document.getElementById("stat-failed-fibers"),
    statAvgAtt: document.getElementById("stat-avg-attenuation"),
    
    // Tabs & Filters
    tabBtns: document.querySelectorAll(".tab-btn"),
    tabPanels: document.querySelectorAll(".tab-panel"),
    overlayCount: document.getElementById("overlay-count"),
    fiberSearch: document.getElementById("fiber-search-input"),
    filterStatusSelect: document.getElementById("filter-status"),
    filterWavelengthSelect: document.getElementById("filter-wavelength"),
    csvExportBtn: document.getElementById("csv-export-btn"),
    fibersTableBody: document.getElementById("fibers-table-body"),
    selectAllFibers: document.getElementById("select-all-fibers"),
    
    // Overlay list
    overlayList: document.getElementById("overlay-list-items"),
    sharedEventsList: document.getElementById("shared-events-list"),
    alignmentsTableBody: document.getElementById("alignments-table-body"),
    alignMinLoss: document.getElementById("align-min-loss"),
    lockYAxisOverlay: document.getElementById("lock-y-axis-overlay"),
    
    // Detailed Modal Dialog
    fiberModal: document.getElementById("fiber-modal"),
    closeModalBtn: document.getElementById("close-modal-btn"),
    closeModalXBtn: document.getElementById("close-modal-x-btn"),
    pdfReportBtn: document.getElementById("pdf-report-btn"),
    eventsTableBody: document.getElementById("events-table-body"),
    modalFiberTitle: document.getElementById("modal-fiber-title"),
    modalTagWavelength: document.getElementById("modal-tag-wavelength"),
    modalBadgeStatus: document.getElementById("modal-badge-status"),
    modalFailureReasons: document.getElementById("modal-failure-reasons"),
    lockYAxisModal: document.getElementById("lock-y-axis-modal")
};

/* ==========================================================================
   GitHub Pages / Static Presentation Mode Interceptor, AES-256 Auth & Publisher
   ========================================================================== */
const _nativeFetch = window.fetch.bind(window);
let _staticMasterKey = null;
let _staticAuthPromise = null;

function jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { "Content-Type": "application/json" }
    });
}

function b64ToBytes(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
        bytes[i] = bin.charCodeAt(i);
    }
    return bytes;
}

function bytesToB64(bytes) {
    let bin = "";
    const u8 = new Uint8Array(bytes);
    for (let i = 0; i < u8.length; i++) {
        bin += String.fromCharCode(u8[i]);
    }
    return btoa(bin);
}

async function importMasterKeyFromBytes(rawBytes) {
    return crypto.subtle.importKey(
        "raw",
        rawBytes,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
    );
}

async function tryUnlockWithCredentials(username, password) {
    const manifestRes = await _nativeFetch("./static_data/auth_manifest.json?t=" + Date.now());
    if (!manifestRes.ok) {
        throw new Error("Authentication manifest not found.");
    }
    const manifest = await manifestRes.json();
    const uname = (username || "").trim().toLowerCase();
    const slot = (manifest.users || []).find(u => u.username === uname);
    if (!slot) {
        throw new Error("Invalid username or password.");
    }

    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    const wrappingKey = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: b64ToBytes(slot.salt),
            iterations: slot.iterations || 100000,
            hash: "SHA-256"
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
    );

    try {
        const rawMasterBuf = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: b64ToBytes(slot.iv) },
            wrappingKey,
            b64ToBytes(slot.wrapped_key)
        );
        const masterKey = await importMasterKeyFromBytes(rawMasterBuf);
        sessionStorage.setItem("osp_static_mk_b64", bytesToB64(rawMasterBuf));
        sessionStorage.setItem("osp_static_user", uname);
        return masterKey;
    } catch (e) {
        throw new Error("Invalid username or password.");
    }
}

async function ensureStaticAuthenticated() {
    if (_staticMasterKey) return _staticMasterKey;

    // Check if already unlocked in current browser tab session
    const savedB64 = sessionStorage.getItem("osp_static_mk_b64");
    if (savedB64) {
        try {
            _staticMasterKey = await importMasterKeyFromBytes(b64ToBytes(savedB64));
            const logoutBtn = document.getElementById("static-logout-btn");
            if (logoutBtn) logoutBtn.classList.remove("hidden");
            return _staticMasterKey;
        } catch (e) {
            sessionStorage.removeItem("osp_static_mk_b64");
        }
    }

    if (_staticAuthPromise) return _staticAuthPromise;

    _staticAuthPromise = new Promise((resolve) => {
        const overlay = document.getElementById("static-login-overlay");
        const form = document.getElementById("static-login-form");
        const userInp = document.getElementById("static-login-user");
        const passInp = document.getElementById("static-login-pass");
        const errBox = document.getElementById("static-login-error");
        const submitBtn = document.getElementById("static-login-submit-btn");

        if (overlay) overlay.classList.remove("hidden");
        if (userInp) setTimeout(() => userInp.focus(), 50);

        const onSubmit = async (e) => {
            e.preventDefault();
            if (errBox) errBox.classList.add("hidden");
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> <span>Verifying...</span>';
            }
            try {
                const mk = await tryUnlockWithCredentials(userInp.value, passInp.value);
                _staticMasterKey = mk;
                if (overlay) overlay.classList.add("hidden");
                const logoutBtn = document.getElementById("static-logout-btn");
                if (logoutBtn) logoutBtn.classList.remove("hidden");
                form.removeEventListener("submit", onSubmit);
                _staticAuthPromise = null;
                resolve(mk);
            } catch (err) {
                if (errBox) {
                    errBox.innerText = err.message || "Invalid username or password.";
                    errBox.classList.remove("hidden");
                }
            } finally {
                if (submitBtn) {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = '<i class="fa-solid fa-unlock-keyhole"></i> <span>Unlock Dashboard</span>';
                }
            }
        };

        if (form) {
            form.addEventListener("submit", onSubmit);
        }
    });

    return _staticAuthPromise;
}

async function fetchAndDecryptStaticJson(urlPath) {
    const res = await _nativeFetch(urlPath);
    if (!res.ok) return res;

    const data = await res.json();
    if (data && data.enc === true && data.iv && data.ct) {
        const mk = await ensureStaticAuthenticated();
        try {
            const ptBuf = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: b64ToBytes(data.iv) },
                mk,
                b64ToBytes(data.ct)
            );
            const decText = new TextDecoder().decode(ptBuf);
            return jsonResponse(JSON.parse(decText), 200);
        } catch (decErr) {
            // Session key may be stale if master key rotated; clear session and prompt login
            sessionStorage.removeItem("osp_static_mk_b64");
            _staticMasterKey = null;
            const freshMk = await ensureStaticAuthenticated();
            const ptBuf = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: b64ToBytes(data.iv) },
                freshMk,
                b64ToBytes(data.ct)
            );
            const decText = new TextDecoder().decode(ptBuf);
            return jsonResponse(JSON.parse(decText), 200);
        }
    }
    return jsonResponse(data, 200);
}

async function enableStaticPresentationMode() {
    if (!appState.isStaticMode) {
        appState.isStaticMode = true;
    }
    const publishBtn = document.getElementById("publish-github-btn");
    const pagesAuthBtn = document.getElementById("pages-auth-btn");
    const staticBadge = document.getElementById("static-mode-badge");
    const staticText = document.getElementById("static-mode-text");
    const scannerBar = document.getElementById("otdr-scanner-bar");

    if (publishBtn) publishBtn.classList.add("hidden");
    if (pagesAuthBtn) pagesAuthBtn.classList.add("hidden");
    if (scannerBar) scannerBar.classList.add("hidden");

    // Transform the Console tab into a clean "Optical Power Report" view on GitHub Pages
    const navConsoleBtn = document.getElementById("nav-console-btn");
    const consoleViewTitle = document.getElementById("console-view-title");
    const consoleViewDesc = document.getElementById("console-view-desc");
    const jbUpperRow = document.getElementById("console-jb-upper-row");
    const leftPanel = document.getElementById("console-left-panel");
    const termHeader = document.getElementById("console-terminal-header");
    const termScreen = document.getElementById("console-terminal-screen");
    const termInputRow = document.getElementById("console-input-row");
    const closeDiagBtn = document.getElementById("console-close-diagnostics-btn");
    const diagCardEl = document.getElementById("console-diagnostics-card");
    const diagTableWrap = document.getElementById("console-diagnostics-table-wrapper");

    if (navConsoleBtn) {
        navConsoleBtn.innerHTML = '<i class="fa-solid fa-square-poll-horizontal"></i> <span>Optical Power Report</span>';
    }
    if (consoleViewTitle) {
        consoleViewTitle.innerHTML = '<i class="fa-solid fa-square-poll-horizontal"></i> Optical Power Report';
    }
    if (consoleViewDesc) {
        consoleViewDesc.innerText = "Snapshot of router connection optical transceiver Rx power levels and DDM thresholds.";
    }
    if (jbUpperRow) jbUpperRow.style.display = "none";
    if (leftPanel) leftPanel.style.display = "none";
    if (termHeader) termHeader.style.display = "none";
    if (termScreen) termScreen.style.display = "none";
    if (termInputRow) termInputRow.style.display = "none";
    if (closeDiagBtn) closeDiagBtn.style.display = "none";
    if (diagCardEl) {
        diagCardEl.classList.remove("hidden");
        diagCardEl.style.maxHeight = "none";
        diagCardEl.style.flex = "1";
        diagCardEl.style.borderTop = "none";
    }
    if (diagTableWrap) {
        diagTableWrap.style.maxHeight = "none";
        diagTableWrap.style.flex = "1";
    }
    if (staticBadge) {
        staticBadge.classList.remove("hidden");
        try {
            const metaRes = await _nativeFetch("./static_data/meta.json");
            if (metaRes.ok) {
                const meta = await metaRes.json();
                appState.staticMeta = meta;
                if (staticText && meta.published_at) {
                    const userStr = sessionStorage.getItem("osp_static_user");
                    staticText.innerText = userStr ? `${userStr} • ${meta.published_at}` : `Snapshot: ${meta.published_at}`;
                }
            }
        } catch (e) {
            // Ignore meta fetch error
        }
    }
}

async function handleStaticApiFallback(urlStr, options = {}) {
    await enableStaticPresentationMode();
    const method = (options.method || "GET").toUpperCase();

    // Parse endpoint path after /api
    const apiIdx = urlStr.indexOf("/api/");
    const endpoint = apiIdx !== -1 ? urlStr.slice(apiIdx + 4) : urlStr;

    if (method === "GET") {
        if (endpoint === "/settings") {
            return fetchAndDecryptStaticJson("./static_data/settings.json");
        }
        if (endpoint === "/folders") {
            return fetchAndDecryptStaticJson("./static_data/folders.json");
        }
        const folderMatch = endpoint.match(/^\/folders\/([^\/]+)\/fibers$/);
        if (folderMatch) {
            return fetchAndDecryptStaticJson(`./static_data/folders/${folderMatch[1]}.json`);
        }
        const fileMatch = endpoint.match(/^\/files\/([^\/]+)$/);
        if (fileMatch) {
            return fetchAndDecryptStaticJson(`./static_data/files/${fileMatch[1]}.json`);
        }
        if (endpoint === "/topology") {
            await ensureStaticAuthenticated();
            return fetchAndDecryptStaticJson("./static_data/topology.json");
        }
        if (endpoint === "/console/optical-scan") {
            return fetchAndDecryptStaticJson("./static_data/optical_scan.json");
        }
        if (endpoint === "/console/settings" || endpoint === "/console/auto-commands" || endpoint === "/console/ssh-rules") {
            const res = await fetchAndDecryptStaticJson("./static_data/settings.json");
            if (res.ok) {
                const cfg = await res.json();
                if (endpoint === "/console/settings") {
                    return jsonResponse(cfg.jumpbox || { router_ip: "10.60.190.15", olt_ip: "10.60.190.16" });
                }
                if (endpoint === "/console/auto-commands") {
                    return jsonResponse(cfg.auto_commands || {});
                }
                if (endpoint === "/console/ssh-rules") {
                    return jsonResponse(cfg.ssh_rules || {});
                }
            }
            return jsonResponse({});
        }
    } else if (method === "POST") {
        if (endpoint === "/settings" && options.body) {
            try {
                const newThresholds = JSON.parse(options.body);
                appState.settings.thresholds = newThresholds;
                return jsonResponse({ message: "Updated in browser memory (Static Mode)", config: appState.settings });
            } catch (e) {}
        }
        if (endpoint === "/topology" && options.body) {
            localStorage.setItem("osp_static_topology", options.body);
            return jsonResponse({ status: "success", message: "Saved in browser localStorage (Static Mode)." });
        }
        if (endpoint === "/console/jumpbox/connect") {
            return jsonResponse({
                status: "success",
                message: "Connected to simulated Jumpbox (GitHub Pages Static Mode).",
                is_simulation: true
            });
        }
        return jsonResponse({ status: "success", is_simulation: true });
    }

    return jsonResponse({ error: "Not available in static presentation mode" }, 404);
}

window.fetch = async function(input, options) {
    const urlStr = typeof input === "string" ? input : (input && input.url ? input.url : "");
    if (urlStr.includes("/api/")) {
        if (appState.isStaticMode) {
            return handleStaticApiFallback(urlStr, options);
        }
        try {
            const response = await _nativeFetch(input, options);
            // If served by a static server (e.g. GitHub Pages or python -m http.server) that returns 404/405 for /api/settings
            if ((response.status === 404 || response.status === 405) && (urlStr.endsWith("/api/settings") || urlStr.endsWith("/api/folders") || urlStr.endsWith("/api/topology"))) {
                return handleStaticApiFallback(urlStr, options);
            }
            return response;
        } catch (networkErr) {
            return handleStaticApiFallback(urlStr, options);
        }
    }
    return _nativeFetch(input, options);
};

async function handlePublishToGitHub() {
    const publishBtn = document.getElementById("publish-github-btn");
    if (!publishBtn || publishBtn.disabled) return;

    const originalHtml = publishBtn.innerHTML;
    publishBtn.disabled = true;
    publishBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> <span>Publishing...</span>';

    try {
        const res = await _nativeFetch(`${API_BASE}/publish-github`, {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });
        const data = await res.json();
        if (!res.ok) {
            throw new Error(data.detail || "Failed to publish snapshot.");
        }

        const m = data.meta || {};
        const summaryLines = [
            `Snapshot Timestamp: ${m.published_at || "-"} (AES-256 Encrypted)`,
            `• OTDR Data: ${m.otdr_folders_count || 0} cable folders (${m.otdr_files_count || 0} fiber traces)`,
            `• Network Topology: ${m.devices_count || 0} devices & ${m.connections_count || 0} links`,
            `• Optical Power Report: ${m.optical_ports_count || 0} scanned ports`
        ].join("\n");

        if (data.status === "success") {
            alert(
                `Successfully published encrypted snapshot to GitHub Pages!\n\n${summaryLines}\n\n` +
                `Live URL:\n${data.pages_url}`
            );
        } else {
            alert(
                `Encrypted static snapshot generated locally!\n\n${summaryLines}\n\n` +
                `Note: ${data.message}`
            );
        }
    } catch (err) {
        alert(`Publish error: ${err.message}`);
        console.error("Publish to GitHub error:", err);
    } finally {
        publishBtn.disabled = false;
        publishBtn.innerHTML = originalHtml;
    }
}

function initPagesAuthModal() {
    const openBtn = document.getElementById("pages-auth-btn");
    const modal = document.getElementById("pages-auth-modal");
    const closeX = document.getElementById("pages-auth-close-x-btn");
    const cancelBtn = document.getElementById("pages-auth-cancel-btn");
    const saveBtn = document.getElementById("pages-auth-save-btn");
    const addBtn = document.getElementById("pages-add-user-btn");
    const tbody = document.getElementById("pages-auth-users-tbody");
    const newName = document.getElementById("pages-new-user-name");
    const newPass = document.getElementById("pages-new-user-pass");
    const newNote = document.getElementById("pages-new-user-note");
    const logoutBtn = document.getElementById("static-logout-btn");

    if (logoutBtn) {
        logoutBtn.addEventListener("click", () => {
            sessionStorage.removeItem("osp_static_mk_b64");
            sessionStorage.removeItem("osp_static_user");
            _staticMasterKey = null;
            window.location.reload();
        });
    }

    if (!openBtn || !modal) return;
    let usersDraft = [];

    function renderUsersDraft() {
        if (!tbody) return;
        tbody.innerHTML = "";
        usersDraft.forEach((u, idx) => {
            const tr = document.createElement("tr");
            tr.style.borderBottom = "1px solid rgba(255,255,255,0.06)";
            tr.innerHTML = `
                <td style="padding: 8px 12px; font-weight: 600; font-family: monospace;">${escapeHTML(u.username)}</td>
                <td style="padding: 8px 12px;">
                    <input type="text" data-idx="${idx}" class="pages-user-pass-input" value="${escapeHTML(u.password)}" style="width: 100%; padding: 5px 8px; background: rgba(0,0,0,0.3); border: 1px solid var(--border-color); color: var(--text-main); border-radius: 4px; font-family: monospace; font-size: 0.78rem;" />
                </td>
                <td style="padding: 8px 12px;">
                    <input type="text" data-idx="${idx}" class="pages-user-note-input" value="${escapeHTML(u.note || '')}" style="width: 100%; padding: 5px 8px; background: rgba(0,0,0,0.3); border: 1px solid var(--border-color); color: var(--text-muted); border-radius: 4px; font-size: 0.78rem;" />
                </td>
                <td style="padding: 8px 12px; text-align: center;">
                    <button type="button" data-idx="${idx}" class="pages-user-del-btn" style="background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.35); color: #ef4444; padding: 4px 8px; border-radius: 4px; cursor: pointer;" title="Remove user">
                        <i class="fa-solid fa-trash-can"></i>
                    </button>
                </td>
            `;
            tbody.appendChild(tr);
        });

        tbody.querySelectorAll(".pages-user-pass-input").forEach(inp => {
            inp.addEventListener("input", (e) => {
                const i = parseInt(e.target.getAttribute("data-idx"), 10);
                if (usersDraft[i]) usersDraft[i].password = e.target.value;
            });
        });
        tbody.querySelectorAll(".pages-user-note-input").forEach(inp => {
            inp.addEventListener("input", (e) => {
                const i = parseInt(e.target.getAttribute("data-idx"), 10);
                if (usersDraft[i]) usersDraft[i].note = e.target.value;
            });
        });
        tbody.querySelectorAll(".pages-user-del-btn").forEach(btn => {
            btn.addEventListener("click", (e) => {
                const i = parseInt(e.currentTarget.getAttribute("data-idx"), 10);
                if (usersDraft.length <= 1) {
                    alert("At least one user must remain in the access list.");
                    return;
                }
                usersDraft.splice(i, 1);
                renderUsersDraft();
            });
        });
    }

    openBtn.addEventListener("click", async () => {
        try {
            const res = await _nativeFetch(`${API_BASE}/pages-auth`);
            if (res.ok) {
                const data = await res.json();
                usersDraft = (data.users || []).map(u => ({ ...u }));
                renderUsersDraft();
                modal.classList.remove("hidden");
            }
        } catch (err) {
            alert("Failed to load Pages Access configuration.");
        }
    });

    const closeModal = () => modal.classList.add("hidden");
    if (closeX) closeX.addEventListener("click", closeModal);
    if (cancelBtn) cancelBtn.addEventListener("click", closeModal);

    if (addBtn) {
        addBtn.addEventListener("click", () => {
            const uname = (newName.value || "").trim();
            const pw = (newPass.value || "").trim();
            const note = (newNote.value || "").trim();
            if (!uname || !pw) {
                alert("Please enter both a Username and Password.");
                return;
            }
            if (usersDraft.some(u => u.username.toLowerCase() === uname.toLowerCase())) {
                alert("Username already exists.");
                return;
            }
            usersDraft.push({ username: uname, password: pw, note });
            newName.value = "";
            newPass.value = "";
            newNote.value = "";
            renderUsersDraft();
        });
    }

    if (saveBtn) {
        saveBtn.addEventListener("click", async () => {
            saveBtn.disabled = true;
            try {
                const res = await _nativeFetch(`${API_BASE}/pages-auth`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ users: usersDraft })
                });
                if (!res.ok) {
                    const err = await res.json();
                    throw new Error(err.detail || "Failed to save access list");
                }
                closeModal();
                alert("Access list updated! Click 'Publish to GitHub' to push the updated user credentials to GitHub Pages.");
            } catch (err) {
                alert(`Error: ${err.message}`);
            } finally {
                saveBtn.disabled = false;
            }
        });
    }
}

/* ==========================================================================
   Initialization & Event Listeners
   ========================================================================== */
document.addEventListener("DOMContentLoaded", async () => {
    initPagesAuthModal();
    if (appState.isStaticMode) {
        await enableStaticPresentationMode();
        await ensureStaticAuthenticated();
    }
    const publishBtn = document.getElementById("publish-github-btn");
    if (publishBtn) {
        publishBtn.addEventListener("click", handlePublishToGitHub);
    }
    setupEventListeners();
    setupNmsEventListeners();
    await initApp();
});

async function initApp() {
    showLoader(true);
    try {
        await loadSettings();
        await loadFolders();
    } catch (err) {
        console.error("Initialization error:", err);
    } finally {
        showLoader(false);
    }
}

function setupEventListeners() {
    // Directory Scanning
    elements.scanBtn.addEventListener("click", handleScan);
    elements.scanPathInput.addEventListener("keypress", (e) => {
        if (e.key === "Enter") handleScan();
    });

    // Month & Year Filter Trigger
    elements.monthYearFilter.addEventListener("change", (e) => {
        appState.selectedMonthYear = e.target.value;
        renderFolderGrid();
    });

    // Back to Home
    elements.backToGridBtn.addEventListener("click", () => {
        elements.folderDetailView.classList.add("hidden");
        elements.folderGridView.classList.remove("hidden");
        loadFolders(); // Refresh folders summaries on home return
    });

    // Threshold Settings Drawer Drawer triggers
    elements.settingsToggleBtn.addEventListener("click", toggleSettingsDrawer);
    elements.closeSettingsBtn.addEventListener("click", toggleSettingsDrawer);
    elements.drawerBackdrop.addEventListener("click", toggleSettingsDrawer);
    elements.saveSettingsBtn.addEventListener("click", saveSettings);

    // Modal Closure
    elements.closeModalBtn.addEventListener("click", () => closeFiberModal());
    elements.closeModalXBtn.addEventListener("click", () => closeFiberModal());
    elements.pdfReportBtn.addEventListener("click", async () => {
        const originalTitle = document.title;
        const coreName = elements.modalFiberTitle.innerText || "OTDR_Report";
        
        // Clean unsafe characters and set document title to the core name for default PDF filename
        document.title = coreName.trim().replace(/[\/\\?%*:|"<>\s]/g, "_");
        
        // Trigger Plotly container resize to adapt graph for print dimensions
        const chart = document.getElementById('modal-plotly-chart');
        if (chart) {
            try {
                await Plotly.Plots.resize(chart);
            } catch (err) {
                console.error("Plotly print resize failed", err);
            }
        }
        
        // Give browser one frame to update layout and render before starting the print dialog
        requestAnimationFrame(() => {
            setTimeout(() => {
                window.print();
                
                // Restore screen title and resize graph back to modal dimensions after print dialog opens
                setTimeout(() => {
                    document.title = originalTitle;
                    if (chart) {
                        Plotly.Plots.resize(chart);
                    }
                }, 1000);
            }, 50);
        });
    });

    // Tabs Switcher
    elements.tabBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetTab = btn.getAttribute("data-tab");
            
            elements.tabBtns.forEach(b => b.classList.remove("active"));
            elements.tabPanels.forEach(p => p.classList.remove("active"));
            
            btn.classList.add("active");
            document.getElementById(targetTab).classList.add("active");
            
            if (targetTab === "tab-trace-overlay") {
                renderTraceOverlay();
            }
        });
    });

    // Filters & Search
    elements.fiberSearch.addEventListener("input", (e) => {
        appState.searchQuery = e.target.value.toLowerCase().trim();
        renderFibersTable();
    });

    elements.filterStatusSelect.addEventListener("change", (e) => {
        appState.filterStatus = e.target.value;
        renderFibersTable();
    });

    elements.filterWavelengthSelect.addEventListener("change", (e) => {
        appState.filterWavelength = e.target.value;
        renderFibersTable();
    });

    elements.csvExportBtn.addEventListener("click", exportFolderToCSV);

    if (elements.alignMinLoss) {
        elements.alignMinLoss.addEventListener("input", () => {
            renderTraceOverlay();
        });
    }

    if (elements.lockYAxisOverlay) {
        elements.lockYAxisOverlay.addEventListener("change", (e) => {
            appState.lockYAxis = e.target.checked;
            if (elements.lockYAxisModal) {
                elements.lockYAxisModal.checked = appState.lockYAxis;
            }
            renderTraceOverlay();
        });
    }

    if (elements.lockYAxisModal) {
        elements.lockYAxisModal.addEventListener("change", (e) => {
            appState.lockYAxis = e.target.checked;
            if (elements.lockYAxisOverlay) {
                elements.lockYAxisOverlay.checked = appState.lockYAxis;
            }
            if (elements.fiberModal && !elements.fiberModal.classList.contains("hidden") && appState.currentModalFile) {
                replotModalChart();
            }
        });
    }

    // Global ESC key listener to close modal
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
            closeFiberModal();
        }
    });

    // Multi-select Select All Checkbox
    elements.selectAllFibers.addEventListener("change", (e) => {
        const isChecked = e.target.checked;
        const visibleRows = getFilteredFibers();
        
        visibleRows.forEach(f => {
            if (isChecked) {
                appState.selectedFiberIds.add(f.id);
            } else {
                appState.selectedFiberIds.delete(f.id);
            }
        });
        
        // Re-render only checkbox elements inside table rows to preserve performance
        updateTableCheckboxes();
        updateOverlayCount();
    });

    // Column Sorting Listeners
    document.querySelectorAll("#fibers-data-table th.sortable").forEach(th => {
        th.addEventListener("click", () => {
            const col = th.getAttribute("data-sort");
            if (appState.sortColumn === col) {
                appState.sortDirection = appState.sortDirection === "asc" ? "desc" : "asc";
            } else {
                appState.sortColumn = col;
                appState.sortDirection = "asc";
            }
            
            // Render clean sort indicators on headers
            document.querySelectorAll("#fibers-data-table th.sortable i").forEach(i => {
                i.className = "fa-solid fa-sort";
            });
            const indicator = th.querySelector("i");
            indicator.className = appState.sortDirection === "asc" ? "fa-solid fa-sort-up" : "fa-solid fa-sort-down";
            
            renderFibersTable();
        });
    });
}

/* ==========================================================================
   UI Helpers & Drawer Controllers
   ========================================================================== */
function showLoader(show) {
    if (show) {
        elements.loader.classList.remove("hidden");
    } else {
        elements.loader.classList.add("hidden");
    }
}

function toggleSettingsDrawer() {
    elements.settingsDrawer.classList.toggle("open");
    elements.drawerBackdrop.classList.toggle("hidden");
}

/* ==========================================================================
   Settings Management (API Calls)
   ========================================================================== */
async function loadSettings() {
    try {
        const res = await fetch(`${API_BASE}/settings`);
        const config = await res.json();
        appState.settings = config;
        
        // Populate header scan input path
        elements.scanPathInput.value = config.last_scan_path;
        
        // Populate drawer inputs
        const th = config.thresholds;
        elements.setSplice.value = th.max_splice_loss_db;
        elements.setConnector.value = th.max_connector_loss_db;
        elements.setAtt1310.value = th.max_attenuation_1310_db_km;
        elements.setAtt1550.value = th.max_attenuation_1550_db_km;
        elements.setTotalLoss.value = th.max_total_loss_db;
    } catch (err) {
        console.error("Error loading settings:", err);
    }
}

async function saveSettings() {
    showLoader(true);
    
    const newThresholds = {
        max_splice_loss_db: parseFloat(elements.setSplice.value),
        max_connector_loss_db: parseFloat(elements.setConnector.value),
        max_attenuation_1310_db_km: parseFloat(elements.setAtt1310.value),
        max_attenuation_1550_db_km: parseFloat(elements.setAtt1550.value),
        max_total_loss_db: parseFloat(elements.setTotalLoss.value)
    };

    try {
        const res = await fetch(`${API_BASE}/settings`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: jsonStringify(newThresholds)
        });
        
        const data = await res.json();
        appState.settings = data.config;
        
        toggleSettingsDrawer();
        
        // If we are currently in a folder detail view, refresh it dynamically!
        if (appState.currentFolder) {
            await loadFolderDetail(appState.currentFolder.folder_id);
        } else {
            await loadFolders();
        }
    } catch (err) {
        alert("Error saving settings. Make sure backend is running.");
        console.error("Error saving settings:", err);
    } finally {
        showLoader(false);
    }
}

/* ==========================================================================
   Folder Index View & Scanning (API Calls)
   ========================================================================== */
async function handleScan() {
    const path = elements.scanPathInput.value.trim();
    if (!path) {
        alert("Please enter a valid path to scan.");
        return;
    }
    
    showLoader(true);
    try {
        const res = await fetch(`${API_BASE}/scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: jsonStringify({ path: path })
        });
        
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || "Scanning failed.");
        }
        
        const summaries = await res.json();
        elements.monthYearFilter.removeAttribute("data-initialized"); // Re-initialize default filter for new scanned path
        processFolders(summaries);
        
        // If we were inside details, jump back to home grid view
        elements.folderDetailView.classList.add("hidden");
        elements.folderGridView.classList.remove("hidden");
        appState.currentFolder = null;
        appState.selectedFiberIds.clear();
        updateOverlayCount();
    } catch (err) {
        alert(`Scan failed: ${err.message}`);
        console.error("Scan failed error:", err);
    } finally {
        showLoader(false);
    }
}

/**
 * Parses month and year in Bahasa Indonesia to a chronological number.
 * e.g., "Januari 2026" -> 2026 * 12 + 1 = 24313
 */
function parseMonthYear(str) {
    if (!str || str === "Other") return 0;
    
    const monthsMap = {
        "januari": 1, "februari": 2, "maret": 3, "april": 4,
        "mei": 5, "juni": 6, "juli": 7, "agustus": 8,
        "september": 9, "oktober": 10, "november": 11, "desember": 12
    };
    
    const parts = str.trim().split(/\s+/);
    if (parts.length < 2) return 0;
    
    const monthName = parts[0].toLowerCase();
    const year = parseInt(parts[1], 10);
    
    if (isNaN(year)) return 0;
    
    const monthNum = monthsMap[monthName] || 0;
    return year * 12 + monthNum;
}

function processFolders(summaries) {
    appState.activeFolders = summaries;
    
    // Extract unique Month & Year strings
    const monthYearsSet = new Set();
    summaries.forEach(s => {
        if (s.month_year) {
            monthYearsSet.add(s.month_year);
        }
    });
    const monthYears = Array.from(monthYearsSet);
    
    // Sort chronologically descending (newest first)
    monthYears.sort((a, b) => parseMonthYear(b) - parseMonthYear(a));
    
    // Populate filter selector
    elements.monthYearFilter.innerHTML = '<option value="all">All Months</option>';
    monthYears.forEach(my => {
        elements.monthYearFilter.innerHTML += `<option value="${my}">${my}</option>`;
    });
    
    // Ensure the current selection is valid for the loaded data
    if (appState.selectedMonthYear !== "all" && !monthYears.includes(appState.selectedMonthYear)) {
        appState.selectedMonthYear = monthYears.length > 0 ? monthYears[0] : "all";
    }
    
    // Default to newest one on first load or after path change
    if (!elements.monthYearFilter.dataset.initialized) {
        if (monthYears.length > 0) {
            appState.selectedMonthYear = monthYears[0];
        } else {
            appState.selectedMonthYear = "all";
        }
        elements.monthYearFilter.dataset.initialized = "true";
    }
    
    // Reflect selected value in dropdown
    elements.monthYearFilter.value = appState.selectedMonthYear;
    
    renderFolderGrid();
}

async function loadFolders() {
    try {
        const res = await fetch(`${API_BASE}/folders`);
        const summaries = await res.json();
        processFolders(summaries);
    } catch (err) {
        console.error("Error loading folders summaries:", err);
    }
}

/**
 * Helper to identify a unified Cable Segment key and display name from folder name.
 * Folders like "KLP-MTK (69km)" and "MTK-KLP (70km)" are grouped as "KLP ↔ MTK".
 */
function getCableSegment(folderName) {
    let base = folderName.split('(')[0].trim();
    let parts = base.split('-').map(p => p.trim()).filter(Boolean);
    
    if (parts.length === 2) {
        let sortedParts = [...parts].sort();
        return {
            key: sortedParts.join('-').toLowerCase(),
            displayName: sortedParts.join(' ↔ '),
            isGroupable: true
        };
    }
    
    return {
        key: base.toLowerCase(),
        displayName: base,
        isGroupable: false
    };
}

function renderFolderGrid() {
    elements.foldersGrid.innerHTML = "";
    
    if (appState.activeFolders.length === 0) {
        elements.foldersGrid.innerHTML = `
            <div class="empty-state">
                <i class="fa-solid fa-folder-tree empty-icon"></i>
                <h3>No folders parsed yet</h3>
                <p>Ensure your folder exists and contains valid .sor files. Click 'Scan Directory' above.</p>
            </div>
        `;
        return;
    }
    
    // Filter active folders by month & year selector
    let foldersToRender = appState.activeFolders;
    if (appState.selectedMonthYear !== "all") {
        foldersToRender = foldersToRender.filter(f => f.month_year === appState.selectedMonthYear);
    }
    
    if (foldersToRender.length === 0) {
        elements.foldersGrid.innerHTML = `
            <div class="empty-state">
                <i class="fa-solid fa-calendar-days empty-icon"></i>
                <h3>No folders for this month</h3>
                <p>Select another Month & Year filter, or scan a new directory.</p>
            </div>
        `;
        return;
    }

    // Group active folders by cable segment
    const groupsMap = new Map();
    
    foldersToRender.forEach(folder => {
        const seg = getCableSegment(folder.folder_name);
        if (!groupsMap.has(seg.key)) {
            groupsMap.set(seg.key, {
                key: seg.key,
                displayName: seg.displayName,
                folders: []
            });
        }
        groupsMap.get(seg.key).folders.push(folder);
    });
    
    // Render each group
    groupsMap.forEach(group => {
        const folders = group.folders;
        
        // Calculate aggregated stats
        const totalFibers = folders.reduce((sum, f) => sum + f.total_fibers, 0);
        const passedFibers = folders.reduce((sum, f) => sum + f.passed_fibers, 0);
        const failedFibers = folders.reduce((sum, f) => sum + f.failed_fibers, 0);
        
        let weightedAttSum = 0;
        let lengthSum = 0;
        const wavelengthsSet = new Set();
        
        folders.forEach(f => {
            weightedAttSum += f.average_attenuation_db_km * f.total_length_km;
            lengthSum += f.total_length_km;
            f.wavelengths.forEach(wl => wavelengthsSet.add(wl));
        });
        
        const avgAttenuation = lengthSum > 0 ? (weightedAttSum / lengthSum) : 0;
        const avgSpan = totalFibers > 0 ? (lengthSum / totalFibers) : 0;
        const wavelengths = Array.from(wavelengthsSet).sort((a, b) => a - b);
        
        // Pass rate percentages
        const passPercent = totalFibers > 0 ? (passedFibers / totalFibers) * 100 : 0;
        const failPercent = totalFibers > 0 ? (failedFibers / totalFibers) * 100 : 0;
        const wlTags = wavelengths.map(wl => `<span class="tag tag-wavelength">${wl} nm</span>`).join(" ");
        
        const card = document.createElement("div");
        card.className = "folder-card";
        if (failedFibers > 0) {
            card.classList.add("has-failures");
        } else {
            card.classList.add("all-passed");
        }
        
        const isSingle = folders.length === 1;
        
        if (isSingle) {
            const folder = folders[0];
            card.innerHTML = `
                <div class="card-header-row">
                    <div class="card-title">
                        <h3>${folder.folder_name}</h3>
                        <span class="card-path" title="${folder.absolute_path}">${folder.relative_path}</span>
                    </div>
                    <div class="card-icon">
                        <i class="${folder.failed_fibers > 0 ? 'fa-solid fa-circle-exclamation' : 'fa-solid fa-circle-check'}"></i>
                    </div>
                </div>
                
                <div class="audit-progress-area">
                    <div class="audit-tally">
                        <span class="tally-pass">${folder.passed_fibers} Pass</span>
                        <span class="tally-fail">${folder.failed_fibers} Fail</span>
                    </div>
                    <div class="progress-track">
                        <div class="progress-bar-pass" style="width: ${passPercent}%"></div>
                        <div class="progress-bar-fail" style="width: ${failPercent}%"></div>
                    </div>
                </div>
                
                <div class="card-stats-grid">
                    <div class="card-stat">
                        <span class="lbl">Fibers Count</span>
                        <span class="val">${folder.total_fibers} cores</span>
                    </div>
                    <div class="card-stat">
                        <span class="lbl">Avg. Span</span>
                        <span class="val">${folder.average_length_km} km</span>
                    </div>
                    <div class="card-stat" style="grid-column: span 2">
                        <span class="lbl">Avg. Attenuation</span>
                        <span class="val">${folder.average_attenuation_db_km} dB/km</span>
                    </div>
                </div>
                
                <div class="card-tags">
                    ${wlTags}
                </div>
            `;
            
            card.addEventListener("click", () => {
                elements.folderGridView.classList.add("hidden");
                elements.folderDetailView.classList.remove("hidden");
                loadFolderDetail(folder.folder_id);
            });
        } else {
            // Group card with list of sub-folders
            card.classList.add("segment-group-card");
            card.innerHTML = `
                <div class="card-header-row">
                    <div class="card-title">
                        <h3><i class="fa-solid fa-route" style="color: var(--primary); margin-right: 6px;"></i>${group.displayName}</h3>
                        <span class="card-path">Cable Segment Group (${folders.length} directories)</span>
                    </div>
                    <div class="card-icon">
                        <i class="${failedFibers > 0 ? 'fa-solid fa-circle-exclamation' : 'fa-solid fa-circle-check'}"></i>
                    </div>
                </div>
                
                <div class="audit-progress-area">
                    <div class="audit-tally">
                        <span class="tally-pass">${passedFibers} Pass</span>
                        <span class="tally-fail">${failedFibers} Fail</span>
                    </div>
                    <div class="progress-track">
                        <div class="progress-bar-pass" style="width: ${passPercent}%"></div>
                        <div class="progress-bar-fail" style="width: ${failPercent}%"></div>
                    </div>
                </div>
                
                <div class="card-stats-grid">
                    <div class="card-stat">
                        <span class="lbl">Fibers Count</span>
                        <span class="val">${totalFibers} cores</span>
                    </div>
                    <div class="card-stat">
                        <span class="lbl">Avg. Span</span>
                        <span class="val">${avgSpan.toFixed(2)} km</span>
                    </div>
                    <div class="card-stat" style="grid-column: span 2">
                        <span class="lbl">Avg. Attenuation</span>
                        <span class="val">${avgAttenuation.toFixed(4)} dB/km</span>
                    </div>
                </div>
                
                <div class="segment-folders-list">
                    ${folders.map(f => `
                        <div class="segment-folder-item" data-folder-id="${f.folder_id}">
                            <div class="item-meta">
                                <span class="item-name" title="${f.folder_name}">${f.folder_name}</span>
                                <span class="item-tally ${f.failed_fibers > 0 ? 'text-fail' : 'text-pass'}">
                                    ${f.passed_fibers}/${f.total_fibers} Pass
                                </span>
                            </div>
                            <i class="fa-solid fa-chevron-right item-arrow"></i>
                        </div>
                    `).join('')}
                </div>
                
                <div class="card-tags" style="margin-top: 12px;">
                    ${wlTags}
                </div>
            `;
            
            // Register click listener for each sub-folder item
            card.querySelectorAll(".segment-folder-item").forEach(item => {
                item.addEventListener("click", (e) => {
                    e.stopPropagation();
                    const folderId = item.getAttribute("data-folder-id");
                    elements.folderGridView.classList.add("hidden");
                    elements.folderDetailView.classList.remove("hidden");
                    loadFolderDetail(folderId);
                });
            });
        }
        
        elements.foldersGrid.appendChild(card);
    });
}

/* ==========================================================================
   Drill Down: Folder Detailed View & Audit Tables (API Calls)
   ========================================================================== */
async function loadFolderDetail(folderId) {
    showLoader(true);
    try {
        const res = await fetch(`${API_BASE}/folders/${folderId}/fibers`);
        const detail = await res.json();
        appState.currentFolder = detail;
        
        // Reset selections
        appState.selectedFiberIds.clear();
        updateOverlayCount();
        elements.selectAllFibers.checked = false;
        
        // Update title bar
        elements.currentFolderTitle.innerText = detail.folder_name;
        elements.currentFolderPath.innerText = detail.absolute_path;
        elements.currentFolderPath.title = detail.absolute_path;
        
        // Set stats ribbon values
        let passed = 0;
        let failed = 0;
        let totalLoss = 0.0;
        let totalLength = 0.0;
        
        detail.fibers.forEach(f => {
            if (f.status === "Pass") passed++;
            else failed++;
            totalLoss += f.link_parameters.total_loss_db || 0;
            totalLength += f.link_parameters.total_length_km || 0;
        });
        
        elements.statTotal.innerText = detail.fibers.length;
        elements.statPassed.innerText = passed;
        elements.statFailed.innerText = failed;
        
        const avgAtt = totalLength > 0 ? (totalLoss / totalLength) : 0.0;
        elements.statAvgAtt.innerText = `${avgAtt.toFixed(4)} dB/km`;
        
        // Switch back to Fiber Audit List tab by default
        elements.tabBtns[0].click();
        
        renderFibersTable();
    } catch (err) {
        console.error("Error loading folder detail:", err);
    } finally {
        showLoader(false);
    }
}

function getFilteredFibers() {
    if (!appState.currentFolder) return [];
    
    let fibers = [...appState.currentFolder.fibers];
    
    // 1. Search Query Filter
    if (appState.searchQuery) {
        fibers = fibers.filter(f => 
            (f.metadata.fiber_id && f.metadata.fiber_id.toLowerCase().includes(appState.searchQuery)) ||
            (f.metadata.cable_id && f.metadata.cable_id.toLowerCase().includes(appState.searchQuery)) ||
            (f.file_name && f.file_name.toLowerCase().includes(appState.searchQuery))
        );
    }
    
    // 2. Status Filter
    if (appState.filterStatus !== "all") {
        fibers = fibers.filter(f => f.status === appState.filterStatus);
    }
    
    // 3. Wavelength Filter
    if (appState.filterWavelength !== "all") {
        const wlInt = parseInt(appState.filterWavelength);
        fibers = fibers.filter(f => f.metadata.wavelength_nm === wlInt);
    }
    
    // 4. Sorting logic
    fibers.sort((a, b) => {
        let valA, valB;
        
        switch (appState.sortColumn) {
            case "fiber_id":
                valA = a.metadata.fiber_id || a.file_name;
                valB = b.metadata.fiber_id || b.file_name;
                return appState.sortDirection === "asc" 
                    ? String(valA).localeCompare(String(valB), undefined, {numeric: true})
                    : String(valB).localeCompare(String(valA), undefined, {numeric: true});
            case "wavelength":
                valA = a.metadata.wavelength_nm || 0;
                valB = b.metadata.wavelength_nm || 0;
                break;
            case "length":
                valA = a.link_parameters.total_length_km || 0.0;
                valB = b.link_parameters.total_length_km || 0.0;
                break;
            case "loss":
                valA = a.link_parameters.total_loss_db || 0.0;
                valB = b.link_parameters.total_loss_db || 0.0;
                break;
            case "attenuation":
                valA = a.link_parameters.average_attenuation_db_km || 0.0;
                valB = b.link_parameters.average_attenuation_db_km || 0.0;
                break;
            case "max_splice":
                valA = a.highest_splice_db || 0.0;
                valB = b.highest_splice_db || 0.0;
                break;
            case "max_connector":
                valA = a.highest_connector_db || 0.0;
                valB = b.highest_connector_db || 0.0;
                break;
            case "status":
                valA = a.status;
                valB = b.status;
                break;
            default:
                valA = a.id;
                valB = b.id;
        }
        
        if (valA < valB) return appState.sortDirection === "asc" ? -1 : 1;
        if (valA > valB) return appState.sortDirection === "asc" ? 1 : -1;
        return 0;
    });
    
    return fibers;
}

function renderFibersTable() {
    elements.fibersTableBody.innerHTML = "";
    const filtered = getFilteredFibers();
    
    if (filtered.length === 0) {
        elements.fibersTableBody.innerHTML = `
            <tr>
                <td colspan="9" style="text-align: center; color: var(--text-dim); padding: 30px;">
                    <i class="fa-solid fa-ban" style="font-size: 1.5rem; margin-bottom: 8px; display: block;"></i>
                    No fibers match current search query or active filter settings.
                </td>
            </tr>
        `;
        return;
    }
    
    filtered.forEach(fiber => {
        const tr = document.createElement("tr");
        const isChecked = appState.selectedFiberIds.has(fiber.id) ? "checked" : "";
        
        // Failure Tooltips helper
        let rowTooltip = "";
        if (fiber.status === "Fail" && fiber.reasons.length > 0) {
            rowTooltip = `title="Fail Criteria:\n- ${fiber.reasons.join('\n- ')}"`;
        }
        
        tr.innerHTML = `
            <td class="col-checkbox" onclick="event.stopPropagation();">
                <input type="checkbox" class="fiber-select-cb" data-id="${fiber.id}" ${isChecked} />
            </td>
            <td style="font-weight: 600;">${fiber.metadata.fiber_id || fiber.file_name}</td>
            <td><span class="tag tag-wavelength">${fiber.metadata.wavelength_nm} nm</span></td>
            <td>${fiber.link_parameters.total_length_km.toFixed(2)} km</td>
            <td>${fiber.link_parameters.total_loss_db.toFixed(2)} dB</td>
            <td>${fiber.link_parameters.average_attenuation_db_km.toFixed(4)} dB/km</td>
            <td>${fiber.highest_splice_db.toFixed(2)} dB</td>
            <td>${fiber.highest_connector_db.toFixed(2)} dB</td>
            <td>
                <span class="badge ${fiber.status === 'Pass' ? 'badge-pass' : 'badge-fail'}" ${rowTooltip}>
                    ${fiber.status}
                </span>
            </td>
        `;
        
        // Handle Row Selection vs. Checkbox Triggering
        tr.addEventListener("click", () => {
            showFiberModal(fiber.id);
        });
        
        const cb = tr.querySelector(".fiber-select-cb");
        cb.addEventListener("change", (e) => {
            const id = e.target.getAttribute("data-id");
            if (e.target.checked) {
                appState.selectedFiberIds.add(id);
            } else {
                appState.selectedFiberIds.delete(id);
            }
            updateOverlayCount();
        });
        
        elements.fibersTableBody.appendChild(tr);
    });
}

function updateTableCheckboxes() {
    document.querySelectorAll(".fiber-select-cb").forEach(cb => {
        const id = cb.getAttribute("data-id");
        cb.checked = appState.selectedFiberIds.has(id);
    });
}

function updateOverlayCount() {
    const size = appState.selectedFiberIds.size;
    elements.overlayCount.innerText = size;
    
    // Enable or disable Tab based on count
    const overlayBtn = elements.overlayCount.closest("button");
    if (size === 0) {
        overlayBtn.style.opacity = "0.5";
        overlayBtn.style.pointerEvents = "none";
        // If we are currently active on overlay panel but count drops to 0, push back to list
        if (overlayBtn.classList.contains("active")) {
            elements.tabBtns[0].click();
        }
    } else {
        overlayBtn.style.opacity = "1";
        overlayBtn.style.pointerEvents = "auto";
    }
}

/* ==========================================================================
   Tab B: Multi-Trace Overlay Plotting Engine (Plotly)
   ========================================================================== */
async function renderTraceOverlay() {
    if (elements.overlayList) {
        elements.overlayList.innerHTML = "";
    }
    if (elements.sharedEventsList) {
        elements.sharedEventsList.innerHTML = "";
    }
    if (elements.alignmentsTableBody) {
        elements.alignmentsTableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-dim)">No overlay fibers selected.</td></tr>`;
    }
    
    if (appState.selectedFiberIds.size === 0) {
        if (elements.overlayList) {
            elements.overlayList.innerHTML = `<span class="sidebar-tip">No fibers selected. Go back to the Audit Table and check the boxes next to the fibers you want to overlay.</span>`;
        }
        if (elements.sharedEventsList) {
            elements.sharedEventsList.innerHTML = `<li class="sidebar-tip">No fibers selected.</li>`;
        }
        Plotly.purge('overlay-plotly-chart');
        return;
    }
    
    showLoader(true);
    if (elements.alignmentsTableBody) {
        elements.alignmentsTableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-dim)">Analyzing trace alignments...</td></tr>`;
    }
    
    // Color palettes to color overlaid lines
    const colors = [
        "hsl(190, 100%, 50%)", // Neon cyan
        "hsl(280, 100%, 65%)", // Purple
        "hsl(142, 70%, 45%)",  // Emerald
        "hsl(25, 100%, 55%)",  // Amber
        "hsl(330, 90%, 60%)",  // Pink
        "hsl(210, 100%, 60%)", // Light Blue
        "hsl(60, 100%, 50%)",  // Yellow
        "hsl(0, 100%, 65%)"    // Light Red
    ];
    
    const traceData = [];
    const idsArray = Array.from(appState.selectedFiberIds);
    
    try {
        // Fetch all deep files details (with data points) in parallel
        const fetchPromises = idsArray.map(id => fetch(`${API_BASE}/files/${id}`).then(res => res.json()));
        const parsedFiles = await Promise.all(fetchPromises);
        
        parsedFiles.forEach((file, idx) => {
            const color = colors[idx % colors.length];
            const name = file.metadata.fiber_id || file.file_name;
            
            // Build Plotly Trace object
            const xVals = file.trace_points.map(pt => pt[0]);
            const yVals = file.trace_points.map(pt => pt[1]);
            
            traceData.push({
                x: xVals,
                y: yVals,
                type: 'scatter',
                mode: 'lines',
                name: `${name} (${file.metadata.wavelength_nm}nm)`,
                line: {
                    color: color,
                    width: 2
                }
            });
        });
        
        // --- Shared Events Alignment Feature ---
        const minLoss = parseFloat(elements.alignMinLoss?.value) || 0.0;
        const allEvents = [];
        parsedFiles.forEach(file => {
            const fiberName = file.metadata.fiber_id || file.file_name;
            
            if (file.events) {
                file.events.forEach(ev => {
                    const evLoss = Math.abs(ev.loss_db || 0);
                    if (evLoss >= minLoss) {
                        allEvents.push({
                            fiberId: file.metadata.fiber_id,
                            fiberName: fiberName,
                            filePath: file.file_path,
                            eventNum: ev.event_num,
                            distanceKm: ev.distance_km,
                            type: ev.type,
                            lossDb: ev.loss_db,
                            reflectanceDb: ev.reflectance_db,
                            slopeDbKm: ev.slope_db_km,
                            wavelength: file.metadata.wavelength_nm
                        });
                    }
                });
            }
        });
        
        const toleranceKm = 0.05; // 50 meters tolerance
        const clusters = [];
        allEvents.sort((a, b) => a.distanceKm - b.distanceKm);
        
        allEvents.forEach(ev => {
            let added = false;
            for (const cluster of clusters) {
                const centroid = cluster.reduce((sum, e) => sum + e.distanceKm, 0) / cluster.length;
                if (Math.abs(ev.distanceKm - centroid) <= toleranceKm) {
                    cluster.push(ev);
                    added = true;
                    break;
                }
            }
            if (!added) {
                clusters.push([ev]);
            }
        });
        
        // Filter clusters that contain events from at least 2 unique core files
        const sharedClusters = clusters.filter(cluster => {
            const uniqueFiles = new Set(cluster.map(e => e.filePath));
            return uniqueFiles.size >= 2;
        });
        
        sharedClusters.sort((a, b) => {
            const avgA = a.reduce((sum, e) => sum + e.distanceKm, 0) / a.length;
            const avgB = b.reduce((sum, e) => sum + e.distanceKm, 0) / b.length;
            return avgA - avgB;
        });
        
        // Populate sidebar shared events
        if (elements.sharedEventsList) {
            elements.sharedEventsList.innerHTML = "";
            if (sharedClusters.length === 0) {
                elements.sharedEventsList.innerHTML = `<li class="sidebar-tip">No shared events detected. (Requires events at same distances across 2+ cores).</li>`;
            } else {
                sharedClusters.forEach((cluster, idx) => {
                    const avgDist = cluster.reduce((sum, e) => sum + e.distanceKm, 0) / cluster.length;
                    const numFibers = new Set(cluster.map(e => e.filePath)).size;
                    
                    const typeCounts = {};
                    cluster.forEach(e => {
                        typeCounts[e.type] = (typeCounts[e.type] || 0) + 1;
                    });
                    const primaryType = Object.keys(typeCounts).reduce((a, b) => typeCounts[a] > typeCounts[b] ? a : b);
                    
                    const li = document.createElement("li");
                    li.className = "overlay-item";
                    li.style.borderLeft = "4px solid hsl(35, 92%, 55%)";
                    li.style.cursor = "pointer";
                    li.style.display = "flex";
                    li.style.flexDirection = "column";
                    li.style.gap = "2px";
                    li.style.padding = "8px 10px";
                    
                    const coreNames = Array.from(new Set(cluster.map(e => e.fiberName))).join(", ");
                    li.title = `Detected in: ${coreNames}`;
                    
                    li.innerHTML = `
                        <div style="display: flex; justify-content: space-between; align-items: center; width: 100%;">
                            <span style="font-weight: 600; color: var(--text-main); font-size: 0.78rem;">Align-${idx + 1}: ${primaryType}</span>
                            <span style="font-size: 0.72rem; color: hsl(35, 92%, 65%); font-weight: bold;">${numFibers} Cores</span>
                        </div>
                        <div style="display: flex; justify-content: space-between; align-items: center; width: 100%; font-size: 0.72rem; color: var(--text-muted);">
                            <span>Dist: <strong>${avgDist.toFixed(3)} km</strong></span>
                            <span style="font-size: 0.65rem; color: var(--text-dim);"><i class="fa-solid fa-magnifying-glass-plus"></i> Click to Zoom</span>
                        </div>
                    `;
                    
                    li.addEventListener("click", () => {
                        const startX = Math.max(0, avgDist - 5);
                        const update = {
                            'xaxis.range': [startX, startX + 10]
                        };
                        if (appState.lockYAxis) {
                            const gd = document.getElementById('overlay-plotly-chart');
                            if (gd && gd.layout && gd.layout.yaxis && gd.layout.yaxis.range) {
                                update['yaxis.range'] = [...gd.layout.yaxis.range];
                            }
                        }
                        Plotly.relayout('overlay-plotly-chart', update);
                    });
                    
                    elements.sharedEventsList.appendChild(li);
                });
            }
        }
        
        // Populate Alignments details table
        if (elements.alignmentsTableBody) {
            elements.alignmentsTableBody.innerHTML = "";
            if (sharedClusters.length === 0) {
                elements.alignmentsTableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-dim)">No shared events detected.</td></tr>`;
            } else {
                sharedClusters.forEach((cluster, idx) => {
                    const avgDist = cluster.reduce((sum, e) => sum + e.distanceKm, 0) / cluster.length;
                    const numFibers = new Set(cluster.map(e => e.filePath)).size;
                    
                    const typeCounts = {};
                    cluster.forEach(e => {
                        typeCounts[e.type] = (typeCounts[e.type] || 0) + 1;
                    });
                    const primaryType = Object.keys(typeCounts).reduce((a, b) => typeCounts[a] > typeCounts[b] ? a : b);
                    
                    // Build participating cores HTML list with individual losses
                    const coreBadges = cluster.map(e => {
                        const isFail = checkEventFailure(e, e.wavelength);
                        const lossText = e.lossDb.toFixed(2) + " dB";
                        
                        let badgeStyle = "background-color: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.1); color: var(--text-main); font-size: 0.72rem; padding: 2px 6px; border-radius: 4px; margin-right: 6px; display: inline-block;";
                        if (isFail.loss) {
                            badgeStyle = "background-color: var(--danger-bg); border: 1px solid var(--danger-border); color: var(--danger); font-size: 0.72rem; padding: 2px 6px; border-radius: 4px; margin-right: 6px; display: inline-block; font-weight: bold;";
                        }
                        
                        return `<span style="${badgeStyle}" title="Wavelength: ${e.wavelength}nm, Reflectance: ${e.reflectanceDb > -900 ? e.reflectanceDb.toFixed(1) + ' dB' : 'N/A'}">${e.fiberName}: <strong>${lossText}</strong></span>`;
                    }).join("");
                    
                    const tr = document.createElement("tr");
                    tr.style.cursor = "pointer";
                    tr.innerHTML = `
                        <td style="font-weight: 700; color: hsl(35, 92%, 65%);">Align-${idx + 1}</td>
                        <td style="font-weight: 600;">${avgDist.toFixed(3)} km</td>
                        <td>${primaryType}</td>
                        <td style="font-weight: 600;">${numFibers} Cores</td>
                        <td>
                            <div style="display: flex; flex-wrap: wrap; gap: 6px;">
                                ${coreBadges}
                            </div>
                        </td>
                    `;
                    
                    tr.addEventListener("click", () => {
                        const startX = Math.max(0, avgDist - 5);
                        const update = {
                            'xaxis.range': [startX, startX + 10]
                        };
                        if (appState.lockYAxis) {
                            const gd = document.getElementById('overlay-plotly-chart');
                            if (gd && gd.layout && gd.layout.yaxis && gd.layout.yaxis.range) {
                                update['yaxis.range'] = [...gd.layout.yaxis.range];
                            }
                        }
                        Plotly.relayout('overlay-plotly-chart', update);
                    });
                    
                    elements.alignmentsTableBody.appendChild(tr);
                });
            }
        }
        
        // Calculate Plotly shapes/annotations for event alignments
        const shapes = [];
        const annotations = [];
        if (traceData.length > 0 && sharedClusters.length > 0) {
            const allYVals = traceData.flatMap(t => t.y);
            const minY = Math.min(...allYVals);
            const maxY = Math.max(...allYVals);
            
            sharedClusters.forEach((cluster, idx) => {
                const avgDist = cluster.reduce((sum, e) => sum + e.distanceKm, 0) / cluster.length;
                const numFibers = new Set(cluster.map(e => e.filePath)).size;
                
                shapes.push({
                    type: 'line',
                    x0: avgDist,
                    y0: minY,
                    x1: avgDist,
                    y1: maxY,
                    line: {
                        color: 'rgba(245, 158, 11, 0.4)',
                        width: 1.5,
                        dash: 'dash'
                    }
                });
                
                annotations.push({
                    x: avgDist,
                    y: maxY,
                    text: `Align-${idx + 1} (${numFibers} Cores)`,
                    showarrow: false,
                    font: {
                        color: 'hsl(35, 92%, 65%)',
                        size: 8,
                        weight: 'bold'
                    },
                    align: 'center',
                    yanchor: 'bottom',
                    bgcolor: document.body.classList.contains("light-mode") ? 'rgba(255, 255, 255, 0.9)' : 'rgba(15, 23, 42, 0.9)',
                    bordercolor: 'rgba(245, 158, 11, 0.4)',
                    borderwidth: 1,
                    borderpad: 2
                });
            });
        }
        
        // Render combined chart with dynamic theme colors
        const isLight = document.body.classList.contains("light-mode");
        const gridColor = isLight ? 'rgba(0,0,0,0.06)' : 'rgba(255,255,255,0.03)';
        const zeroLineColor = isLight ? 'rgba(0,0,0,0.1)' : 'rgba(255,255,255,0.05)';
        const textColor = isLight ? 'hsl(215, 16%, 42%)' : 'hsl(215, 20%, 65%)';
        const legendBg = isLight ? 'rgba(255,255,255,0.85)' : 'rgba(10, 15, 30, 0.65)';
        const legendBorder = isLight ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.05)';
        const tooltipBg = isLight ? 'rgba(255,255,255,0.95)' : 'rgba(15, 23, 42, 0.95)';
        const tooltipBorder = isLight ? 'rgba(0,0,0,0.12)' : 'rgba(255,255,255,0.1)';
        const tooltipText = isLight ? 'hsl(222, 47%, 12%)' : 'hsl(210, 40%, 98%)';

        const layout = {
            paper_bgcolor: 'rgba(0,0,0,0)',
            plot_bgcolor: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(0,0,0,0.1)',
            margin: { t: 25, r: 15, l: 45, b: 35 },
            xaxis: {
                title: { text: 'Distance (km)', font: { color: textColor, size: 10 } },
                gridcolor: gridColor,
                zerolinecolor: zeroLineColor,
                tickfont: { color: 'hsl(215, 15%, 50%)', size: 9 }
            },
            yaxis: {
                title: { text: 'Backscatter Power (dB)', font: { color: textColor, size: 10 } },
                gridcolor: gridColor,
                zerolinecolor: zeroLineColor,
                tickfont: { color: 'hsl(215, 15%, 50%)', size: 9 },
                fixedrange: appState.lockYAxis
            },
            showlegend: true,
            legend: {
                font: { color: textColor, size: 9 },
                bgcolor: legendBg,
                bordercolor: legendBorder,
                borderwidth: 1
            },
            hovermode: 'closest',
            hoverlabel: {
                bgcolor: tooltipBg,
                bordercolor: tooltipBorder,
                font: { color: tooltipText, size: 11 }
            },
            shapes: shapes,
            annotations: annotations
        };
        
        const config = {
            responsive: true,
            displayModeBar: true,
            modeBarButtonsToRemove: ['select2d', 'lasso2d', 'autoScale2d']
        };
        
        Plotly.newPlot('overlay-plotly-chart', traceData, layout, config);
    } catch (err) {
        console.error("Overlay loading failed:", err);
    } finally {
        showLoader(false);
    }
}

/* ==========================================================================
   Detail Modal View & Visualizing a Single Fiber Trace
   ========================================================================== */
async function showFiberModal(fiberId) {
    showLoader(true);
    try {
        const res = await fetch(`${API_BASE}/files/${fiberId}`);
        const file = await res.json();
        
        // 1. Populate Text fields in Modal
        elements.modalFiberTitle.innerText = file.metadata.fiber_id || file.file_name;
        elements.modalTagWavelength.innerText = `${file.metadata.wavelength_nm} nm`;
        
        // Status Badge
        elements.modalBadgeStatus.innerText = file.status;
        elements.modalBadgeStatus.className = `badge ${file.status === 'Pass' ? 'badge-pass' : 'badge-fail'}`;
        
        // Load detailed metadata
        document.getElementById("m-cable-id").innerText = file.metadata.cable_id || "-";
        document.getElementById("m-fiber-id").innerText = `${file.metadata.fiber_id || "-"} (#${file.metadata.fiber_number || 1})`;
        document.getElementById("m-wavelength").innerText = `${file.metadata.wavelength_nm} nm`;
        document.getElementById("m-pulse-width").innerText = `${file.metadata.pulse_width_ns} ns`;
        document.getElementById("m-ior").innerText = file.metadata.index_of_refraction.toFixed(5);
        document.getElementById("m-backscatter").innerText = `${file.metadata.backscatter_coefficient_db} dB`;
        document.getElementById("m-total-length").innerText = `${file.link_parameters.total_length_km.toFixed(3)} km`;
        document.getElementById("m-total-loss").innerText = `${file.link_parameters.total_loss_db.toFixed(2)} dB`;
        document.getElementById("m-avg-attenuation").innerText = `${file.link_parameters.average_attenuation_db_km.toFixed(4)} dB/km`;
        document.getElementById("m-orl").innerText = file.link_parameters.orl_db ? `${file.link_parameters.orl_db.toFixed(2)} dB` : "N/A";
        document.getElementById("m-datetime").innerText = file.metadata.date_time || "-";
        document.getElementById("m-hardware").innerText = `${file.metadata.otdr_vendor} ${file.metadata.otdr_model} (${file.metadata.otdr_serial})`;
        document.getElementById("m-operator").innerText = file.metadata.operator || "-";
        document.getElementById("m-comment").innerText = file.metadata.comment || "-";
        
        // Handle failure reasons
        if (file.status === "Fail" && file.reasons.length > 0) {
            elements.modalFailureReasons.classList.remove("hidden");
            elements.modalFailureReasons.innerHTML = `
                <strong><i class="fa-solid fa-circle-exclamation"></i> Quality Threshold Failures:</strong>
                ${file.reasons.map(r => `<div>• ${r}</div>`).join('')}
            `;
        } else {
            elements.modalFailureReasons.classList.add("hidden");
        }
        
        // 2. Populate Event Table
        elements.eventsTableBody.innerHTML = "";
        if (file.events && file.events.length > 0) {
            file.events.forEach(ev => {
                const tr = document.createElement("tr");
                const isFail = checkEventFailure(ev, file.metadata.wavelength_nm);
                
                tr.innerHTML = `
                    <td class="col-num">${ev.event_num}</td>
                    <td style="font-weight: 600;">${ev.distance_km.toFixed(3)}</td>
                    <td>${ev.type}</td>
                    <td style="${isFail.loss ? 'color: var(--danger); font-weight: bold;' : ''}">${ev.loss_db.toFixed(2)}</td>
                    <td>${ev.reflectance_db > -900 ? ev.reflectance_db.toFixed(1) : '-'}</td>
                    <td style="${isFail.slope ? 'color: var(--danger); font-weight: bold;' : ''}">${ev.slope_db_km.toFixed(3)}</td>
                    <td style="color: var(--text-muted); font-size: 0.72rem;">${ev.comment || '-'}</td>
                `;
                elements.eventsTableBody.appendChild(tr);
            });
        } else {
            elements.eventsTableBody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-dim)">No event logs detected in .sor file.</td></tr>`;
        }
        
        // 3. Cache current modal file and render graph
        appState.currentModalFile = file;

        // Show modal by removing hidden class
        elements.fiberModal.classList.remove("hidden");
        
        // Wait 100ms for modal rendering animation before plotting, ensuring Plotly measures DOM box accurately!
        setTimeout(() => {
            replotModalChart();
        }, 100);
        
    } catch (err) {
        alert("Error deep-loading fiber details.");
        console.error("Modal loading failed:", err);
    } finally {
        showLoader(false);
    }
}

function replotModalChart() {
    if (!appState.currentModalFile) return;
    const file = appState.currentModalFile;

    const xVals = file.trace_points.map(pt => pt[0]);
    const yVals = file.trace_points.map(pt => pt[1]);
    
    const trace = {
        x: xVals,
        y: yVals,
        type: 'scatter',
        mode: 'lines',
        name: 'Trace',
        line: {
            color: 'hsl(190, 100%, 45%)',
            width: 2.5
        }
    };
    
    // Draw vertical lines on chart showing event markers
    const shapes = [];
    const annotations = [];
    
    if (file.events) {
        file.events.forEach(ev => {
            shapes.push({
                type: 'line',
                x0: ev.distance_km,
                y0: Math.min(...yVals),
                x1: ev.distance_km,
                y1: Math.max(...yVals),
                line: {
                    color: 'rgba(255, 255, 255, 0.15)',
                    width: 1.2,
                    dash: 'dashdot'
                }
            });
            
            annotations.push({
                x: ev.distance_km,
                y: Math.max(...yVals),
                text: `E${ev.event_num}`,
                showarrow: false,
                font: {
                    color: 'hsl(215, 20%, 65%)',
                    size: 9
                },
                align: 'center',
                yanchor: 'bottom'
            });
        });
    }
    
    const isLight = document.body.classList.contains("light-mode");
    const gridColor = isLight ? 'rgba(0,0,0,0.06)' : 'rgba(255,255,255,0.03)';
    const zeroLineColor = isLight ? 'rgba(0,0,0,0.1)' : 'rgba(255,255,255,0.05)';
    const textColor = isLight ? 'hsl(215, 16%, 42%)' : 'hsl(215, 20%, 65%)';
    const tooltipBg = isLight ? 'rgba(255,255,255,0.95)' : 'rgba(15, 23, 42, 0.95)';
    const tooltipBorder = isLight ? 'rgba(0,0,0,0.12)' : 'rgba(255,255,255,0.1)';
    const tooltipText = isLight ? 'hsl(222, 47%, 12%)' : 'hsl(210, 40%, 98%)';

    const layout = {
        paper_bgcolor: 'rgba(0,0,0,0)',
        plot_bgcolor: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(0,0,0,0.1)',
        margin: { t: 30, r: 15, l: 45, b: 35 },
        xaxis: {
            title: { text: 'Distance (km)', font: { color: textColor, size: 10 } },
            gridcolor: gridColor,
            zerolinecolor: zeroLineColor,
            tickfont: { color: 'hsl(215, 15%, 50%)', size: 9 }
        },
        yaxis: {
            title: { text: 'Backscatter Power (dB)', font: { color: textColor, size: 10 } },
            gridcolor: gridColor,
            zerolinecolor: zeroLineColor,
            tickfont: { color: 'hsl(215, 15%, 50%)', size: 9 },
            fixedrange: appState.lockYAxis
        },
        showlegend: false,
        shapes: shapes,
        annotations: annotations,
        hovermode: 'closest',
        hoverlabel: {
            bgcolor: tooltipBg,
            bordercolor: tooltipBorder,
            font: { color: tooltipText, size: 11 }
        }
    };
    
    const config = {
        responsive: true,
        displayModeBar: true,
        modeBarButtonsToRemove: ['select2d', 'lasso2d']
    };
    
    Plotly.newPlot('modal-plotly-chart', [trace], layout, config);
}

function closeFiberModal() {
    if (elements.fiberModal) {
        elements.fiberModal.classList.add("hidden");
    }
    appState.currentModalFile = null;
}

function checkEventFailure(ev, wavelength) {
    const th = appState.settings.thresholds;
    const type = ev.type.lower();
    
    let isLossFail = false;
    let isSlopeFail = false;
    
    // Connectors / Splices checked
    if (type.includes("launch") || type.includes("end")) {
        // Skip launch/end for middle threshold audits
    } else if (type.includes("connector") || type.includes("reflection")) {
        if (ev.loss_db > th.max_connector_loss_db) isLossFail = true;
    } else if (type.includes("splice") || type.includes("non-reflective") || ev.loss_db > 0.0) {
        if (ev.loss_db > th.max_splice_loss_db) isLossFail = true;
    }
    
    // Slopes checked (attenuation)
    if (wavelength === 1310) {
        if (ev.slope_db_km > th.max_attenuation_1310_db_km) isSlopeFail = true;
    } else {
        if (ev.slope_db_km > th.max_attenuation_1550_db_km) isSlopeFail = true;
    }
    
    return { loss: isLossFail, slope: isSlopeFail };
}

/* ==========================================================================
   Spreadsheet CSV Exporter Utility
   ========================================================================== */
function exportFolderToCSV() {
    if (!appState.currentFolder) return;
    
    const fibers = getFilteredFibers();
    if (fibers.length === 0) {
        alert("No fibers to export.");
        return;
    }
    
    // CSV Header row
    const headers = [
        "Cable ID",
        "Fiber ID",
        "Fiber Number",
        "Wavelength (nm)",
        "Pulse Width (ns)",
        "Index of Refraction",
        "Length (km)",
        "Total Loss (dB)",
        "Avg Attenuation (dB/km)",
        "Max Splice Loss (dB)",
        "Max Connector Loss (dB)",
        "Status",
        "Audit Failure Details"
    ];
    
    const csvRows = [headers.join(",")];
    
    fibers.forEach(f => {
        const row = [
            escapeCSV(f.metadata.cable_id || "-"),
            escapeCSV(f.metadata.fiber_id || f.file_name),
            f.metadata.fiber_number || 1,
            f.metadata.wavelength_nm,
            f.metadata.pulse_width_ns,
            f.metadata.index_of_refraction.toFixed(5),
            f.link_parameters.total_length_km.toFixed(3),
            f.link_parameters.total_loss_db.toFixed(2),
            f.link_parameters.average_attenuation_db_km.toFixed(4),
            f.highest_splice_db.toFixed(2),
            f.highest_connector_db.toFixed(2),
            f.status,
            escapeCSV(f.reasons.join("; "))
        ];
        csvRows.push(row.join(","));
    });
    
    // Generate CSV Blob
    const csvString = csvRows.join("\n");
    const blob = new Blob([csvString], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    
    // Native browser download
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", `OTDR_Audit_Summary_${appState.currentFolder.folder_name}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

function escapeCSV(text) {
    if (text === null || text === undefined) return "";
    let str = String(text);
    if (str.includes(",") || str.includes('"') || str.includes("\n") || str.includes(";")) {
        str = str.replace(/"/g, '""');
        return `"${str}"`;
    }
    return str;
}

/* ==========================================================================
   Modern ES6 JS Prototypes / Extensions (For String manipulation)
   ========================================================================== */
if (!String.prototype.lower) {
    String.prototype.lower = function() {
        return this.toLowerCase();
    };
}

// Custom helpers for secure serialization (FastAPI compat)
function jsonStringify(obj) {
    return JSON.stringify(obj);
}

/* ==========================================================================
   Network Topology NMS Controller
   ========================================================================== */

function getVisibilityFilters() {
    const showRoutersCheck = document.getElementById("nms-show-routers");
    const showOltsCheck = document.getElementById("nms-show-olts");
    const onlyOpticalNokCheck = document.getElementById("nms-only-optical-nok");
    
    return {
        showRouters: showRoutersCheck ? showRoutersCheck.checked : true,
        showOlts: showOltsCheck ? showOltsCheck.checked : true,
        onlyOpticalNok: onlyOpticalNokCheck ? onlyOpticalNokCheck.checked : false
    };
}

function setupNmsEventListeners() {
    const otdrBtn = document.getElementById("nav-otdr-btn");
    const nmsBtn = document.getElementById("nav-nms-btn");
    const consoleBtn = document.getElementById("nav-console-btn");
    
    if (otdrBtn && nmsBtn) {
        otdrBtn.addEventListener("click", () => switchView("otdr"));
        nmsBtn.addEventListener("click", () => switchView("nms"));
    }
    if (consoleBtn) {
        consoleBtn.addEventListener("click", () => switchView("console"));
    }
    
    // Zoom & Arrange buttons
    const zoomIn = document.getElementById("nms-zoom-in-btn");
    const zoomOut = document.getElementById("nms-zoom-out-btn");
    const resetZoom = document.getElementById("nms-reset-zoom-btn");
    const arrangeBtn = document.getElementById("nms-arrange-btn");
    
    if (zoomIn) {
        zoomIn.addEventListener("click", () => {
            if (appState.nms.layoutMode === "geo" && appState.nms.map) {
                appState.nms.map.zoomIn();
            } else {
                adjustNmsZoom(1.2);
            }
        });
    }
    if (zoomOut) {
        zoomOut.addEventListener("click", () => {
            if (appState.nms.layoutMode === "geo" && appState.nms.map) {
                appState.nms.map.zoomOut();
            } else {
                adjustNmsZoom(0.8);
            }
        });
    }
    if (resetZoom) {
        resetZoom.addEventListener("click", () => {
            if (appState.nms.layoutMode === "geo" && appState.nms.map && appState.nms.mapLayers) {
                const bounds = appState.nms.mapLayers.getBounds();
                if (bounds.isValid()) {
                    appState.nms.map.fitBounds(bounds, { padding: [50, 50] });
                }
            } else {
                resetNmsZoomAndPan();
            }
        });
    }
    if (arrangeBtn) {
        arrangeBtn.addEventListener("click", () => {
            const algoSelect = document.getElementById("nms-arrange-algorithm");
            const algo = algoSelect ? algoSelect.value : "tree";
            if (algo === "force") {
                autoArrangeForceDirected();
            } else if (algo === "radial") {
                autoArrangeRadial();
            } else {
                autoArrangeTopology();
            }
        });
    }
    
    // Spreadsheet tabs
    const tabDevices = document.getElementById("tab-devices-btn");
    const tabConns = document.getElementById("tab-connections-btn");
    
    if (tabDevices && tabConns) {
        tabDevices.addEventListener("click", () => switchNmsEditorTab("devices"));
        tabConns.addEventListener("click", () => switchNmsEditorTab("connections"));
    }
    
    // Add Row Buttons
    const addDevBtn = document.getElementById("add-device-row-btn");
    const addConnBtn = document.getElementById("add-connection-row-btn");
    
    if (addDevBtn) addDevBtn.addEventListener("click", addDeviceRow);
    if (addConnBtn) addConnBtn.addEventListener("click", addConnectionRow);
    
    // Save button
    const saveBtn = document.getElementById("nms-save-btn");
    if (saveBtn) saveBtn.addEventListener("click", saveNmsTopology);
    
    // Overlay close button
    const closeOverlayBtn = document.getElementById("nms-detail-close-btn");
    if (closeOverlayBtn) {
        closeOverlayBtn.addEventListener("click", () => {
            const placeholder = document.getElementById("nms-detail-placeholder");
            const content = document.getElementById("nms-detail-content");
            if (content) content.classList.add("hidden");
            if (placeholder) placeholder.classList.remove("hidden");
            appState.nms.selectedNodeId = null;
            document.querySelectorAll(".nms-node").forEach(n => n.classList.remove("selected"));
            document.querySelectorAll(".nms-link-line").forEach(l => l.classList.remove("selected"));
            if (appState.nms.layoutMode === "geo") {
                renderNmsLeafletMap();
            } else {
                renderNmsGraph();
            }
        });
    }
    
    // Search filter input trigger
    const searchInput = document.getElementById("nms-search-input");
    if (searchInput) {
        searchInput.addEventListener("input", () => {
            renderNmsSpreadsheet();
            if (appState.nms.layoutMode === "geo") {
                renderNmsLeafletMap();
            } else {
                renderNmsGraph();
            }
        });
    }
    
    // Lock toggle event listener
    const lockToggleBtn = document.getElementById("nms-toggle-lock-btn");
    if (lockToggleBtn) {
        lockToggleBtn.addEventListener("click", toggleNmsEditLock);
    }
    
    // Unhide All event listener
    const unhideAllBtn = document.getElementById("nms-unhide-all-btn");
    if (unhideAllBtn) {
        unhideAllBtn.addEventListener("click", () => {
            let changed = false;
            appState.nms.devices.forEach(d => {
                if (d.hidden) {
                    d.hidden = false;
                    changed = true;
                }
            });
            appState.nms.connections.forEach(c => {
                if (c.hidden) {
                    c.hidden = false;
                    changed = true;
                }
            });
            
            if (changed) {
                appState.nms.hasChanges = true;
                markUnsavedChanges(true);
                renderNmsSpreadsheet();
                renderNmsGraph();
                if (appState.nms.layoutMode === "geo") {
                    renderNmsLeafletMap();
                }
                
                // If a connection is selected and sidebar is showing connection details, refresh it
                if (appState.nms.selectedConnectionId) {
                    const conn = appState.nms.connections.find(c => c.id === appState.nms.selectedConnectionId);
                    if (conn) {
                        const allConnsInPair = appState.nms.connections.filter(c => 
                            (c.source === conn.source && c.target === conn.target) ||
                            (c.source === conn.target && c.target === conn.source)
                        );
                        showNmsConnectionDetailPanel(allConnsInPair, conn);
                    }
                }
            }
        });
    }
    
    // Visibility filter change listeners
    const showRoutersCheck = document.getElementById("nms-show-routers");
    const showOltsCheck = document.getElementById("nms-show-olts");
    const onlyOpticalNokCheck = document.getElementById("nms-only-optical-nok");
    const opticalNokBtn = document.getElementById("nms-optical-nok-btn");
    const syncOpticalNokBtnState = () => {
        if (opticalNokBtn && onlyOpticalNokCheck) {
            opticalNokBtn.classList.toggle("active", onlyOpticalNokCheck.checked);
        }
    };
    const handleFilterChange = () => {
        syncOpticalNokBtnState();
        renderNmsSpreadsheet();
        if (appState.nms.layoutMode === "geo") {
            renderNmsLeafletMap();
        } else {
            renderNmsGraph();
        }
    };
    if (showRoutersCheck) showRoutersCheck.addEventListener("change", handleFilterChange);
    if (showOltsCheck) showOltsCheck.addEventListener("change", handleFilterChange);
    if (onlyOpticalNokCheck) onlyOpticalNokCheck.addEventListener("change", handleFilterChange);
    if (opticalNokBtn && onlyOpticalNokCheck) {
        opticalNokBtn.addEventListener("click", () => {
            onlyOpticalNokCheck.checked = !onlyOpticalNokCheck.checked;
            // If currently on Summary tab, switch to Geographic Map to show the filtered NOK links immediately
            if (onlyOpticalNokCheck.checked && appState.nms.layoutMode === "summary") {
                switchNmsLayout("geo");
            }
            handleFilterChange();
        });
    }
    
    // Bind SVG Mouse Zoom and Pan Event Listeners
    setupNmsCanvasInteractions();

    // Excel Batch Modal buttons
    const batchBtn = document.getElementById("nms-batch-btn");
    const closeBatchX = document.getElementById("close-batch-modal-x");
    const cancelBatch = document.getElementById("batch-cancel-btn");
    const copyCurrentBatch = document.getElementById("batch-copy-current-btn");
    const applyBatch = document.getElementById("batch-apply-btn");
    const pasteArea = document.getElementById("batch-paste-area");
    
    if (batchBtn) batchBtn.addEventListener("click", openBatchModal);
    if (closeBatchX) closeBatchX.addEventListener("click", closeBatchModal);
    if (cancelBatch) cancelBatch.addEventListener("click", closeBatchModal);
    if (copyCurrentBatch) copyCurrentBatch.addEventListener("click", copyCurrentDevicesToClipboard);
    if (applyBatch) applyBatch.addEventListener("click", applyBatchImport);
    if (pasteArea) {
        pasteArea.addEventListener("input", handleBatchPasteAreaInput);
    }
    
    // Excel Connections Batch Modal buttons
    const connBatchBtn = document.getElementById("nms-conn-batch-btn");
    const closeConnBatchX = document.getElementById("close-conn-batch-modal-x");
    const cancelConnBatch = document.getElementById("batch-conn-cancel-btn");
    const copyCurrentConnBatch = document.getElementById("batch-copy-current-conns-btn");
    const applyConnBatch = document.getElementById("batch-conn-apply-btn");
    const pasteConnArea = document.getElementById("batch-conn-paste-area");
    
    if (connBatchBtn) connBatchBtn.addEventListener("click", openConnBatchModal);
    if (closeConnBatchX) closeConnBatchX.addEventListener("click", closeConnBatchModal);
    if (cancelConnBatch) cancelConnBatch.addEventListener("click", closeConnBatchModal);
    if (copyCurrentConnBatch) copyCurrentConnBatch.addEventListener("click", copyCurrentConnectionsToClipboard);
    if (applyConnBatch) applyConnBatch.addEventListener("click", applyConnBatchImport);
    if (pasteConnArea) {
        pasteConnArea.addEventListener("input", handleConnBatchPasteAreaInput);
    }
    
    // Sidebar toggle collapse handle button
    const sidebarToggle = document.getElementById("nms-sidebar-toggle-btn");
    if (sidebarToggle) {
        sidebarToggle.addEventListener("click", () => {
            const layout = document.querySelector(".nms-main-layout");
            layout.classList.toggle("sidebar-collapsed");
            
            // Adjust SVG sizing after transition completes so labels and lines align perfectly
            setTimeout(updateLinksSvgPosition, 350);
        });
    }

    // Layout switcher logic
    const logicalBtn = document.getElementById("layout-logical-btn");
    const geoBtn = document.getElementById("layout-geo-btn");
    const summaryBtn = document.getElementById("layout-summary-btn");
    if (logicalBtn && geoBtn) {
        logicalBtn.addEventListener("click", () => switchNmsLayout("logical"));
        geoBtn.addEventListener("click", () => switchNmsLayout("geo"));
        if (summaryBtn) summaryBtn.addEventListener("click", () => switchNmsLayout("summary"));
    }

    // NMS Legend toggle collapse listener
    const legendToggle = document.getElementById("nms-legend-toggle");
    const legendContainer = document.getElementById("nms-legend");
    if (legendToggle && legendContainer) {
        legendToggle.addEventListener("click", () => {
            legendContainer.classList.toggle("collapsed");
        });
    }

    // NMS Controls toggle collapse listener
    const controlsToggle = document.getElementById("nms-controls-toggle");
    const controlsContainer = document.getElementById("nms-floating-controls");
    if (controlsToggle && controlsContainer) {
        controlsToggle.addEventListener("click", () => {
            controlsContainer.classList.toggle("collapsed");
        });
    }

    // Fullscreen Topology Panel Toggle
    const fullscreenBtn = document.getElementById("nms-fullscreen-btn");
    if (fullscreenBtn) {
        fullscreenBtn.addEventListener("click", () => {
            const target = document.querySelector(".nms-main-layout");
            if (!target) return;
            
            if (!document.fullscreenElement) {
                target.requestFullscreen().catch(err => {
                    console.error("Error entering fullscreen:", err);
                });
            } else {
                document.exitFullscreen();
            }
        });
    }

    document.addEventListener("fullscreenchange", () => {
        const btn = document.getElementById("nms-fullscreen-btn");
        if (btn) {
            if (document.fullscreenElement) {
                btn.innerHTML = `<i class="fa-solid fa-compress"></i> <span>Minimize</span>`;
            } else {
                btn.innerHTML = `<i class="fa-solid fa-expand"></i> <span>Fullscreen</span>`;
            }
        }
        // Force SVG layout recalculation
        setTimeout(updateLinksSvgPosition, 200);
    });

    // Theme Toggle (Light / Dark mode)
    const themeBtn = document.getElementById("theme-toggle-btn");
    if (themeBtn) {
        themeBtn.addEventListener("click", () => {
            document.body.classList.toggle("light-mode");
            const isLight = document.body.classList.contains("light-mode");
            
            if (isLight) {
                themeBtn.innerHTML = `<i class="fa-solid fa-moon"></i>`;
            } else {
                themeBtn.innerHTML = `<i class="fa-solid fa-sun"></i>`;
            }
            
            // Leaflet base layer uses OpenStreetMap tiles with CSS dark-mode filter on .leaflet-tile-pane
            if (appState.nms.tileLayer && appState.nms.map) {
                appState.nms.tileLayer.setUrl('https://tile.openstreetmap.org/{z}/{x}/{y}.png');
            }

            // Refresh any loaded Plotly charts to update gridlines/text color
            try {
                if (document.getElementById('overlay-plotly-chart') && appState.selectedFolderId) {
                    loadCombinedOverlayChart();
                }
            } catch (err) {}

            try {
                if (document.getElementById('modal-plotly-chart') && appState.activeSorData) {
                    replotModalChart();
                }
            } catch (err) {}
        });
    }
}

function switchView(viewName) {
    const otdrBtn = document.getElementById("nav-otdr-btn");
    const nmsBtn = document.getElementById("nav-nms-btn");
    const consoleBtn = document.getElementById("nav-console-btn");
    const scannerBar = document.getElementById("otdr-scanner-bar");
    const settingsBtn = document.getElementById("settings-toggle-btn");
    const viewport = document.querySelector(".app-viewport");
    
    const otdrView = document.getElementById("folder-grid-view");
    const detailView = document.getElementById("folder-detail-view");
    const nmsView = document.getElementById("nms-topology-view");
    const consoleView = document.getElementById("console-view");
    
    // Reset active buttons
    if (otdrBtn) otdrBtn.classList.remove("active");
    if (nmsBtn) nmsBtn.classList.remove("active");
    if (consoleBtn) consoleBtn.classList.remove("active");
    
    // Hide all view panels
    if (otdrView) otdrView.classList.add("hidden");
    if (detailView) detailView.classList.add("hidden");
    if (nmsView) nmsView.classList.add("hidden");
    if (consoleView) consoleView.classList.add("hidden");
    
    if (viewName === "otdr") {
        if (otdrBtn) otdrBtn.classList.add("active");
        if (scannerBar) scannerBar.classList.remove("hidden");
        if (settingsBtn) settingsBtn.classList.remove("hidden");
        
        if (viewport) viewport.classList.remove("flush-viewport");
        
        const headerCtrls = document.getElementById("nms-header-controls");
        if (headerCtrls) headerCtrls.classList.add("hidden");
        
        // Restore active OTDR view based on state
        if (appState.currentFolder) {
            if (detailView) detailView.classList.remove("hidden");
        } else {
            if (otdrView) otdrView.classList.remove("hidden");
        }
    } else if (viewName === "nms") {
        if (nmsBtn) nmsBtn.classList.add("active");
        if (scannerBar) scannerBar.classList.add("hidden");
        if (settingsBtn) settingsBtn.classList.add("hidden");
        
        if (viewport) viewport.classList.add("flush-viewport");
        
        const headerCtrls = document.getElementById("nms-header-controls");
        if (headerCtrls) headerCtrls.classList.remove("hidden");
        
        if (nmsView) nmsView.classList.remove("hidden");
        
        // Load and render NMS
        initNmsView();
    } else if (viewName === "console") {
        if (consoleBtn) consoleBtn.classList.add("active");
        if (scannerBar) scannerBar.classList.add("hidden");
        if (settingsBtn) settingsBtn.classList.add("hidden");
        
        if (viewport) viewport.classList.remove("flush-viewport");
        
        const headerCtrls = document.getElementById("nms-header-controls");
        if (headerCtrls) headerCtrls.classList.add("hidden");
        
        if (consoleView) consoleView.classList.remove("hidden");
        
        // Initialize Console elements and listeners
        initConsoleView();
    }
}

async function initNmsView() {
    showLoader(true);
    try {
        await loadNmsTopology();
        resetNmsZoomAndPan();
        renderNmsGraph();
        renderNmsSpreadsheet();
        validateNmsData();
        markUnsavedChanges(false);
    } catch (err) {
        console.error("Failed to load topology:", err);
    } finally {
        showLoader(false);
    }
}

async function syncNmsOpticalScanData() {
    if (!appState.nms.opticalScan) {
        appState.nms.opticalScan = { updated_at: null, results: [], byDevicePort: {} };
    }
    try {
        const res = await fetch(`${API_BASE}/console/optical-scan`);
        if (res.ok) {
            const scanData = await res.json();
            const results = Array.isArray(scanData.results) ? scanData.results : [];
            const byDevicePort = {};
            results.forEach(item => {
                if (item.router && item.port) {
                    byDevicePort[`${item.router.trim()}::${item.port.trim()}`] = item;
                }
            });
            appState.nms.opticalScan = {
                updated_at: scanData.updated_at || null,
                results: results,
                byDevicePort: byDevicePort
            };
        }
    } catch (err) {
        console.error("Failed to sync optical scan data for topology:", err);
    }
}

function evaluatePortOpticalHealth(optItem) {
    if (!optItem) {
        return { severity: "none", statusText: "Not Scanned", color: "var(--text-muted)", rxText: "-" };
    }
    if (optItem.status === "unsupported") {
        return { severity: "unsupported", statusText: "DDM N/A", color: "var(--text-muted)", rxText: "N/A" };
    }
    if (optItem.status !== "success") {
        const errLabel = optItem.status === "unreachable" ? "Unreachable" : "Scan Failed";
        return { severity: "alarm", statusText: errLabel, color: "#ef4444", rxText: errLabel };
    }
    let tStatus = optItem.thresholdStatus;
    if (!tStatus && optItem.value !== undefined && optItem.value !== null) {
        if (optItem.value <= optItem.lowAlarm) tStatus = "Low Alarm";
        else if (optItem.value <= optItem.lowWarn) tStatus = "Low Warning";
        else if (optItem.value >= optItem.highAlarm) tStatus = "High Alarm";
        else if (optItem.value >= optItem.highWarn) tStatus = "High Warning";
        else tStatus = "Normal";
    }
    tStatus = tStatus || "Normal";
    const rxText = optItem.displayText || (optItem.value !== undefined && optItem.value !== null ? `${Number(optItem.value).toFixed(2)} dBm` : "-");

    if (tStatus.includes("Alarm")) {
        return { severity: "alarm", statusText: tStatus, color: "#ef4444", rxText };
    }
    if (tStatus.includes("Warning")) {
        return { severity: "warning", statusText: tStatus, color: "#f97316", rxText };
    }
    return { severity: "normal", statusText: "Normal", color: "#10b981", rxText };
}

function getConnectionOpticalInfo(conn) {
    const byDevicePort = (appState.nms.opticalScan && appState.nms.opticalScan.byDevicePort) || {};
    const sKey = `${(conn.source || "").trim()}::${(conn.source_interface || "").trim()}`;
    const tKey = `${(conn.target || "").trim()}::${(conn.target_interface || "").trim()}`;
    const sourceOpt = byDevicePort[sKey] || null;
    const targetOpt = byDevicePort[tKey] || null;

    const sHealth = evaluatePortOpticalHealth(sourceOpt);
    const tHealth = evaluatePortOpticalHealth(targetOpt);

    const rank = { alarm: 3, warning: 2, normal: 1, unsupported: 0, none: 0 };
    const sRank = rank[sHealth.severity] || 0;
    const tRank = rank[tHealth.severity] || 0;

    let worstSeverity = "none";
    let primaryOpt = sourceOpt || targetOpt;
    let primaryHealth = sourceOpt ? sHealth : tHealth;
    let primaryDevice = sourceOpt ? conn.source : conn.target;
    let primaryPort = sourceOpt ? conn.source_interface : conn.target_interface;

    if (sRank >= tRank && sRank > 0) {
        worstSeverity = sHealth.severity;
        primaryOpt = sourceOpt;
        primaryHealth = sHealth;
        primaryDevice = conn.source;
        primaryPort = conn.source_interface;
    } else if (tRank > sRank && tRank > 0) {
        worstSeverity = tHealth.severity;
        primaryOpt = targetOpt;
        primaryHealth = tHealth;
        primaryDevice = conn.target;
        primaryPort = conn.target_interface;
    }

    const tooltipLines = [];
    if (sourceOpt) {
        tooltipLines.push(`Optical Rx (${conn.source} [${conn.source_interface}]): ${sHealth.rxText} [${sHealth.statusText}]`);
    }
    if (targetOpt) {
        tooltipLines.push(`Optical Rx (${conn.target} [${conn.target_interface}]): ${tHealth.rxText} [${tHealth.statusText}]`);
    }

    return {
        sourceOpt,
        targetOpt,
        sHealth,
        tHealth,
        worstSeverity,
        isNok: worstSeverity === "alarm" || worstSeverity === "warning",
        primaryOpt,
        primaryHealth,
        primaryDevice,
        primaryPort,
        tooltipLines
    };
}

function buildCleanLinkTooltipHtml(conn, optInfo) {
    const srcPort = conn.source_interface || "-";
    const tgtPort = conn.target_interface || "-";
    const cap = `${conn.bitrate || 10}G ${conn.type || "Interlink"}`;
    const statusDotColor = conn.status === "Active" ? "#10b981" : "#94a3b8";

    const renderTooltipOptLine = (label, devName, portName, opt, health) => {
        if (!opt) {
            return `
                <div style="display: flex; align-items: center; justify-content: space-between; gap: 12px; font-size: 0.71rem;">
                    <span style="color: var(--text-muted);">${escapeHTML(devName)} [${escapeHTML(portName)}]:</span>
                    <span style="color: #64748b; font-family: monospace;">Not Scanned</span>
                </div>
            `;
        }
        const limitStr = (opt.status === "success" && opt.lowWarn !== undefined && opt.lowAlarm !== undefined)
            ? ` <span style="color: #64748b; font-size: 0.65rem;">(W:${Number(opt.lowWarn).toFixed(1)}/A:${Number(opt.lowAlarm).toFixed(1)})</span>`
            : "";
        return `
            <div style="display: flex; align-items: center; justify-content: space-between; gap: 12px; font-size: 0.72rem;">
                <span style="color: var(--text-muted);">${escapeHTML(devName)} [${escapeHTML(portName)}]:</span>
                <span style="font-family: monospace;"><strong style="color: ${health.color};">${escapeHTML(health.rxText)}</strong> <span style="color: ${health.color}; font-size: 0.68rem;">[${escapeHTML(health.statusText)}]</span>${limitStr}</span>
            </div>
        `;
    };

    let optRowHtml = "";
    if (optInfo && (optInfo.sourceOpt || optInfo.targetOpt)) {
        optRowHtml = `
            <div style="margin-top: 6px; padding-top: 6px; border-top: 1px solid rgba(255,255,255,0.1); display: flex; flex-direction: column; gap: 3px;">
                ${renderTooltipOptLine("Source", conn.source, srcPort, optInfo.sourceOpt, optInfo.sHealth)}
                ${renderTooltipOptLine("Peer", conn.target, tgtPort, optInfo.targetOpt, optInfo.tHealth)}
            </div>
        `;
    }

    return `
        <div style="display: flex; flex-direction: column; gap: 3px; min-width: 240px;">
            <div style="display: flex; align-items: center; justify-content: space-between; gap: 12px;">
                <span style="font-weight: 700; color: #f8fafc; font-size: 0.8rem;">${escapeHTML(conn.source)} ↔ ${escapeHTML(conn.target)}</span>
                <span style="font-size: 0.68rem; padding: 1px 6px; border-radius: 4px; background: rgba(255,255,255,0.08); color: #cbd5e1; font-weight: 600;">${escapeHTML(cap)}</span>
            </div>
            <div style="display: flex; align-items: center; justify-content: space-between; gap: 10px; font-size: 0.72rem; color: #94a3b8; font-family: monospace;">
                <span>${escapeHTML(srcPort)} → ${escapeHTML(tgtPort)}</span>
                <span style="display: inline-flex; align-items: center; gap: 4px; font-family: 'Inter', sans-serif;"><span style="width: 6px; height: 6px; border-radius: 50%; background: ${statusDotColor};"></span>${escapeHTML(conn.status || "Active")}</span>
            </div>
            ${optRowHtml}
        </div>
    `;
}

function renderOpticalEndpointBox(roleLabel, deviceName, portName, optItem) {
    if (!optItem) {
        return `
            <div style="margin-top: 6px; padding: 7px 10px; border-radius: 6px; background: rgba(255,255,255,0.02); border: 1px dashed rgba(255,255,255,0.1); font-size: 0.72rem; display: flex; justify-content: space-between; align-items: center; gap: 8px;">
                <span style="font-weight: 600; color: var(--text-muted); font-family: monospace;">${escapeHTML(roleLabel)}: ${escapeHTML(deviceName)} [${escapeHTML(portName || '-')}]</span>
                <span class="badge" style="font-size: 0.62rem; padding: 2px 6px; background: rgba(255,255,255,0.05); color: var(--text-muted);">Not Scanned</span>
            </div>
        `;
    }
    const health = evaluatePortOpticalHealth(optItem);
    const isAlarm = health.severity === "alarm";
    const isWarn = health.severity === "warning";

    const borderCol = isAlarm ? "rgba(239, 68, 68, 0.45)" : isWarn ? "rgba(249, 115, 22, 0.45)" : "rgba(16, 185, 129, 0.25)";
    const bgCol = isAlarm ? "rgba(239, 68, 68, 0.08)" : isWarn ? "rgba(249, 115, 22, 0.08)" : "rgba(16, 185, 129, 0.04)";
    const badgeBg = isAlarm ? "rgba(239, 68, 68, 0.2)" : isWarn ? "rgba(249, 115, 22, 0.2)" : "rgba(16, 185, 129, 0.15)";

    if (optItem.status !== "success") {
        return `
            <div style="margin-top: 6px; padding: 8px 10px; border-radius: 6px; background: rgba(255,255,255,0.03); border: 1px solid var(--border-color); font-size: 0.74rem; display: flex; justify-content: space-between; align-items: center; gap: 8px;">
                <span style="font-weight: 600; color: var(--text-main); font-family: monospace;">${escapeHTML(roleLabel)}: ${escapeHTML(deviceName)} [${escapeHTML(portName || '-')}]</span>
                <span class="badge" style="font-size: 0.64rem; padding: 2px 6px; background: rgba(255,255,255,0.06); color: var(--text-muted);">${escapeHTML(health.statusText)}</span>
            </div>
        `;
    }

    const lowA = Number(optItem.lowAlarm ?? -20).toFixed(1);
    const lowW = Number(optItem.lowWarn ?? -16).toFixed(1);

    return `
        <div style="margin-top: 6px; padding: 9px 11px; border-radius: 6px; background: ${bgCol}; border: 1px solid ${borderCol}; display: flex; flex-direction: column; gap: 5px;">
            <div style="display: flex; justify-content: space-between; align-items: center; gap: 6px;">
                <span style="font-size: 0.73rem; font-weight: 700; color: var(--text-main); font-family: monospace;">
                    <span style="color: var(--text-muted); font-weight: 500;">${escapeHTML(roleLabel)}:</span> ${escapeHTML(deviceName)} [${escapeHTML(portName || '-')}]
                </span>
                <span class="badge" style="font-size: 0.64rem; padding: 2px 7px; background: ${badgeBg}; color: ${health.color}; border: 1px solid ${borderCol}; font-weight: 700; white-space: nowrap;">
                    ${escapeHTML(health.statusText)}
                </span>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-size: 0.72rem; color: var(--text-muted);">Rx Power:</span>
                <span style="font-size: 0.92rem; font-weight: 800; font-family: monospace; color: ${health.color};">${escapeHTML(health.rxText)}</span>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.68rem; color: var(--text-muted); border-top: 1px dashed rgba(255,255,255,0.08); padding-top: 4px;">
                <span>Threshold:</span>
                <span style="font-family: monospace;">Warn ${lowW} | Alarm ${lowA} dBm</span>
            </div>
        </div>
    `;
}

async function loadNmsTopology() {
    const res = await fetch(`${API_BASE}/topology`);
    if (!res.ok) throw new Error("API server error loading topology");
    const data = await res.json();
    
    appState.nms.devices = data.devices || [];
    appState.nms.connections = data.connections || [];
    await syncNmsOpticalScanData();
    
    // Auto coordinate generation if missing
    let needsArrange = false;
    appState.nms.devices.forEach((dev, idx) => {
        // Fallbacks for geographic coordinates
        if (dev.latitude === undefined || dev.latitude === null) dev.latitude = -6.2 - (idx * 0.05);
        if (dev.longitude === undefined || dev.longitude === null) dev.longitude = 106.8 + (idx * 0.03);
        
        if (dev.x === undefined || dev.y === undefined || dev.x === 0 || dev.y === 0) {
            // Assign default circular slots initially
            const angle = (idx / appState.nms.devices.length) * 2 * Math.PI;
            dev.x = Math.round(500 + 200 * Math.cos(angle));
            dev.y = Math.round(300 + 120 * Math.sin(angle));
            needsArrange = true;
        }
        dev.logical_x = dev.x;
        dev.logical_y = dev.y;
    });
    
    if (needsArrange) {
        const algoSelect = document.getElementById("nms-arrange-algorithm");
        const algo = algoSelect ? algoSelect.value : "radial";
        if (algo === "force") {
            autoArrangeForceDirected();
        } else if (algo === "radial") {
            autoArrangeRadial();
        } else {
            autoArrangeTopology();
        }
        appState.nms.devices.forEach(dev => {
            dev.logical_x = dev.x;
            dev.logical_y = dev.y;
        });
    }

    switchNmsLayout(appState.nms.layoutMode || "geo");
}

function switchNmsLayout(mode) {
    appState.nms.layoutMode = mode;
    
    const logicalBtn = document.getElementById("layout-logical-btn");
    const geoBtn = document.getElementById("layout-geo-btn");
    const summaryBtn = document.getElementById("layout-summary-btn");
    const arrangeGroup = document.getElementById("nms-arrange-group");
    const canvasContainer = document.querySelector(".nms-canvas-container");
    const mapContainer = document.getElementById("nms-map-container");
    const svgCanvas = document.getElementById("nms-svg");
    const summaryContainer = document.getElementById("nms-summary-container");
    const controlsContainer = document.getElementById("nms-floating-controls");
    const legendContainer = document.getElementById("nms-legend");
    
    if (canvasContainer) {
        if (mode === "geo") {
            canvasContainer.classList.add("layout-mode-geo");
        } else {
            canvasContainer.classList.remove("layout-mode-geo");
        }
    }
    
    if (mode === "summary") {
        if (logicalBtn) logicalBtn.classList.remove("active");
        if (geoBtn) geoBtn.classList.remove("active");
        if (summaryBtn) summaryBtn.classList.add("active");
        if (arrangeGroup) arrangeGroup.classList.add("hidden");
        
        if (mapContainer) mapContainer.classList.add("hidden");
        if (svgCanvas) svgCanvas.classList.add("hidden");
        if (summaryContainer) summaryContainer.classList.remove("hidden");
        if (controlsContainer) controlsContainer.classList.add("hidden");
        if (legendContainer) legendContainer.classList.add("hidden");
        
        updateNmsSummaryDashboard();
    } else if (mode === "logical") {
        if (logicalBtn) logicalBtn.classList.add("active");
        if (geoBtn) geoBtn.classList.remove("active");
        if (summaryBtn) summaryBtn.classList.remove("active");
        if (arrangeGroup) arrangeGroup.classList.remove("hidden");
        
        if (mapContainer) mapContainer.classList.add("hidden");
        if (svgCanvas) svgCanvas.classList.remove("hidden");
        if (summaryContainer) summaryContainer.classList.add("hidden");
        if (controlsContainer) controlsContainer.classList.remove("hidden");
        if (legendContainer) legendContainer.classList.remove("hidden");
        
        appState.nms.mapCentered = false;
        
        // Auto-arrange with Radial Ring Layout as default when opening Logical View
        const arrangeAlgoSelect = document.getElementById("nms-arrange-algorithm");
        if (arrangeAlgoSelect) arrangeAlgoSelect.value = "radial";
        autoArrangeRadial();
    } else {
        if (logicalBtn) logicalBtn.classList.remove("active");
        if (geoBtn) geoBtn.classList.add("active");
        if (summaryBtn) summaryBtn.classList.remove("active");
        if (arrangeGroup) arrangeGroup.classList.add("hidden");
        
        if (mapContainer) mapContainer.classList.remove("hidden");
        if (svgCanvas) svgCanvas.classList.add("hidden");
        if (summaryContainer) summaryContainer.classList.add("hidden");
        if (controlsContainer) controlsContainer.classList.remove("hidden");
        if (legendContainer) legendContainer.classList.remove("hidden");
        
        appState.nms.mapCentered = false;
        renderNmsLeafletMap();
    }
}

function renderNmsLeafletMap() {
    const mapContainer = document.getElementById("nms-map-container");
    const svgCanvas = document.getElementById("nms-svg");
    if (!mapContainer || !svgCanvas) return;
    
    mapContainer.classList.remove("hidden");
    svgCanvas.classList.add("hidden");
    
    const searchInput = document.getElementById("nms-search-input");
    const query = searchInput ? searchInput.value.toLowerCase().trim() : "";
    
    if (!appState.nms.map) {
        appState.nms.map = L.map('nms-map-container', {
            zoomControl: false,
            attributionControl: true
        }).setView([-6.2, 106.8], 10);
        
        appState.nms.tileLayer = L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
            maxZoom: 19
        }).addTo(appState.nms.map);
        
        appState.nms.mapLayers = L.featureGroup().addTo(appState.nms.map);
    }
    
    // Force Leaflet to recalculate container bounds and size (fixes display none zero-size cache issues)
    if (appState.nms.map) {
        appState.nms.map.invalidateSize();
    }
    
    appState.nms.mapLayers.clearLayers();
    
    // Group devices by geographic coordinate
    const filters = getVisibilityFilters();
    const activeSelectionId = appState.nms.selectedNodeId;
    const selectedConn = appState.nms.connections.find(c => c.id === appState.nms.selectedConnectionId);
    const selectedPeerConns = selectedConn ? getRelatedPeerConnections(selectedConn) : [];
    const selectedPeerConnIds = new Set(selectedPeerConns.map(c => c.id));

    const nokDeviceNames = new Set();
    if (filters.onlyOpticalNok) {
        appState.nms.connections.forEach(c => {
            if (!c.hidden && (getConnectionOpticalInfo(c).isNok || selectedPeerConnIds.has(c.id))) {
                nokDeviceNames.add(c.source);
                nokDeviceNames.add(c.target);
            }
        });
    }

    const coordsMap = {};
    const validDevs = appState.nms.devices.filter(d => 
        !d.hidden &&
        d.latitude !== undefined && 
        d.longitude !== undefined && 
        !isNaN(parseFloat(d.latitude)) && 
        !isNaN(parseFloat(d.longitude)) &&
        ((d.type === "Router" && filters.showRouters) || (d.type === "OLT" && filters.showOlts))
    );
    
    validDevs.forEach(dev => {
        const lat = parseFloat(dev.latitude);
        const lng = parseFloat(dev.longitude);
        const coordKey = `${lat.toFixed(4)},${lng.toFixed(4)}`;
        if (!coordsMap[coordKey]) coordsMap[coordKey] = [];
        coordsMap[coordKey].push(dev);
    });
    
    const primaries = [];
    const deviceMapCoords = {};
    
    Object.keys(coordsMap).forEach(key => {
        const group = coordsMap[key];
        const lat = parseFloat(key.split(",")[0]);
        const lng = parseFloat(key.split(",")[1]);
        
        // Find if there is a Router in the group
        const routerDev = group.find(d => d.type === "Router");
        // Visual representation prefers Router if present, otherwise first OLT
        const displayDev = routerDev || group[0];
        
        // The selection target (active selection or Router or first OLT)
        const selected = group.find(d => d.id === activeSelectionId);
        const primary = selected || routerDev || group[0];
        
        primaries.push({
            primary: primary,
            displayDev: displayDev,
            group: group,
            lat: lat,
            lng: lng
        });
        
        group.forEach(dev => {
            deviceMapCoords[dev.name] = [lat, lng];
        });
    });
    
    // Render polylines
    const devicePairs = {};
    appState.nms.connections.forEach(conn => {
        if (!conn.source || !conn.target) return;
        if (conn.hidden) return;
        
        const sourceDev = appState.nms.devices.find(d => d.name === conn.source);
        const targetDev = appState.nms.devices.find(d => d.name === conn.target);
        if (!sourceDev || !targetDev) return;
        if (sourceDev.hidden || targetDev.hidden) return;
        
        const pairKey = [conn.source, conn.target].sort().join("<-->");
        if (!devicePairs[pairKey]) devicePairs[pairKey] = [];
        devicePairs[pairKey].push(conn);
    });
    
    Object.keys(devicePairs).forEach(pairKey => {
        const conns = devicePairs[pairKey];
        if (conns.length === 0) return;
        
        const first = conns[0];
        const sLoc = deviceMapCoords[first.source];
        const tLoc = deviceMapCoords[first.target];
        if (!sLoc || !tLoc) return;
        
        // Skip loopback line if co-located
        if (sLoc[0] === tLoc[0] && sLoc[1] === tLoc[1]) return;
        
        let isLinkMatch = true;
        if (query) {
            isLinkMatch = conns.some(c => 
                (c.source && c.source.toLowerCase().includes(query)) ||
                (c.target && c.target.toLowerCase().includes(query)) ||
                (c.link && c.link.toLowerCase().includes(query)) ||
                (c.source_interface && c.source_interface.toLowerCase().includes(query)) ||
                (c.target_interface && c.target_interface.toLowerCase().includes(query))
            );
        }
        
        const n = conns.length;
        const spacing = 0.00008; // spacing distance in degrees (~8 meters)
        
        const lat1 = sLoc[0], lng1 = sLoc[1];
        const lat2 = tLoc[0], lng2 = tLoc[1];
        const dLat = lat2 - lat1;
        const dLng = lng2 - lng1;
        const len = Math.sqrt(dLat * dLat + dLng * dLng);
        
        let nx = 0, ny = 0;
        if (len > 0) {
            nx = -dLng / len;
            ny = dLat / len;
        }
        
        conns.forEach((conn, index) => {
            const dist = (index - (n - 1) / 2.0) * spacing;
            const isConnSelected = conn.id === appState.nms.selectedConnectionId;
            const optInfo = getConnectionOpticalInfo(conn);

            // When "Optical NOK Only" is toggled on, hide non-NOK links unless it's a peer link of the clicked connection
            if (filters.onlyOpticalNok && !optInfo.isNok && !selectedPeerConnIds.has(conn.id)) return;

            const connMatchesFilter = isLinkMatch;
            
            const bitrateVal = parseInt(conn.bitrate) || 10;
            let color = "#10b981";
            if (bitrateVal >= 100) color = "#3b82f6";
            else if (bitrateVal >= 40) color = "#06b6d4";
            
            let weight = 2.0;
            if (bitrateVal >= 100) weight = 5.0;
            else if (bitrateVal >= 40) weight = 3.5;
            
            if (conns.length > 1) {
                weight += 2.0; // Bolder weight for aggregated links!
            }

            let optClass = "";
            if (optInfo.worstSeverity === "alarm") {
                color = "#ef4444";
                weight = Math.max(weight + 1.5, 4.5);
                optClass = "map-optical-alarm";
            } else if (optInfo.worstSeverity === "warning") {
                color = "#f97316";
                weight = Math.max(weight + 1.0, 4.0);
                optClass = "map-optical-warning";
            }
            
            const tooltipHtml = buildCleanLinkTooltipHtml(conn, optInfo);
            const lineClass = [isConnSelected ? "map-selected-line" : "", optClass].filter(Boolean).join(" ");
            
            if (conn.dual_track) {
                const subOffset = 0.00003;
                const dualColor = optInfo.isNok ? color : "#f59e0b";
                
                const line1 = L.polyline([
                    [lat1 + nx * (dist + subOffset), lng1 + ny * (dist + subOffset)],
                    [lat2 + nx * (dist + subOffset), lng2 + ny * (dist + subOffset)]
                ], {
                    color: dualColor,
                    weight: isConnSelected ? 6.5 : 4.5,
                    dashArray: conn.status === "Backup" ? "6, 6" : null,
                    opacity: connMatchesFilter ? 0.9 : 0.12,
                    className: lineClass
                }).addTo(appState.nms.mapLayers);
                
                const line2 = L.polyline([
                    [lat1 + nx * (dist - subOffset), lng1 + ny * (dist - subOffset)],
                    [lat2 + nx * (dist - subOffset), lng2 + ny * (dist - subOffset)]
                ], {
                    color: dualColor,
                    weight: isConnSelected ? 6.5 : 4.5,
                    dashArray: conn.status === "Backup" ? "6, 6" : null,
                    opacity: connMatchesFilter ? 0.9 : 0.12,
                    className: lineClass
                }).addTo(appState.nms.mapLayers);
                
                const onClick = () => selectNmsConnection(conn.id);
                line1.bindTooltip(tooltipHtml, { sticky: true });
                line2.bindTooltip(tooltipHtml, { sticky: true });
                line1.on("click", onClick);
                line2.on("click", onClick);
            } else {
                const polyline = L.polyline([
                    [lat1 + nx * dist, lng1 + ny * dist],
                    [lat2 + nx * dist, lng2 + ny * dist]
                ], {
                    color: color,
                    weight: isConnSelected ? 7.0 : weight,
                    dashArray: conn.status === "Backup" ? "6, 6" : null,
                    opacity: connMatchesFilter ? 0.9 : 0.12,
                    className: lineClass
                }).addTo(appState.nms.mapLayers);
                
                polyline.bindTooltip(tooltipHtml, { sticky: true });
                polyline.on("click", () => selectNmsConnection(conn.id));
            }

            if (optInfo.isNok && connMatchesFilter) {
                const midLat = (lat1 + lat2) / 2.0 + nx * dist;
                const midLng = (lng1 + lng2) / 2.0 + ny * dist;
                const badgeIcon = L.divIcon({
                    className: "",
                    html: `<div class="nms-map-optical-badge ${optInfo.worstSeverity}"><i class="fa-solid fa-triangle-exclamation"></i> ${escapeHTML(optInfo.primaryHealth.rxText)}</div>`,
                    iconSize: [0, 0]
                });
                const badgeMarker = L.marker([midLat, midLng], { icon: badgeIcon, zIndexOffset: 900 }).addTo(appState.nms.mapLayers);
                badgeMarker.bindTooltip(tooltipHtml, { direction: "top", offset: [0, -10] });
                badgeMarker.on("click", () => selectNmsConnection(conn.id));
            }
        });
    });
    
    // Render markers (One marker per coordinate cluster)
    primaries.forEach(p => {
        if (filters.onlyOpticalNok && !p.group.some(d => nokDeviceNames.has(d.name))) {
            return;
        }
        const dev = p.displayDev;
        const targetDev = p.primary;
        const loc = [p.lat, p.lng];
        
        let isNodeMatch = true;
        if (query) {
            isNodeMatch = p.group.some(d => 
                (d.name && d.name.toLowerCase().includes(query)) ||
                (d.ip && d.ip.toLowerCase().includes(query)) ||
                (d.brand && d.brand.toLowerCase().includes(query)) ||
                (d.model && d.model.toLowerCase().includes(query)) ||
                (d.type && d.type.toLowerCase().includes(query)) ||
                (d.status && d.status.toLowerCase().includes(query))
            );
        }
        
        const groupHasSelected = p.group.some(d => 
            d.id === activeSelectionId || 
            (selectedConn && (d.name === selectedConn.source || d.name === selectedConn.target))
        );
        
        const customIcon = L.divIcon({
            className: `nms-map-marker ${groupHasSelected ? 'selected' : ''}`,
            html: `<div class="nms-node type-${dev.type.toLowerCase()} status-${dev.status.toLowerCase()} ${groupHasSelected ? 'selected' : ''} ${!isNodeMatch ? 'search-dimmed' : ''}">
                    <div class="nms-node-bg" style="width: 24px; height: 24px; border-radius: ${dev.type === 'Router' ? '50%' : '4px'}; border: 2px solid var(--border-color); background: var(--bg-app); display: flex; align-items: center; justify-content: center; position: relative;">
                        <i class="fa-solid ${dev.type === 'Router' ? 'fa-server' : 'fa-sitemap'}" style="color: ${dev.type === 'Router' ? 'var(--primary)' : 'hsl(280, 80%, 60%)'}; font-size: 10px; z-index: 2;"></i>
                        ${groupHasSelected ? '<div class="marker-pulse-halo"></div>' : ''}
                    </div>
                   </div>`,
            iconSize: [24, 24],
            iconAnchor: [12, 12]
        });
        
        const marker = L.marker(loc, {
            icon: customIcon,
            draggable: appState.nms.editModeEnabled
        }).addTo(appState.nms.mapLayers);
        
        marker.on('drag', (e) => {
            const newLatLng = e.target.getLatLng();
            const lat = parseFloat(newLatLng.lat.toFixed(6));
            const lng = parseFloat(newLatLng.lng.toFixed(6));
            
            p.group.forEach(member => {
                member.latitude = lat;
                member.longitude = lng;
                
                const activeDev = appState.nms.devices.find(d => d.id === member.id);
                if (activeDev) {
                    activeDev.latitude = lat;
                    activeDev.longitude = lng;
                }
                
                const row = document.querySelector(`.nms-device-row[data-id="${member.id}"]`);
                if (row) {
                    const latInput = row.querySelector('input[data-field="latitude"]');
                    const lngInput = row.querySelector('input[data-field="longitude"]');
                    if (latInput) latInput.value = lat;
                    if (lngInput) lngInput.value = lng;
                }
            });
        });
        
        marker.on('dragend', () => {
            appState.nms.hasChanges = true;
            markUnsavedChanges(true);
            validateNmsData();
            renderNmsLeafletMap();
        });
        
        marker.on('click', () => {
            selectNmsNode(targetDev.id);
        });
    });
    
    if (appState.nms.selectedNodeId) {
        const selectedDev = appState.nms.devices.find(d => d.id === appState.nms.selectedNodeId);
        if (selectedDev && selectedDev.latitude !== undefined && selectedDev.longitude !== undefined) {
            appState.nms.map.setView([parseFloat(selectedDev.latitude), parseFloat(selectedDev.longitude)], 13);
            appState.nms.mapCentered = true;
        }
    } else if (!appState.nms.mapCentered) {
        const bounds = appState.nms.mapLayers.getBounds();
        if (bounds.isValid()) {
            appState.nms.map.fitBounds(bounds, { padding: [50, 50] });
            appState.nms.mapCentered = true;
        }
    }
    updateNmsCounters();
}

function projectGeographicCoords() {
    const devices = appState.nms.devices;
    const validDevs = devices.filter(d => d.latitude !== undefined && d.longitude !== undefined && !isNaN(parseFloat(d.latitude)) && !isNaN(parseFloat(d.longitude)));
    
    if (validDevs.length === 0) return;
    
    let minLat = Infinity, maxLat = -Infinity;
    let minLng = Infinity, maxLng = -Infinity;
    
    validDevs.forEach(d => {
        const lat = parseFloat(d.latitude);
        const lng = parseFloat(d.longitude);
        if (lat < minLat) minLat = lat;
        if (lat > maxLat) maxLat = lat;
        if (lng < minLng) minLng = lng;
        if (lng > maxLng) maxLng = lng;
    });
    
    const margin = 80;
    const width = 1000;
    const height = 600;
    
    const spanLat = maxLat - minLat;
    const spanLng = maxLng - minLng;
    
    const coordsMap = {};
    
    devices.forEach(dev => {
        if (dev.latitude === undefined || dev.longitude === undefined || isNaN(parseFloat(dev.latitude)) || isNaN(parseFloat(dev.longitude))) {
            dev.x = width / 2;
            dev.y = height / 2;
            return;
        }
        
        const lat = parseFloat(dev.latitude);
        const lng = parseFloat(dev.longitude);
        
        let rawX, rawY;
        if (spanLng === 0) {
            rawX = width / 2;
        } else {
            rawX = Math.round(margin + ((lng - minLng) / spanLng) * (width - 2 * margin));
        }
        
        if (spanLat === 0) {
            rawY = height / 2;
        } else {
            rawY = Math.round(height - margin - ((lat - minLat) / spanLat) * (height - 2 * margin));
        }
        
        dev.rawGeoX = rawX;
        dev.rawGeoY = rawY;
        
        // Group close coordinates rounded to 4 decimals (approx 10 meters)
        const coordKey = `${lat.toFixed(4)},${lng.toFixed(4)}`;
        if (!coordsMap[coordKey]) {
            coordsMap[coordKey] = [];
        }
        coordsMap[coordKey].push(dev);
    });
    
    // Apply radial offsets for co-located clusters
    Object.keys(coordsMap).forEach(key => {
        const group = coordsMap[key];
        const count = group.length;
        if (count === 1) {
            group[0].x = group[0].rawGeoX;
            group[0].y = group[0].rawGeoY;
        } else {
            const radius = 25; // cluster radius gap
            group.forEach((dev, idx) => {
                const angle = (2 * Math.PI * idx) / count;
                dev.x = Math.round(dev.rawGeoX + radius * Math.cos(angle));
                dev.y = Math.round(dev.rawGeoY + radius * Math.sin(angle));
            });
        }
    });
}

function reverseProjectGeographic(dev, x, y) {
    const devices = appState.nms.devices;
    const validDevs = devices.filter(d => d.id !== dev.id && d.latitude !== undefined && d.longitude !== undefined && !isNaN(parseFloat(d.latitude)) && !isNaN(parseFloat(d.longitude)));
    
    if (validDevs.length === 0) return;
    
    let minLat = Infinity, maxLat = -Infinity;
    let minLng = Infinity, maxLng = -Infinity;
    
    validDevs.forEach(d => {
        const lat = parseFloat(d.latitude);
        const lng = parseFloat(d.longitude);
        if (lat < minLat) minLat = lat;
        if (lat > maxLat) maxLat = lat;
        if (lng < minLng) minLng = lng;
        if (lng > maxLng) maxLng = lng;
    });
    
    const margin = 80;
    const width = 1000;
    const height = 600;
    
    const spanLat = maxLat - minLat;
    const spanLng = maxLng - minLng;
    
    if (spanLng !== 0) {
        dev.longitude = parseFloat((minLng + ((x - margin) / (width - 2 * margin)) * spanLng).toFixed(6));
    }
    if (spanLat !== 0) {
        dev.latitude = parseFloat((minLat + ((height - y - margin) / (height - 2 * margin)) * spanLat).toFixed(6));
    }
}

function renderNmsGeoGrid(linksGroup) {
    const devices = appState.nms.devices;
    const validDevs = devices.filter(d => d.latitude !== undefined && d.longitude !== undefined && !isNaN(parseFloat(d.latitude)) && !isNaN(parseFloat(d.longitude)));
    if (validDevs.length === 0) return;
    
    let minLat = Infinity, maxLat = -Infinity;
    let minLng = Infinity, maxLng = -Infinity;
    validDevs.forEach(d => {
        const lat = parseFloat(d.latitude);
        const lng = parseFloat(d.longitude);
        if (lat < minLat) minLat = lat;
        if (lat > maxLat) maxLat = lat;
        if (lng < minLng) minLng = lng;
        if (lng > maxLng) maxLng = lng;
    });
    
    const margin = 80;
    const width = 1000;
    const height = 600;
    
    const latStep = (maxLat - minLat) / 2;
    const lngStep = (maxLng - minLng) / 2;
    
    for (let i = 0; i <= 2; i++) {
        const latVal = minLat + i * latStep;
        const y = height - margin - (i * 0.5) * (height - 2 * margin);
        
        const latPath = document.createElementNS("http://www.w3.org/2000/svg", "path");
        latPath.setAttribute("d", `M 30 ${y} L 970 ${y}`);
        latPath.setAttribute("stroke", "rgba(255, 255, 255, 0.05)");
        latPath.setAttribute("stroke-dasharray", "4, 4");
        latPath.setAttribute("stroke-width", "1");
        linksGroup.appendChild(latPath);
        
        const latText = document.createElementNS("http://www.w3.org/2000/svg", "text");
        latText.setAttribute("x", "35");
        latText.setAttribute("y", y - 4);
        latText.setAttribute("fill", "rgba(255, 255, 255, 0.2)");
        latText.setAttribute("font-size", "9px");
        latText.setAttribute("font-family", "monospace");
        latText.textContent = `LAT: ${latVal.toFixed(4)}°`;
        linksGroup.appendChild(latText);
        
        const lngVal = minLng + i * lngStep;
        const x = margin + (i * 0.5) * (width - 2 * margin);
        
        const lngPath = document.createElementNS("http://www.w3.org/2000/svg", "path");
        lngPath.setAttribute("d", `M ${x} 30 L ${x} 570`);
        lngPath.setAttribute("stroke", "rgba(255, 255, 255, 0.05)");
        lngPath.setAttribute("stroke-dasharray", "4, 4");
        lngPath.setAttribute("stroke-width", "1");
        linksGroup.appendChild(lngPath);
        
        const lngText = document.createElementNS("http://www.w3.org/2000/svg", "text");
        lngText.setAttribute("x", x + 4);
        lngText.setAttribute("y", "565");
        lngText.setAttribute("fill", "rgba(255, 255, 255, 0.2)");
        lngText.setAttribute("font-size", "9px");
        lngText.setAttribute("font-family", "monospace");
        lngText.textContent = `LNG: ${lngVal.toFixed(4)}°`;
        linksGroup.appendChild(lngText);
    }
}

function autoArrangeTopology() {
    const devices = appState.nms.devices;
    if (devices.length === 0) return;
    
    const margin = 200;
    const width = 3000;
    
    const routers = devices.filter(d => d.type === "Router");
    const olts = devices.filter(d => d.type === "OLT");
    
    const core = routers.filter(r => r.name.toLowerCase().includes("core") || r.ip.startsWith("10.0."));
    const agg = routers.filter(r => !core.includes(r));
    
    // Sort logically for deterministic ordering
    core.sort((a, b) => a.name.localeCompare(b.name));
    
    // Step 1: Place Core Routers along Y = 150
    core.forEach((dev, idx) => {
        dev.x = margin + idx * 450;
        dev.y = 150;
    });
    
    // Step 2: Place Aggregation Routers along Y = 600, sorted by their parent Core X positions
    agg.forEach(dev => {
        const connectedCores = appState.nms.connections.filter(c => 
            (c.source === dev.name || c.target === dev.name)
        ).map(c => {
            const partner = c.source === dev.name ? c.target : c.source;
            return core.find(d => d.name === partner);
        }).filter(Boolean);
        
        dev.preferredX = connectedCores.length > 0 
            ? connectedCores.reduce((sum, c) => sum + c.x, 0) / connectedCores.length 
            : width / 2;
    });
    
    agg.sort((a, b) => a.preferredX - b.preferredX || a.name.localeCompare(b.name));
    agg.forEach((dev, idx) => {
        dev.x = margin + idx * 280;
        dev.y = 600;
    });
    
    // Step 3: Filter and place connected OLTs along Y = 1050, sorted by parent Router X positions
    const connectedOlts = olts.filter(o => 
        appState.nms.connections.some(c => 
            (c.source === o.name && routers.some(r => r.name === c.target)) ||
            (c.target === o.name && routers.some(r => r.name === c.source))
        )
    );
    
    connectedOlts.forEach(o => {
        const connectedRouters = appState.nms.connections.filter(c => 
            (c.source === o.name || c.target === o.name)
        ).map(c => {
            const partner = c.source === o.name ? c.target : c.source;
            return routers.find(r => r.name === partner);
        }).filter(Boolean);
        
        o.preferredX = connectedRouters.length > 0
            ? connectedRouters.reduce((sum, r) => sum + r.x, 0) / connectedRouters.length
            : width / 2;
    });
    
    connectedOlts.sort((a, b) => a.preferredX - b.preferredX || a.name.localeCompare(b.name));
    connectedOlts.forEach((dev, idx) => {
        dev.x = margin + idx * 180;
        dev.y = 1050;
    });
    
    // Step 4: Place the remaining unconnected OLTs to the right of connected ones
    const unconnectedOlts = olts.filter(o => !connectedOlts.includes(o));
    const lastX = connectedOlts.length > 0 ? connectedOlts[connectedOlts.length - 1].x : margin;
    
    unconnectedOlts.forEach((dev, idx) => {
        dev.x = lastX + (idx + 1) * 180;
        dev.y = 1050;
    });
    
    // Step 5: Shift all coordinates horizontally to center the entire topology on the 3000px canvas
    const allX = devices.map(d => d.x);
    const minX = Math.min(...allX);
    const maxX = Math.max(...allX);
    const totalWidth = maxX - minX;
    const offsetX = (width - totalWidth) / 2 - minX;
    
    devices.forEach(d => {
        d.x += offsetX;
    });
    
    // Apply coordinates to logical fields
    devices.forEach(d => {
        d.x = Math.round(d.x);
        d.y = Math.round(d.y);
        d.logical_x = d.x;
        d.logical_y = d.y;
    });
    
    renderNmsGraph();
    updateLinksSvgPosition();
    autoFitNmsLogicalViewport(); // Auto-fit camera
    
    appState.nms.hasChanges = true;
    markUnsavedChanges(true);
}

function autoFitNmsLogicalViewport() {
    const devices = appState.nms.devices;
    if (devices.length === 0) return;
    
    const svg = document.getElementById("nms-svg");
    if (!svg) return;
    
    const svgWidth = svg.clientWidth || 800;
    const svgHeight = svg.clientHeight || 500;
    
    let centerX = 1500;
    let centerY = 750;
    
    // Find selected node if active
    const selectedDev = appState.nms.selectedNodeId ? devices.find(d => d.id === appState.nms.selectedNodeId) : null;
    
    if (selectedDev) {
        centerX = selectedDev.x;
        centerY = selectedDev.y;
    } else {
        let minX = Infinity, maxX = -Infinity;
        let minY = Infinity, maxY = -Infinity;
        devices.forEach(d => {
            if (d.x < minX) minX = d.x;
            if (d.x > maxX) maxX = d.x;
            if (d.y < minY) minY = d.y;
            if (d.y > maxY) maxY = d.y;
        });
        centerX = (minX + maxX) / 2.0;
        centerY = (minY + maxY) / 2.0;
    }
    
    // Fit zoom
    let minX = Infinity, maxX = -Infinity;
    let minY = Infinity, maxY = -Infinity;
    devices.forEach(d => {
        if (d.x < minX) minX = d.x;
        if (d.x > maxX) maxX = d.x;
        if (d.y < minY) minY = d.y;
        if (d.y > maxY) maxY = d.y;
    });
    
    const margin = 120;
    const bboxWidth = (maxX - minX) + 2 * margin;
    const bboxHeight = (maxY - minY) + 2 * margin;
    
    let zoom = Math.min(svgWidth / bboxWidth, svgHeight / bboxHeight);
    zoom = Math.max(0.25, Math.min(1.2, zoom));
    
    const panX = svgWidth / 2.0 - centerX * zoom;
    const panY = svgHeight / 2.0 - centerY * zoom;
    
    appState.nms.zoom = zoom;
    appState.nms.pan = { x: panX, y: panY };
    applyNmsZoomPan();
}

function autoArrangeRadial() {
    const devices = appState.nms.devices;
    if (devices.length === 0) return;
    
    // Spacious radial area center
    const centerX = 1500;
    const centerY = 750;
    
    const routers = devices.filter(d => d.type === "Router");
    const olts = devices.filter(d => d.type === "OLT");
    
    const core = routers.filter(r => r.name.toLowerCase().includes("core") || r.ip.startsWith("10.0."));
    const agg = routers.filter(r => !core.includes(r));
    
    // Sort logically
    core.sort((a, b) => a.name.localeCompare(b.name));
    agg.sort((a, b) => a.name.localeCompare(b.name));
    olts.sort((a, b) => a.name.localeCompare(b.name));
    
    // Spaced out radial rings to guarantee no overlaps between rings
    const rCore = 220;
    const rAgg = 520;
    const rOlt = 850;
    
    // 1. Core routers innermost ring
    core.forEach((dev, idx) => {
        const theta = (idx / (core.length || 1)) * 2.0 * Math.PI;
        dev.x = centerX + rCore * Math.cos(theta);
        dev.y = centerY + rCore * Math.sin(theta);
        dev.angle = theta;
    });
    
    // 2. Aggregation routers middle ring (placed by average parent core angle)
    agg.forEach(dev => {
        const connectedCores = appState.nms.connections.filter(c => 
            (c.source === dev.name || c.target === dev.name)
        ).map(c => {
            const partner = c.source === dev.name ? c.target : c.source;
            return core.find(d => d.name === partner);
        }).filter(Boolean);
        
        if (connectedCores.length > 0) {
            dev.preferredAngle = connectedCores.reduce((sum, c) => sum + c.angle, 0) / connectedCores.length;
        } else {
            dev.preferredAngle = 0;
        }
    });
    
    // Sort and place Aggregations on middle ring
    agg.sort((a, b) => a.preferredAngle - b.preferredAngle);
    agg.forEach((dev, idx) => {
        const theta = (idx / (agg.length || 1)) * 2.0 * Math.PI;
        dev.x = centerX + rAgg * Math.cos(theta);
        dev.y = centerY + rAgg * Math.sin(theta);
        dev.angle = theta;
    });
    
    // 3. OLT cabinets outermost ring (placed by average parent aggregation angle)
    olts.forEach(dev => {
        const connectedAggs = appState.nms.connections.filter(c => 
            (c.source === dev.name || c.target === dev.name)
        ).map(c => {
            const partner = c.source === dev.name ? c.target : c.source;
            return agg.find(d => d.name === partner);
        }).filter(Boolean);
        
        if (connectedAggs.length > 0) {
            dev.preferredAngle = connectedAggs.reduce((sum, a) => sum + a.angle, 0) / connectedAggs.length;
        } else {
            dev.preferredAngle = 0;
        }
    });
    
    // Sort and place OLTs on outer ring
    olts.sort((a, b) => a.preferredAngle - b.preferredAngle);
    olts.forEach((dev, idx) => {
        const theta = (idx / (olts.length || 1)) * 2.0 * Math.PI;
        dev.x = centerX + rOlt * Math.cos(theta);
        dev.y = centerY + rOlt * Math.sin(theta);
        dev.angle = theta;
    });
    
    // Final check to guarantee that even on same ring no nodes overlap
    // Resolve radial spacing overlaps
    for (let resolve = 0; resolve < 50; resolve++) {
        for (let i = 0; i < devices.length; i++) {
            const u = devices[i];
            for (let j = i + 1; j < devices.length; j++) {
                const v = devices[j];
                const dx = u.x - v.x;
                const dy = u.y - v.y;
                const d = Math.sqrt(dx * dx + dy * dy) || 1.0;
                const minD = 180.0; // Secure distance between icons & labels
                if (d < minD) {
                    const overlap = minD - d;
                    const pushX = (dx / d) * overlap * 0.5;
                    const pushY = (dy / d) * overlap * 0.5;
                    u.x += pushX;
                    u.y += pushY;
                    v.x -= pushX;
                    v.y -= pushY;
                }
            }
        }
    }
    
    // Apply coordinates to logical fields
    devices.forEach(d => {
        d.x = Math.round(d.x);
        d.y = Math.round(d.y);
        d.logical_x = d.x;
        d.logical_y = d.y;
    });
    
    renderNmsGraph();
    updateLinksSvgPosition();
    autoFitNmsLogicalViewport();
    
    appState.nms.hasChanges = true;
    markUnsavedChanges(true);
}

function autoArrangeForceDirected() {
    const devices = appState.nms.devices;
    if (devices.length === 0) return;
    
    const width = 2400;
    const height = 1100;
    const margin = 150;
    
    const routers = devices.filter(d => d.type === "Router");
    const olts = devices.filter(d => d.type === "OLT");
    
    const core = routers.filter(r => r.name.toLowerCase().includes("core") || r.ip.startsWith("10.0."));
    const agg = routers.filter(r => !core.includes(r));
    
    // Assign target hierarchical layers
    devices.forEach(dev => {
        if (core.includes(dev)) {
            dev.targetY = 150;
        } else if (agg.includes(dev)) {
            dev.targetY = 550;
        } else {
            dev.targetY = 950;
        }
        
        if (!dev.x || !dev.y || (devices.filter(o => o.x === dev.x && o.y === dev.y).length > 1)) {
            dev.x = margin + Math.random() * (width - 2 * margin);
            dev.y = dev.targetY + (Math.random() - 0.5) * 60;
        }
    });
    
    const iterations = 150;
    const k = 220.0;
    let temp = 150.0;
    const coolingFactor = 0.95;
    
    for (let pass = 0; pass < iterations; pass++) {
        devices.forEach(dev => {
            dev.dispX = 0;
            dev.dispY = 0;
        });
        
        // 1. Repulsive forces
        for (let i = 0; i < devices.length; i++) {
            const u = devices[i];
            for (let j = i + 1; j < devices.length; j++) {
                const v = devices[j];
                const dx = u.x - v.x;
                const dy = u.y - v.y;
                const d = Math.sqrt(dx * dx + dy * dy) || 1.0;
                
                const sameLayer = u.targetY === v.targetY;
                const forceK = sameLayer ? k : k * 0.6;
                const force = (forceK * forceK) / d;
                
                const fx = (dx / d) * force;
                const fy = (dy / d) * force;
                
                u.dispX += fx;
                u.dispY += fy;
                v.dispX -= fx;
                v.dispY -= fy;
            }
        }
        
        // 2. Attractive forces
        appState.nms.connections.forEach(conn => {
            const u = devices.find(d => d.name === conn.source);
            const v = devices.find(d => d.name === conn.target);
            if (u && v && u.id !== v.id) {
                const dx = u.x - v.x;
                const dy = u.y - v.y;
                const d = Math.sqrt(dx * dx + dy * dy) || 1.0;
                
                const force = (d * d) / (k * 0.7);
                const fx = (dx / d) * force;
                const fy = (dy / d) * force;
                
                u.dispX -= fx;
                u.dispY -= fy;
                v.dispX += fx;
                v.dispY += fy;
            }
        });
        
        // 3. Parent X gravity pull
        devices.forEach(dev => {
            const parents = appState.nms.connections.filter(c => 
                (c.source === dev.name || c.target === dev.name)
            ).map(c => {
                const partner = c.source === dev.name ? c.target : c.source;
                return devices.find(d => d.name === partner);
            }).filter(neighbor => neighbor && neighbor.targetY < dev.targetY);
            
            if (parents.length > 0) {
                const avgParentX = parents.reduce((sum, p) => sum + p.x, 0) / parents.length;
                const dx = avgParentX - dev.x;
                dev.dispX += dx * 2.0;
            }
        });
        
        // 4. Hierarchical layer constraints
        devices.forEach(dev => {
            const dy = dev.targetY - dev.y;
            dev.dispY += dy * 2.0;
        });
        
        // 5. Line segment avoidance
        const lines = [];
        appState.nms.connections.forEach(conn => {
            const u = devices.find(d => d.name === conn.source);
            const v = devices.find(d => d.name === conn.target);
            if (u && v && u.id !== v.id) {
                lines.push({ a: u, b: v });
            }
        });
        
        devices.forEach(node => {
            lines.forEach(line => {
                if (node.id === line.a.id || node.id === line.b.id) return;
                
                const ax = line.a.x, ay = line.a.y;
                const bx = line.b.x, by = line.b.y;
                const px = node.x, py = node.y;
                
                const dx = bx - ax;
                const dy = by - ay;
                const lenSq = dx * dx + dy * dy;
                if (lenSq === 0) return;
                
                let t = ((px - ax) * dx + (py - ay) * dy) / lenSq;
                t = Math.max(0, Math.min(1, t));
                
                const projX = ax + t * dx;
                const projY = ay + t * dy;
                
                const distX = px - projX;
                const distY = py - projY;
                const dist = Math.sqrt(distX * distX + distY * distY) || 1.0;
                const safeDist = 120.0;
                
                if (dist < safeDist) {
                    const overlap = safeDist - dist;
                    let pushX = distX / dist;
                    let pushY = distY / dist;
                    if (distX === 0 && distY === 0) {
                        pushX = node.id.localeCompare(line.a.id) > 0 ? 1 : -1;
                        pushY = 0;
                    }
                    
                    node.dispX += pushX * overlap * 12.0;
                    node.dispY += pushY * overlap * 12.0;
                }
            });
        });
        
        // Resolve horizontal overlaps
        function resolveRowOverlapsInLoop(rowNodes, minSpacing) {
            rowNodes.sort((a, b) => a.x - b.x);
            for (let i = 0; i < rowNodes.length - 1; i++) {
                const a = rowNodes[i];
                const b = rowNodes[i+1];
                if (b.x - a.x < minSpacing) {
                    const diff = minSpacing - (b.x - a.x);
                    a.dispX -= diff / 2;
                    b.dispX += diff / 2;
                }
            }
        }
        resolveRowOverlapsInLoop(core, 200);
        resolveRowOverlapsInLoop(agg, 180);
        resolveRowOverlapsInLoop(olts, 140);
        
        // 6. Apply displacement limited by temperature
        devices.forEach(dev => {
            const dispDist = Math.sqrt(dev.dispX * dev.dispX + dev.dispY * dev.dispY) || 1.0;
            const cappedDist = Math.min(dispDist, temp);
            
            dev.x += (dev.dispX / dispDist) * cappedDist;
            dev.y += (dev.dispY / dispDist) * cappedDist;
            
            if (dev.x < margin) dev.x = margin;
            if (dev.x > width - margin) dev.x = width - margin;
            if (dev.y < 80) dev.y = 80;
            if (dev.y > height - 100) dev.y = height - 100;
        });
        
        temp *= coolingFactor;
    }
    
    // Rigorous overlap resolution loop to ensure zero node stacking
    for (let resolve = 0; resolve < 80; resolve++) {
        for (let i = 0; i < devices.length; i++) {
            const u = devices[i];
            for (let j = i + 1; j < devices.length; j++) {
                const v = devices[j];
                if (u.targetY === v.targetY) {
                    const dx = u.x - v.x;
                    const minD = 180.0; // Secure distance between icons & labels
                    if (Math.abs(dx) < minD) {
                        const overlap = minD - Math.abs(dx);
                        const dir = dx >= 0 ? 1 : -1;
                        u.x += dir * overlap * 0.5;
                        v.x -= dir * overlap * 0.5;
                    }
                }
            }
        }
    }
    
    // Constrain within virtual canvas margins and assign coordinates
    devices.forEach(d => {
        d.y = d.targetY;
        if (d.x < margin) d.x = margin;
        if (d.x > width - margin) d.x = width - margin;
        d.x = Math.round(d.x);
        d.y = Math.round(d.y);
        d.logical_x = d.x;
        d.logical_y = d.y;
    });
    
    renderNmsGraph();
    updateLinksSvgPosition();
    autoFitNmsLogicalViewport();
    
    appState.nms.hasChanges = true;
    markUnsavedChanges(true);
}

function renderNmsGraph() {
    const linksGroup = document.getElementById("nms-links-group");
    const nodesGroup = document.getElementById("nms-nodes-group");
    if (!linksGroup || !nodesGroup) return;
    
    linksGroup.innerHTML = "";
    nodesGroup.innerHTML = "";
    
    const searchInput = document.getElementById("nms-search-input");
    const query = searchInput ? searchInput.value.toLowerCase().trim() : "";
    
    // Draw Geo Grid if in geo mode
    if (appState.nms.layoutMode === "geo") {
        renderNmsGeoGrid(linksGroup);
    }
    
    // 1. Draw Connection Lines
    // 1. Group Connections between same pair of devices
    const devicePairs = {};
    appState.nms.connections.forEach(conn => {
        if (!conn.source || !conn.target) return;
        if (conn.hidden) return;
        
        const sourceDev = appState.nms.devices.find(d => d.name === conn.source);
        const targetDev = appState.nms.devices.find(d => d.name === conn.target);
        if (!sourceDev || !targetDev) return;
        if (sourceDev.hidden || targetDev.hidden) return;
        
        // Define sorted name key to group A->B and B->A together
        const pairKey = [conn.source, conn.target].sort().join("<-->");
        if (!devicePairs[pairKey]) {
            devicePairs[pairKey] = [];
        }
        devicePairs[pairKey].push(conn);
    });
    
    Object.keys(devicePairs).forEach(pairKey => {
        const conns = devicePairs[pairKey];
        if (conns.length === 0) return;
        
        const first = conns[0];
        const sourceNode = appState.nms.devices.find(d => d.name === first.source);
        const targetNode = appState.nms.devices.find(d => d.name === first.target);
        if (!sourceNode || !targetNode) return;
        
        const filters = getVisibilityFilters();
        const isSourceVisible = (sourceNode.type === "Router" && filters.showRouters) || (sourceNode.type === "OLT" && filters.showOlts);
        const isTargetVisible = (targetNode.type === "Router" && filters.showRouters) || (targetNode.type === "OLT" && filters.showOlts);
        if (!isSourceVisible || !isTargetVisible) return;
         // Symmetrically offset each connection
        const n = conns.length;
        const spacing = 12.0; // Spacing distance between multiple connections
        
        const dx = targetNode.x - sourceNode.x;
        const dy = targetNode.y - sourceNode.y;
        const len = Math.sqrt(dx * dx + dy * dy);
        
        let nx = 0, ny = 0;
        if (len > 0) {
            nx = -dy / len;
            ny = dx / len;
        }
        
        conns.forEach((conn, index) => {
            const dist = (index - (n - 1) / 2.0) * spacing;
            const isConnSelected = conn.id === appState.nms.selectedConnectionId;
            const optInfo = getConnectionOpticalInfo(conn);
            
            const bitrateVal = parseInt(conn.bitrate) || 10;
            let capClass = "capacity-10";
            if (bitrateVal >= 100) capClass = "capacity-100";
            else if (bitrateVal >= 40) capClass = "capacity-40";
            
            const typeClass = conn.type === "Uplink" ? "type-uplink" : "type-interlink";
            const statusClass = conn.status === "Active" ? "active-traffic" : "status-backup";
            const optLineClass = optInfo.worstSeverity === "alarm" ? "optical-nok-alarm" : optInfo.worstSeverity === "warning" ? "optical-nok-warning" : "";
            
            let isLinkMatch = true;
            if (query) {
                isLinkMatch = (conn.source && conn.source.toLowerCase().includes(query)) ||
                              (conn.target && conn.target.toLowerCase().includes(query)) ||
                              (conn.link && conn.link.toLowerCase().includes(query)) ||
                              (conn.source_interface && conn.source_interface.toLowerCase().includes(query)) ||
                              (conn.target_interface && conn.target_interface.toLowerCase().includes(query));
            }
            // When "Optical NOK Only" is toggled on, hide non-NOK links unless it's a peer link of the clicked connection
            const selectedConnObj = appState.nms.connections.find(c => c.id === appState.nms.selectedConnectionId);
            const selectedPeerIds = new Set((selectedConnObj ? getRelatedPeerConnections(selectedConnObj) : []).map(c => c.id));
            if (filters.onlyOpticalNok && !optInfo.isNok && !selectedPeerIds.has(conn.id)) {
                return;
            }
            const getBezierPathD = (x1, y1, x2, y2, connId) => {
                const algoSelect = document.getElementById("nms-arrange-algorithm");
                const algo = algoSelect ? algoSelect.value : "tree";
                if (algo === "radial") {
                    return `M ${x1} ${y1} L ${x2} ${y2}`;
                }
                if (Math.abs(y1 - y2) > 40) {
                    let hash = 0;
                    if (connId) {
                        for (let i = 0; i < connId.length; i++) {
                            hash += connId.charCodeAt(i);
                        }
                    }
                    const staggerIndex = hash % 5;
                    const offset = (staggerIndex - 2) * 16;
                    const cy = (y1 + y2) / 2.0 + offset;
                    return `M ${x1} ${y1} L ${x1} ${cy} L ${x2} ${cy} L ${x2} ${y2}`;
                }
                return `M ${x1} ${y1} L ${x2} ${y2}`;
            };

            const hoverPath = document.createElementNS("http://www.w3.org/2000/svg", "path");
            hoverPath.setAttribute("class", `nms-link-hover-target ${!isLinkMatch ? 'search-dimmed' : ''}`);
            hoverPath.setAttribute("d", getBezierPathD(sourceNode.x + nx * dist, sourceNode.y + ny * dist, targetNode.x + nx * dist, targetNode.y + ny * dist, conn.id));
            hoverPath.setAttribute("data-id", conn.id);
            
            hoverPath.style.cursor = "pointer";
            hoverPath.addEventListener("click", () => {
                selectNmsConnection(conn.id);
            });
            
            linksGroup.appendChild(hoverPath);
            
            if (conn.dual_track) {
                const subOffset = 3.0;
                
                const path1 = document.createElementNS("http://www.w3.org/2000/svg", "path");
                path1.setAttribute("class", `nms-link-line dual-track-line ${capClass} ${typeClass} ${statusClass} ${optLineClass} ${!isLinkMatch ? 'search-dimmed' : ''} ${isConnSelected ? 'selected' : ''}`);
                path1.setAttribute("d", getBezierPathD(sourceNode.x + nx * (dist + subOffset), sourceNode.y + ny * (dist + subOffset), targetNode.x + nx * (dist + subOffset), targetNode.y + ny * (dist + subOffset), conn.id));
                path1.setAttribute("data-id", conn.id);
                linksGroup.appendChild(path1);
                
                const path2 = document.createElementNS("http://www.w3.org/2000/svg", "path");
                path2.setAttribute("class", `nms-link-line dual-track-line ${capClass} ${typeClass} ${statusClass} ${optLineClass} ${!isLinkMatch ? 'search-dimmed' : ''} ${isConnSelected ? 'selected' : ''}`);
                path2.setAttribute("d", getBezierPathD(sourceNode.x - nx * (dist - subOffset), sourceNode.y - ny * (dist - subOffset), targetNode.x - nx * (dist - subOffset), targetNode.y - ny * (dist - subOffset), conn.id));
                path2.setAttribute("data-id", conn.id);
                linksGroup.appendChild(path2);
            } else {
                const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
                path.setAttribute("class", `nms-link-line ${conns.length > 1 ? 'aggregated-line' : ''} ${capClass} ${typeClass} ${statusClass} ${optLineClass} ${!isLinkMatch ? 'search-dimmed' : ''} ${isConnSelected ? 'selected' : ''}`);
                path.setAttribute("d", getBezierPathD(sourceNode.x + nx * dist, sourceNode.y + ny * dist, targetNode.x + nx * dist, targetNode.y + ny * dist, conn.id));
                path.setAttribute("data-id", conn.id);
                linksGroup.appendChild(path);
            }
            
            const title = document.createElementNS("http://www.w3.org/2000/svg", "title");
            let svgTooltip = `Link: ${conn.link || 'Unnamed'}\nCapacity: ${conn.bitrate} Gbps\nType: ${conn.type || 'Interlink'}\nStatus: ${conn.status}\nFrom: ${conn.source} [${conn.source_interface || 'no-port'}]\nTo: ${conn.target} [${conn.target_interface || 'no-port'}]`;
            if (optInfo.tooltipLines.length > 0) {
                svgTooltip += `\n` + optInfo.tooltipLines.join(`\n`);
            }
            title.textContent = svgTooltip;
            hoverPath.appendChild(title);
            
            const labelGroup = document.createElementNS("http://www.w3.org/2000/svg", "g");
            labelGroup.setAttribute("class", `nms-link-label-group ${!isLinkMatch ? 'search-dimmed' : ''}`);
            labelGroup.setAttribute("data-id", conn.id);
            labelGroup.style.pointerEvents = "all";
            labelGroup.style.cursor = "pointer";
            labelGroup.addEventListener("click", () => selectNmsConnection(conn.id));
            
            const midX = (sourceNode.x + targetNode.x) / 2.0 + nx * dist;
            const midY = (sourceNode.y + targetNode.y) / 2.0 + ny * dist;
            
            const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
            const bgNokClass = optInfo.worstSeverity === "alarm" ? "optical-nok-alarm-bg" : optInfo.worstSeverity === "warning" ? "optical-nok-warning-bg" : "";
            rect.setAttribute("class", `nms-link-label-bg ${bgNokClass}`);
            
            const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
            const txtNokClass = optInfo.worstSeverity === "alarm" ? "optical-nok-alarm-text" : optInfo.worstSeverity === "warning" ? "optical-nok-warning-text" : "";
            text.setAttribute("class", `nms-link-label-text ${txtNokClass}`);
            text.setAttribute("x", midX);
            text.setAttribute("y", midY);
            if (optInfo.isNok && optInfo.primaryHealth) {
                text.textContent = `⚠ ${bitrateVal}G (${optInfo.primaryHealth.rxText.replace(' dBm', '')}dBm)`;
            } else {
                text.textContent = `${bitrateVal}G`;
            }
            
            labelGroup.appendChild(rect);
            labelGroup.appendChild(text);
            linksGroup.appendChild(labelGroup);
            
            setTimeout(() => {
                try {
                    const bbox = text.getBBox();
                    rect.setAttribute("x", bbox.x - 3);
                    rect.setAttribute("y", bbox.y - 1);
                    rect.setAttribute("width", bbox.width + 6);
                    rect.setAttribute("height", bbox.height + 2);
                    rect.setAttribute("rx", "3");
                    rect.setAttribute("ry", "3");
                } catch(err) {}
            }, 50);
        });
    });   
    // 2. Draw Devices Nodes
    const nokDeviceNames = new Set();
    if (getVisibilityFilters().onlyOpticalNok) {
        const selectedConnObj = appState.nms.connections.find(c => c.id === appState.nms.selectedConnectionId);
        const selectedPeerIds = new Set((selectedConnObj ? getRelatedPeerConnections(selectedConnObj) : []).map(c => c.id));
        appState.nms.connections.forEach(c => {
            if (!c.hidden && (getConnectionOpticalInfo(c).isNok || selectedPeerIds.has(c.id))) {
                nokDeviceNames.add(c.source);
                nokDeviceNames.add(c.target);
            }
        });
    }
    const sortedDevices = [...appState.nms.devices].sort((a, b) => {
        if (a.type === "Router" && b.type !== "Router") return 1;
        if (a.type !== "Router" && b.type === "Router") return -1;
        return 0;
    });
    sortedDevices.forEach(dev => {
        if (dev.hidden) return;
        
        const filters = getVisibilityFilters();
        const isVisible = (dev.type === "Router" && filters.showRouters) || (dev.type === "OLT" && filters.showOlts);
        if (!isVisible) return;
        if (filters.onlyOpticalNok && !nokDeviceNames.has(dev.name)) return;
        
        let isNodeMatch = true;
        if (query) {
            isNodeMatch = (dev.name && dev.name.toLowerCase().includes(query)) ||
                         (dev.ip && dev.ip.toLowerCase().includes(query)) ||
                         (dev.brand && dev.brand.toLowerCase().includes(query)) ||
                         (dev.model && dev.model.toLowerCase().includes(query)) ||
                         (dev.type && dev.type.toLowerCase().includes(query)) ||
                         (dev.status && dev.status.toLowerCase().includes(query));
        }
        
        const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
        const isSelected = appState.nms.selectedNodeId === dev.id;
        g.setAttribute("class", `nms-node type-${dev.type.toLowerCase()} status-${dev.status.toLowerCase()} ${isSelected ? 'selected' : ''} ${!isNodeMatch ? 'search-dimmed' : ''}`);
        g.setAttribute("transform", `translate(${dev.x}, ${dev.y})`);
        g.setAttribute("data-id", dev.id);
        
        // Glow/Shape Card background
        const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
        rect.setAttribute("class", "nms-node-bg");
        if (dev.type === "Router") {
            rect.setAttribute("x", -24);
            rect.setAttribute("y", -24);
            rect.setAttribute("width", 48);
            rect.setAttribute("height", 48);
        } else {
            rect.setAttribute("x", -20);
            rect.setAttribute("y", -24);
            rect.setAttribute("width", 40);
            rect.setAttribute("height", 48);
        }
        g.appendChild(rect);
        
        // Status indicator dot
        const dot = document.createElementNS("http://www.w3.org/2000/svg", "circle");
        dot.setAttribute("class", "nms-node-status-dot");
        if (dev.type === "Router") {
            dot.setAttribute("cx", 16);
            dot.setAttribute("cy", -16);
        } else {
            dot.setAttribute("cx", 14);
            dot.setAttribute("cy", -18);
        }
        dot.setAttribute("r", 5);
        g.appendChild(dot);
        
        // FontAwesome Icon Glyph
        const icon = document.createElementNS("http://www.w3.org/2000/svg", "text");
        icon.setAttribute("class", "nms-node-icon");
        icon.setAttribute("y", -2);
        icon.textContent = dev.type === "Router" ? "\uf233" : "\uf0e8"; // \uf233=server, \uf0e8=sitemap
        g.appendChild(icon);
        
        // Name Label
        const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
        label.setAttribute("class", "nms-node-label");
        label.setAttribute("y", 38);
        label.textContent = dev.name;
        g.appendChild(label);
        
        // IP Label
        const ip = document.createElementNS("http://www.w3.org/2000/svg", "text");
        ip.setAttribute("class", "nms-node-ip");
        ip.setAttribute("y", 49);
        ip.textContent = dev.ip;
        g.appendChild(ip);
        
        nodesGroup.appendChild(g);
    });
    
    setTimeout(updateLinksSvgPosition, 50);
    updateNmsCounters();
}

function updateNodeSvgPosition(id, x, y) {
    const nodeEl = document.querySelector(`.nms-node[data-id="${id}"]`);
    if (!nodeEl) return;
    nodeEl.setAttribute("transform", `translate(${x}, ${y})`);
}

function getBezierPathD(x1, y1, x2, y2, connId) {
    const algoSelect = document.getElementById("nms-arrange-algorithm");
    const algo = algoSelect ? algoSelect.value : "tree";
    if (algo === "radial") {
        return `M ${x1} ${y1} L ${x2} ${y2}`;
    }
    if (Math.abs(y1 - y2) > 40) {
        let hash = 0;
        if (connId) {
            for (let i = 0; i < connId.length; i++) {
                hash += connId.charCodeAt(i);
            }
        }
        const staggerIndex = hash % 5;
        const offset = (staggerIndex - 2) * 16;
        const cy = (y1 + y2) / 2.0 + offset;
        return `M ${x1} ${y1} L ${x1} ${cy} L ${x2} ${cy} L ${x2} ${y2}`;
    }
    return `M ${x1} ${y1} L ${x2} ${y2}`;
}

function updateLinksSvgPosition() {
    const devicePairs = {};
    appState.nms.connections.forEach(conn => {
        if (!conn.source || !conn.target) return;
        const pairKey = [conn.source, conn.target].sort().join("<-->");
        if (!devicePairs[pairKey]) {
            devicePairs[pairKey] = [];
        }
        devicePairs[pairKey].push(conn);
    });
    
    Object.keys(devicePairs).forEach(pairKey => {
        const conns = devicePairs[pairKey];
        if (conns.length === 0) return;
        
        const first = conns[0];
        const sourceNode = appState.nms.devices.find(d => d.name === first.source);
        const targetNode = appState.nms.devices.find(d => d.name === first.target);
        if (!sourceNode || !targetNode) return;
        
        const n = conns.length;
        const spacing = 12.0;
        
        const dx = targetNode.x - sourceNode.x;
        const dy = targetNode.y - sourceNode.y;
        const len = Math.sqrt(dx * dx + dy * dy);
        
        let nx = 0, ny = 0;
        if (len > 0) {
            nx = -dy / len;
            ny = dx / len;
        }
        
        conns.forEach((conn, index) => {
            const dist = (index - (n - 1) / 2.0) * spacing;
            
            const hoverEl = document.querySelector(`.nms-link-hover-target[data-id="${conn.id}"]`);
            if (hoverEl) {
                hoverEl.setAttribute("d", getBezierPathD(sourceNode.x + nx * dist, sourceNode.y + ny * dist, targetNode.x + nx * dist, targetNode.y + ny * dist, conn.id));
            }
            
            const pathEls = document.querySelectorAll(`.nms-link-line[data-id="${conn.id}"]`);
            if (pathEls.length > 0) {
                if (conn.dual_track && pathEls.length === 2) {
                    const subOffset = 3.0;
                    pathEls[0].setAttribute("d", getBezierPathD(sourceNode.x + nx * (dist + subOffset), sourceNode.y + ny * (dist + subOffset), targetNode.x + nx * (dist + subOffset), targetNode.y + ny * (dist + subOffset), conn.id));
                    pathEls[1].setAttribute("d", getBezierPathD(sourceNode.x - nx * (dist - subOffset), sourceNode.y - ny * (dist - subOffset), targetNode.x - nx * (dist - subOffset), targetNode.y - ny * (dist - subOffset), conn.id));
                } else {
                    pathEls.forEach(pathEl => {
                        pathEl.setAttribute("d", getBezierPathD(sourceNode.x + nx * dist, sourceNode.y + ny * dist, targetNode.x + nx * dist, targetNode.y + ny * dist, conn.id));
                    });
                }
            }
            
            const labelGroup = document.querySelector(`.nms-link-label-group[data-id="${conn.id}"]`);
            if (labelGroup) {
                const midX = (sourceNode.x + targetNode.x) / 2.0 + nx * dist;
                const midY = (sourceNode.y + targetNode.y) / 2.0 + ny * dist;
                const rectEl = labelGroup.querySelector("rect");
                const textEl = labelGroup.querySelector("text");
                
                if (textEl) {
                    textEl.setAttribute("x", midX);
                    textEl.setAttribute("y", midY);
                }
                
                if (rectEl && textEl) {
                    try {
                        const bbox = textEl.getBBox();
                        rectEl.setAttribute("x", bbox.x - 3);
                        rectEl.setAttribute("y", bbox.y - 1);
                        rectEl.setAttribute("width", bbox.width + 6);
                        rectEl.setAttribute("height", bbox.height + 2);
                    } catch(e) {
                        rectEl.setAttribute("x", midX - 15);
                        rectEl.setAttribute("y", midY - 8);
                        rectEl.setAttribute("width", 30);
                        rectEl.setAttribute("height", 16);
                    }
                }
            }
        });
    });
}

function setupNmsCanvasInteractions() {
    const svg = document.getElementById("nms-svg");
    if (!svg) return;
    
    svg.addEventListener("mousedown", (e) => {
        if (e.target.closest(".nms-node")) {
            const nodeElement = e.target.closest(".nms-node");
            const nodeId = nodeElement.getAttribute("data-id");
            
            if (!appState.nms.editModeEnabled) {
                selectNmsNode(nodeId);
                return;
            }
            
            appState.nms.draggedNode = nodeId;
            
            const nodesGroup = document.getElementById("nms-nodes-group");
            nodesGroup.appendChild(nodeElement); // Bring to front
            
            const pt = svg.createSVGPoint();
            pt.x = e.clientX;
            pt.y = e.clientY;
            const svgPoint = pt.matrixTransform(document.getElementById("nms-zoom-group").getScreenCTM().inverse());
            
            const dev = appState.nms.devices.find(d => d.id === nodeId);
            if (dev) {
                appState.nms.dragStartPos = {
                    x: svgPoint.x - dev.x,
                    y: svgPoint.y - dev.y
                };
            }
            
            selectNmsNode(nodeId);
            return;
        }
        
        appState.nms.isPanning = true;
        appState.nms.panStart = {
            x: e.clientX - appState.nms.pan.x,
            y: e.clientY - appState.nms.pan.y
        };
    });
    
    svg.addEventListener("mousemove", (e) => {
        if (appState.nms.draggedNode) {
            const pt = svg.createSVGPoint();
            pt.x = e.clientX;
            pt.y = e.clientY;
            const svgPoint = pt.matrixTransform(document.getElementById("nms-zoom-group").getScreenCTM().inverse());
            
            const dev = appState.nms.devices.find(d => d.id === appState.nms.draggedNode);
            if (dev) {
                dev.x = Math.round(svgPoint.x - appState.nms.dragStartPos.x);
                dev.y = Math.round(svgPoint.y - appState.nms.dragStartPos.y);
                
                // Boundaries
                dev.x = Math.max(30, Math.min(970, dev.x));
                dev.y = Math.max(30, Math.min(570, dev.y));
                
                if (appState.nms.layoutMode === "geo") {
                    reverseProjectGeographic(dev, dev.x, dev.y);
                    
                    // Update spreadsheet inputs inline
                    const tr = document.querySelector(`#devices-sheet-body tr[data-id="${dev.id}"]`);
                    if (tr) {
                        const latInput = tr.querySelector('input[data-field="latitude"]');
                        const lngInput = tr.querySelector('input[data-field="longitude"]');
                        if (latInput) latInput.value = dev.latitude;
                        if (lngInput) lngInput.value = dev.longitude;
                    }
                } else {
                    dev.logical_x = dev.x;
                    dev.logical_y = dev.y;
                }
                
                updateNodeSvgPosition(dev.id, dev.x, dev.y);
                updateLinksSvgPosition();
                
                if (appState.nms.selectedNodeId === dev.id) {
                    showNmsDetailPanel(dev);
                }
                
                appState.nms.hasChanges = true;
                markUnsavedChanges(true);
            }
        } else if (appState.nms.isPanning) {
            appState.nms.pan.x = e.clientX - appState.nms.panStart.x;
            appState.nms.pan.y = e.clientY - appState.nms.panStart.y;
            applyNmsZoomPan();
        }
    });
    
    svg.addEventListener("mouseup", () => {
        appState.nms.draggedNode = null;
        appState.nms.isPanning = false;
    });
    
    svg.addEventListener("mouseleave", () => {
        appState.nms.draggedNode = null;
        appState.nms.isPanning = false;
    });
    
    svg.addEventListener("wheel", (e) => {
        e.preventDefault();
        const factor = e.deltaY < 0 ? 1.1 : 0.9;
        adjustNmsZoom(factor, e);
    });
}

function toggleNmsEditLock() {
    appState.nms.editModeEnabled = !appState.nms.editModeEnabled;
    
    const lockBtn = document.getElementById("nms-toggle-lock-btn");
    if (lockBtn) {
        if (appState.nms.editModeEnabled) {
            lockBtn.classList.add("unlocked");
            lockBtn.innerHTML = `<i class="fa-solid fa-lock-open"></i> <span>Unlocked (Edit Mode)</span>`;
        } else {
            lockBtn.classList.remove("unlocked");
            lockBtn.innerHTML = `<i class="fa-solid fa-lock"></i> <span>Locked (View Mode)</span>`;
        }
    }
    
    renderNmsSpreadsheet();
    if (appState.nms.layoutMode === "geo") {
        renderNmsLeafletMap();
    } else {
        renderNmsGraph();
    }
}

function applyNmsZoomPan() {
    const group = document.getElementById("nms-zoom-group");
    if (group) {
        group.setAttribute("transform", `translate(${appState.nms.pan.x}, ${appState.nms.pan.y}) scale(${appState.nms.zoom})`);
    }
}

function adjustNmsZoom(factor, mouseEvent = null) {
    const svg = document.getElementById("nms-svg");
    if (!svg) return;
    
    let targetX, targetY;
    
    if (mouseEvent) {
        const rect = svg.getBoundingClientRect();
        targetX = mouseEvent.clientX - rect.left;
        targetY = mouseEvent.clientY - rect.top;
    } else {
        // Fallback to center of SVG viewport
        const rect = svg.getBoundingClientRect();
        targetX = rect.width / 2;
        targetY = rect.height / 2;
    }
    
    const currentZoom = appState.nms.zoom;
    const newZoom = Math.max(0.3, Math.min(4, currentZoom * factor));
    
    // Zoom centered around (targetX, targetY)
    const unzoomedX = (targetX - appState.nms.pan.x) / currentZoom;
    const unzoomedY = (targetY - appState.nms.pan.y) / currentZoom;
    
    appState.nms.pan.x = targetX - unzoomedX * newZoom;
    appState.nms.pan.y = targetY - unzoomedY * newZoom;
    appState.nms.zoom = newZoom;
    
    applyNmsZoomPan();
}

function resetNmsZoomAndPan() {
    if (appState.nms.layoutMode === "logical") {
        autoFitNmsLogicalViewport();
    } else {
        appState.nms.zoom = 1;
        appState.nms.pan = { x: 0, y: 0 };
        applyNmsZoomPan();
    }
}

function selectNmsNode(nodeId) {
    appState.nms.selectedNodeId = nodeId;
    appState.nms.selectedConnectionId = null;
    
    const nodes = document.querySelectorAll(".nms-node");
    nodes.forEach(n => {
        if (n.getAttribute("data-id") === nodeId) n.classList.add("selected");
        else n.classList.remove("selected");
    });
    
    // Clear connection active highlights
    document.querySelectorAll(".nms-link-line").forEach(line => line.classList.remove("selected"));
    
    const dev = appState.nms.devices.find(d => d.id === nodeId);
    if (dev) {
        // Swap sub-sections back to device view
        const devSection = document.getElementById("nms-detail-device-section");
        const connSection = document.getElementById("nms-detail-connection-section");
        if (devSection) devSection.classList.remove("hidden");
        if (connSection) connSection.classList.add("hidden");
        
        showNmsDetailPanel(dev);
        zoomToNmsNode(dev);
    }
    
    if (appState.nms.layoutMode === "geo") {
        renderNmsLeafletMap();
    }
}

function getRelatedPeerConnections(conn) {
    if (!conn) return [];
    const sDev = appState.nms.devices.find(d => d.name === conn.source);
    const tDev = appState.nms.devices.find(d => d.name === conn.target);
    const oltName = (sDev && sDev.type === "OLT") ? sDev.name : (tDev && tDev.type === "OLT") ? tDev.name : null;

    return appState.nms.connections.filter(c => {
        if (c.hidden) return false;
        const samePair = (c.source === conn.source && c.target === conn.target) ||
                         (c.source === conn.target && c.target === conn.source);
        if (samePair) return true;
        // If one endpoint is an OLT, also include any redundant/peer uplinks attached to that OLT
        if (oltName && (c.source === oltName || c.target === oltName)) return true;
        return false;
    });
}

function selectNmsConnection(connId) {
    appState.nms.selectedNodeId = null;
    appState.nms.selectedConnectionId = connId;
    
    const conn = appState.nms.connections.find(c => c.id === connId);
    if (!conn) return;
    
    const allConnsInPair = getRelatedPeerConnections(conn);
    const peerDeviceSet = new Set();
    allConnsInPair.forEach(c => {
        peerDeviceSet.add(c.source);
        peerDeviceSet.add(c.target);
    });
    
    if (appState.nms.layoutMode === "geo") {
        renderNmsLeafletMap();
    } else if (appState.nms.layoutMode === "logical") {
        renderNmsGraph();
    }

    // Highlight connection endpoint & peer nodes
    document.querySelectorAll(".nms-node").forEach(n => {
        const nodeId = n.getAttribute("data-id");
        const dev = appState.nms.devices.find(d => d.id === nodeId);
        if (dev && peerDeviceSet.has(dev.name)) {
            n.classList.add("selected");
        } else {
            n.classList.remove("selected");
        }
    });
    
    // Highlight connection line in SVG graph
    document.querySelectorAll(".nms-link-line").forEach(line => {
        const ids = (line.getAttribute("data-id") || "").split(",");
        const hasAnyId = ids.some(id => allConnsInPair.some(ac => ac.id === id));
        if (hasAnyId) line.classList.add("selected");
        else line.classList.remove("selected");
    });
    
    showNmsConnectionDetailPanel(allConnsInPair, conn);
    zoomToNmsConnection(conn);
}

function showNmsConnectionDetailPanel(allConns, selectedConn) {
    const placeholder = document.getElementById("nms-detail-placeholder");
    const content = document.getElementById("nms-detail-content");
    const devSection = document.getElementById("nms-detail-device-section");
    const connSection = document.getElementById("nms-detail-connection-section");
    if (!content || !devSection || !connSection) return;
    
    if (placeholder) placeholder.classList.add("hidden");
    content.classList.remove("hidden");
    
    // Swap sub-sections
    devSection.classList.add("hidden");
    connSection.classList.remove("hidden");
    
    const connsList = Array.isArray(allConns) ? allConns : [allConns];
    const mainConn = selectedConn || connsList[0];
    
    if (connsList.length > 1) {
        document.getElementById("nms-detail-name").innerText = `${mainConn.source} ↔ ${mainConn.target}`;
        document.getElementById("nms-detail-type").innerText = `${connsList.length} Aggregated Links`;
    } else {
        document.getElementById("nms-detail-name").innerText = mainConn.link || "Unnamed Connection";
        document.getElementById("nms-detail-type").innerText = mainConn.type || "Interlink";
    }
    
    const detailIcon = document.getElementById("nms-detail-icon");
    if (detailIcon) {
        detailIcon.innerHTML = `<i class="fa-solid fa-link" style="color: var(--primary);"></i>`;
    }
    
    const container = document.getElementById("nms-detail-connections-list-container");
    if (container) {
        container.innerHTML = "";
        
        // Sort so the clicked connection (selectedConn) or NOK links appear first
        const sortedList = [...connsList].sort((a, b) => {
            if (selectedConn && a.id === selectedConn.id) return -1;
            if (selectedConn && b.id === selectedConn.id) return 1;
            const oa = getConnectionOpticalInfo(a);
            const ob = getConnectionOpticalInfo(b);
            if (oa.isNok && !ob.isNok) return -1;
            if (!oa.isNok && ob.isNok) return 1;
            return 0;
        });

        sortedList.forEach((c, index) => {
            const card = document.createElement("div");
            card.className = `nms-detail-conn-card`;
            const optInfo = getConnectionOpticalInfo(c);
            const isClickedConn = selectedConn && c.id === selectedConn.id && sortedList.length > 1;
            if (c.hidden) {
                card.style.opacity = "0.55";
            }
            if (optInfo.worstSeverity === "alarm") {
                card.style.borderColor = "rgba(239, 68, 68, 0.6)";
                card.style.boxShadow = "0 0 12px rgba(239, 68, 68, 0.15)";
            } else if (optInfo.worstSeverity === "warning") {
                card.style.borderColor = "rgba(249, 115, 22, 0.55)";
            } else if (isClickedConn) {
                card.style.borderColor = "rgba(59, 130, 246, 0.65)";
            }

            const opticalBoxesHtml = [
                renderOpticalEndpointBox("Source", c.source, c.source_interface, optInfo.sourceOpt),
                renderOpticalEndpointBox("Target", c.target, c.target_interface, optInfo.targetOpt)
            ].filter(Boolean).join("");
            
            const extraTags = [
                c.dual_track ? "Dual-Track" : "",
                c.multipath_lag ? "Multipath LAG" : ""
            ].filter(Boolean);

            card.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center; gap: 6px; margin-bottom: 8px; padding-bottom: 6px; border-bottom: 1px solid rgba(255,255,255,0.08);">
                    <span style="font-size: 0.78rem; font-weight: 700; color: var(--text-main);">
                        ${connsList.length > 1 ? `${isClickedConn ? 'Selected' : 'Peer'} Link #${index + 1}: ${escapeHTML(c.source + ' ↔ ' + c.target)}` : escapeHTML(c.source + ' ↔ ' + c.target)}
                    </span>
                    <div style="display: flex; align-items: center; gap: 5px;">
                        <span class="badge" style="font-size: 0.64rem; padding: 2px 6px;">${c.bitrate || 10}G ${escapeHTML(c.type || 'Interlink')}</span>
                        <span style="font-size: 0.68rem; color: var(--text-muted); display: inline-flex; align-items: center; gap: 4px;">
                            <span class="status-indicator ${c.status === 'Active' ? 'online' : 'offline'}" style="margin: 0;"></span>${escapeHTML(c.status || 'Active')}
                        </span>
                    </div>
                </div>
                <div style="display: flex; flex-direction: column; gap: 5px; font-size: 0.74rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center; gap: 8px;">
                        <span style="color: var(--text-muted);">Source:</span>
                        <span style="font-family: monospace; font-weight: 600; color: var(--text-main); text-align: right;">${escapeHTML(c.source)} [${escapeHTML(c.source_interface || '-')}]${c.source_lag ? ` (${escapeHTML(c.source_lag)})` : ''}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; gap: 8px;">
                        <span style="color: var(--text-muted);">Target:</span>
                        <span style="font-family: monospace; font-weight: 600; color: var(--text-main); text-align: right;">${escapeHTML(c.target)} [${escapeHTML(c.target_interface || '-')}]${c.target_lag ? ` (${escapeHTML(c.target_lag)})` : ''}</span>
                    </div>
                    ${extraTags.length > 0 ? `
                        <div style="display: flex; justify-content: space-between; align-items: center; gap: 8px;">
                            <span style="color: var(--text-muted);">Attributes:</span>
                            <span style="font-size: 0.68rem; color: #cbd5e1;">${escapeHTML(extraTags.join(' • '))}</span>
                        </div>
                    ` : ''}
                </div>
                ${opticalBoxesHtml ? `
                    <div style="margin-top: 8px; padding-top: 8px; border-top: 1px solid rgba(255,255,255,0.08);">
                        <div style="font-size: 0.66rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-muted); margin-bottom: 2px;">
                            <i class="fa-solid fa-bolt" style="color: #f59e0b; margin-right: 4px;"></i>Optical Power
                        </div>
                        ${opticalBoxesHtml}
                    </div>
                ` : ""}
                <div style="display: flex; gap: 8px; margin-top: 8px; padding-top: 6px; border-top: 1px solid rgba(255,255,255,0.05); justify-content: flex-end;">
                    <button class="btn btn-secondary btn-sm" onclick="sidebarToggleConnectionVisibility('${c.id}')" style="padding: 3px 8px; font-size: 0.68rem; display: flex; align-items: center; gap: 4px; background: rgba(255,255,255,0.03); border: 1px solid var(--border-color); color: var(--text-muted); cursor: pointer; border-radius: 4px;">
                        <i class="fa-regular ${c.hidden ? 'fa-eye' : 'fa-eye-slash'}"></i>
                        <span>${c.hidden ? 'Unhide' : 'Hide'}</span>
                    </button>
                </div>
            `;
            container.appendChild(card);
        });
    }
}

function zoomToNmsNode(dev) {
    // Auto-zooming and centering on click selection is disabled globally
}

function zoomToNmsConnection(conn) {
    // Auto-zooming and centering on click selection is disabled globally
}

function showNmsDetailPanel(dev) {
    const placeholder = document.getElementById("nms-detail-placeholder");
    const content = document.getElementById("nms-detail-content");
    if (!content) return;
    
    if (placeholder) placeholder.classList.add("hidden");
    content.classList.remove("hidden");
    
    document.getElementById("nms-detail-name").innerText = dev.name;
    document.getElementById("nms-detail-type").innerText = dev.type;
    document.getElementById("nms-detail-model").innerText = `${dev.brand} ${dev.model}`;
    document.getElementById("nms-detail-ip").innerText = dev.ip;
    
    const statusText = document.getElementById("nms-detail-status");
    const indicatorClass = dev.status.toLowerCase();
    statusText.innerHTML = `<span class="status-indicator ${indicatorClass}"></span> ${dev.status}`;
    
    const connsList = document.getElementById("nms-detail-conns-list");
    connsList.innerHTML = "";
    
    const adjacent = appState.nms.connections.filter(c => c.source === dev.name || c.target === dev.name);
    if (adjacent.length === 0) {
        connsList.innerHTML = `<li><i class="fa-solid fa-ban"></i> No connected interfaces.</li>`;
    } else {
        const peerGroups = {};
        adjacent.forEach(c => {
            const peer = c.source === dev.name ? c.target : c.source;
            if (!peerGroups[peer]) peerGroups[peer] = [];
            peerGroups[peer].push(c);
        });
        
        Object.keys(peerGroups).forEach(peer => {
            const conns = peerGroups[peer];
            const formatOptPill = (conn) => {
                const oi = getConnectionOpticalInfo(conn);
                if (!oi.primaryOpt || oi.primaryOpt.status !== "success") return "";
                const h = oi.primaryHealth;
                const bg = h.severity === "alarm" ? "rgba(239,68,68,0.2)" : h.severity === "warning" ? "rgba(249,115,22,0.2)" : "rgba(16,185,129,0.15)";
                return ` <span onclick="event.stopPropagation(); selectNmsConnection('${conn.id}')" title="Click for optical details (${escapeHTML(h.statusText)})" style="display: inline-block; padding: 1px 6px; border-radius: 4px; font-family: monospace; font-size: 0.68rem; font-weight: 700; background: ${bg}; color: ${h.color}; border: 1px solid ${h.color}; cursor: pointer;">${h.severity !== 'normal' ? '⚠ ' : ''}${escapeHTML(h.rxText)}</span>`;
            };
            if (conns.length === 1) {
                const c = conns[0];
                const myPort = c.source === dev.name ? c.source_interface : c.target_interface;
                const peerPort = c.source === dev.name ? c.target_interface : c.source_interface;
                const typeText = c.type || "Interlink";
                const iconClass = typeText === "Uplink" ? "fa-arrow-right" : "fa-arrow-right-arrow-left";
                
                const li = document.createElement("li");
                li.style.cursor = "pointer";
                li.onclick = () => selectNmsConnection(c.id);
                li.innerHTML = `<i class="fa-solid ${iconClass}"></i> [${myPort || 'no-port'}] to <strong>${peer}</strong> [${peerPort || 'no-port'}] (${c.bitrate}G via ${c.link || 'Link'})${formatOptPill(c)}`;
                connsList.appendChild(li);
            } else {
                const totalCapacity = conns.reduce((sum, c) => sum + (parseInt(c.bitrate) || 0), 0);
                const parentLi = document.createElement("li");
                parentLi.innerHTML = `<i class="fa-solid fa-network-wired"></i> to <strong>${peer}</strong> (Total: <strong>${totalCapacity}G</strong> across ${conns.length} connections)`;
                
                const subUl = document.createElement("ul");
                subUl.style.paddingLeft = "20px";
                subUl.style.marginTop = "4px";
                subUl.style.listStyleType = "circle";
                subUl.style.fontSize = "0.75rem";
                
                conns.forEach(c => {
                    const myPort = c.source === dev.name ? c.source_interface : c.target_interface;
                    const peerPort = c.source === dev.name ? c.target_interface : c.source_interface;
                    const typeText = c.type || "Interlink";
                    const subLi = document.createElement("li");
                    subLi.style.cursor = "pointer";
                    subLi.onclick = () => selectNmsConnection(c.id);
                    subLi.innerHTML = `[${myPort || 'no-port'}] to [${peerPort || 'no-port'}] (${c.bitrate}G)${formatOptPill(c)}`;
                    subUl.appendChild(subLi);
                });
                
                parentLi.appendChild(subUl);
                connsList.appendChild(parentLi);
            }
        });
    }
    
    const detailIcon = document.getElementById("nms-detail-icon");
    if (detailIcon) {
        detailIcon.innerHTML = dev.type === "Router" ? `<i class="fa-solid fa-server"></i>` : `<i class="fa-solid fa-sitemap"></i>`;
    }
    
    // Co-located cluster section representation
    const colocatedContainer = document.getElementById("nms-detail-colocated-container");
    if (colocatedContainer) {
        colocatedContainer.innerHTML = "";
        if (appState.nms.layoutMode === "geo") {
            const myLat = parseFloat(dev.latitude);
            const myLng = parseFloat(dev.longitude);
            
            if (!isNaN(myLat) && !isNaN(myLng)) {
                const colocated = appState.nms.devices.filter(d => 
                    d.id !== dev.id && 
                    parseFloat(d.latitude).toFixed(4) === myLat.toFixed(4) && 
                    parseFloat(d.longitude).toFixed(4) === myLng.toFixed(4)
                );
                
                if (colocated.length > 0) {
                    let html = `<div class="detail-colocated" style="margin-top: 15px; border-top: 1px solid var(--border-color); padding-top: 15px; min-width: 0;">`;
                    html += `<h4 style="font-size: 0.8rem; color: var(--text-main); margin-bottom: 8px;"><i class="fa-solid fa-layer-group" style="margin-right: 6px; color: var(--primary);"></i> Co-located Equipment (${colocated.length + 1})</h4>`;
                    html += `<ul style="list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 6px;">`;
                    
                    html += `<li style="font-size: 0.8rem; display: flex; align-items: center; gap: 8px;">`;
                    html += `<span style="width: 6px; height: 6px; background-color: var(--primary); border-radius: 50%;"></span>`;
                    html += `<span style="color: var(--text-main); font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 170px;">${dev.name} (${dev.type})</span> <span class="badge" style="font-size: 0.65rem; background: rgba(59, 130, 246, 0.15); color: var(--primary); padding: 1px 4px; border-radius: 3px; white-space: nowrap;">Active</span>`;
                    html += `</li>`;
                    
                    colocated.forEach(member => {
                        html += `<li style="font-size: 0.8rem; display: flex; align-items: center; gap: 8px;">`;
                        html += `<span style="width: 6px; height: 6px; background-color: transparent; border: 1px solid var(--text-muted); border-radius: 50%;"></span>`;
                        html += `<a href="#" onclick="event.preventDefault(); selectNmsNode('${member.id}')" style="color: var(--text-dim); text-decoration: none; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 180px; transition: color 0.2s;" onmouseover="this.style.color='var(--text-main)'" onmouseout="this.style.color='var(--text-dim)'">${member.name} (${member.type})</a>`;
                        html += `</li>`;
                    });
                    
                    html += `</ul>`;
                    html += `</div>`;
                    colocatedContainer.innerHTML = html;
                }
            }
        }
    }
}

function renderNmsSpreadsheet() {
    const devBody = document.getElementById("devices-sheet-body");
    const connBody = document.getElementById("connections-sheet-body");
    
    const searchInput = document.getElementById("nms-search-input");
    const query = searchInput ? searchInput.value.toLowerCase().trim() : "";
    
    const isEditDisabled = !appState.nms.editModeEnabled;
    
    if (devBody) {
        devBody.innerHTML = "";
        const filters = getVisibilityFilters();
        let filteredDevs = appState.nms.devices.filter(d => 
            (d.type === "Router" && filters.showRouters) || 
            (d.type === "OLT" && filters.showOlts)
        );
        
        if (query) {
            filteredDevs = filteredDevs.filter(d => 
                (d.name && d.name.toLowerCase().includes(query)) ||
                (d.type && d.type.toLowerCase().includes(query)) ||
                (d.brand && d.brand.toLowerCase().includes(query)) ||
                (d.model && d.model.toLowerCase().includes(query)) ||
                (d.ip && d.ip.toLowerCase().includes(query)) ||
                (d.status && d.status.toLowerCase().includes(query))
            );
        }
        
        if (filteredDevs.length === 0) {
            devBody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-dim);">${query ? 'No matching devices found.' : 'No devices. Click "Add Device Row" to add.'}</td></tr>`;
        } else {
            filteredDevs.forEach((dev, idx) => {
                const tr = document.createElement("tr");
                tr.setAttribute("data-id", dev.id);
                if (dev.hidden) {
                    tr.classList.add("row-hidden");
                }
                
                tr.innerHTML = `
                    <td>
                        <input type="text" value="${escapeHTML(dev.name)}" data-field="name" placeholder="Router-Name" ${isEditDisabled ? 'disabled' : ''} />
                    </td>
                    <td>
                        <select data-field="type" ${isEditDisabled ? 'disabled' : ''}>
                            <option value="Router" ${dev.type === 'Router' ? 'selected' : ''}>Router</option>
                            <option value="OLT" ${dev.type === 'OLT' ? 'selected' : ''}>OLT</option>
                        </select>
                    </td>
                    <td>
                        <input type="text" value="${escapeHTML(dev.brand + (dev.model ? ' ' + dev.model : ''))}" data-field="brandModel" placeholder="Brand & Model" ${isEditDisabled ? 'disabled' : ''} />
                    </td>
                    <td>
                        <input type="text" value="${escapeHTML(dev.ip)}" data-field="ip" placeholder="10.0.0.1" ${isEditDisabled ? 'disabled' : ''} />
                    </td>
                    <td>
                        <select data-field="status" ${isEditDisabled ? 'disabled' : ''}>
                            <option value="Online" ${dev.status === 'Online' ? 'selected' : ''}>Online</option>
                            <option value="Offline" ${dev.status === 'Offline' ? 'selected' : ''}>Offline</option>
                            <option value="Maintenance" ${dev.status === 'Maintenance' ? 'selected' : ''}>Maintenance</option>
                        </select>
                    </td>
                    <td>
                        <input type="number" step="any" value="${dev.latitude !== undefined ? dev.latitude : ''}" data-field="latitude" placeholder="-6.2000" ${isEditDisabled ? 'disabled' : ''} />
                    </td>
                    <td>
                        <input type="number" step="any" value="${dev.longitude !== undefined ? dev.longitude : ''}" data-field="longitude" placeholder="106.8000" ${isEditDisabled ? 'disabled' : ''} />
                    </td>
                    <td>
                        <div style="display: flex; justify-content: center; align-items: center; width: 100%; height: 100%; min-height: 24px;">
                            <input type="checkbox" ${dev.outside_managed ? 'checked' : ''} data-field="outside_managed" ${isEditDisabled ? 'disabled' : ''} style="cursor: pointer; width: 15px; height: 15px; margin: 0; padding: 0;" />
                        </div>
                    </td>
                    <td class="col-actions" style="display: flex; gap: 6px; justify-content: center; align-items: center; min-height: 38px;">
                        <button class="btn-toggle-visibility" title="${dev.hidden ? 'Show Device' : 'Hide Device'}" onclick="toggleDeviceVisibility('${dev.id}', event)" style="background: none; border: none; color: ${dev.hidden ? 'var(--text-dim)' : 'var(--primary)'}; cursor: pointer; padding: 4px; font-size: 0.85rem; display: flex; align-items: center; justify-content: center;">
                            <i class="fa-regular ${dev.hidden ? 'fa-eye-slash' : 'fa-eye'}"></i>
                        </button>
                        <button class="btn-delete-row" title="Delete Device" onclick="deleteDeviceRow('${dev.id}')" ${isEditDisabled ? 'disabled style="opacity: 0.4; cursor: not-allowed;"' : ''}>
                            <i class="fa-regular fa-trash-can"></i>
                        </button>
                    </td>
                `;
                
                tr.querySelectorAll("input, select").forEach(input => {
                    input.addEventListener("change", (e) => handleNmsSpreadsheetEdit("device", dev.id, e.target));
                });
                tr.querySelectorAll("input").forEach(input => {
                    input.addEventListener("paste", (e) => handleCellPaste(e, dev.id, e.target.getAttribute("data-field")));
                });
                
                tr.style.cursor = "pointer";
                tr.addEventListener("click", (e) => {
                    if (appState.nms.editModeEnabled && e.target.tagName.match(/INPUT|SELECT|BUTTON|I/)) {
                        return;
                    }
                    selectNmsNode(dev.id);
                });
                
                devBody.appendChild(tr);
            });
        }
    }
    
    if (connBody) {
        connBody.innerHTML = "";
        const filters = getVisibilityFilters();
        const visibleDeviceNames = new Set(appState.nms.devices
            .filter(d => (d.type === "Router" && filters.showRouters) || (d.type === "OLT" && filters.showOlts))
            .map(d => d.name)
        );
        
        let filteredConns = appState.nms.connections.filter(c => 
            visibleDeviceNames.has(c.source) && visibleDeviceNames.has(c.target) &&
            (!filters.onlyOpticalNok || getConnectionOpticalInfo(c).isNok)
        );
        
        if (query) {
            filteredConns = filteredConns.filter(c => 
                (c.source && c.source.toLowerCase().includes(query)) ||
                (c.target && c.target.toLowerCase().includes(query)) ||
                (c.link && c.link.toLowerCase().includes(query)) ||
                (c.source_interface && c.source_interface.toLowerCase().includes(query)) ||
                (c.target_interface && c.target_interface.toLowerCase().includes(query))
            );
        }
        
        if (filteredConns.length === 0) {
            connBody.innerHTML = `<tr><td colspan="12" style="text-align: center; color: var(--text-dim);">${query ? 'No matching connections found.' : 'No connections. Click "Add Connection Row" to add.'}</td></tr>`;
        } else {
            filteredConns.forEach(conn => {
                const tr = document.createElement("tr");
                tr.setAttribute("data-id", conn.id);
                if (conn.hidden) {
                    tr.classList.add("row-hidden");
                }
                
                // Calculate link type based on device types automatically
                const sourceDev = appState.nms.devices.find(d => d.name === conn.source);
                const targetDev = appState.nms.devices.find(d => d.name === conn.target);
                let computedType = "Uplink";
                if (sourceDev && targetDev) {
                    if (sourceDev.type === "Router" && targetDev.type === "Router") {
                        computedType = "Interlink";
                    }
                }
                conn.type = computedType; // keep dynamic connection model in sync
                
                const deviceOptions = appState.nms.devices.map(d => `<option value="${escapeHTML(d.name)}" ${d.name === conn.source ? 'selected' : ''}>${escapeHTML(d.name)}</option>`).join("");
                const targetOptions = appState.nms.devices.map(d => `<option value="${escapeHTML(d.name)}" ${d.name === conn.target ? 'selected' : ''}>${escapeHTML(d.name)}</option>`).join("");
                
                tr.innerHTML = `
                    <td>
                        <select data-field="source" ${isEditDisabled ? 'disabled' : ''}>
                            <option value="" ${!conn.source ? 'selected' : ''}>-- Select --</option>
                            ${deviceOptions}
                        </select>
                    </td>
                    <td>
                        <input type="text" value="${escapeHTML(conn.source_interface || '')}" data-field="source_interface" placeholder="GE-1/0/1" ${isEditDisabled ? 'disabled' : ''} />
                    </td>
                    <td>
                        <input type="text" value="${escapeHTML(conn.source_lag || '')}" data-field="source_lag" placeholder="" ${isEditDisabled ? 'disabled' : ''} />
                    </td>
                    <td>
                        <select data-field="target" ${isEditDisabled ? 'disabled' : ''}>
                            <option value="" ${!conn.target ? 'selected' : ''}>-- Select --</option>
                            ${targetOptions}
                        </select>
                    </td>
                    <td>
                        <input type="text" value="${escapeHTML(conn.target_interface || '')}" data-field="target_interface" placeholder="GE-1/0/2" ${isEditDisabled ? 'disabled' : ''} />
                    </td>
                    <td>
                        <input type="text" value="${escapeHTML(conn.target_lag || '')}" data-field="target_lag" placeholder="" ${isEditDisabled ? 'disabled' : ''} />
                    </td>
                    <td>
                        <input type="number" value="${conn.bitrate}" data-field="bitrate" min="1" max="1000" ${isEditDisabled ? 'disabled' : ''} />
                    </td>
                    <td>
                        <input type="text" value="${escapeHTML(conn.link)}" data-field="link" placeholder="FO-Cable-X" ${isEditDisabled ? 'disabled' : ''} />
                    </td>
                    <td style="vertical-align: middle; text-align: center;">
                        <span class="badge ${computedType === 'Interlink' ? 'badge-interlink' : 'badge-uplink'}" style="padding: 4px 10px; border-radius: 20px; display: inline-flex; min-width: 70px; justify-content: center; font-size: 0.7rem; font-weight: 600;">
                            ${computedType}
                        </span>
                    </td>
                    <td>
                        <select data-field="status" ${isEditDisabled ? 'disabled' : ''}>
                            <option value="Active" ${conn.status === 'Active' ? 'selected' : ''}>Active</option>
                            <option value="Backup" ${conn.status === 'Backup' ? 'selected' : ''}>Backup</option>
                        </select>
                    </td>
                    <td style="text-align: center;">
                        <input type="checkbox" data-field="dual_track" ${conn.dual_track ? 'checked' : ''} ${isEditDisabled ? 'disabled' : ''} style="cursor: pointer; width: auto; margin: 0 auto; display: block;" />
                    </td>
                    <td style="text-align: center;">
                        <input type="checkbox" data-field="multipath_lag" ${conn.multipath_lag ? 'checked' : ''} ${isEditDisabled ? 'disabled' : ''} style="cursor: pointer; width: auto; margin: 0 auto; display: block;" />
                    </td>
                    <td class="col-actions" style="display: flex; gap: 6px; justify-content: center; align-items: center; min-height: 38px;">
                        <button class="btn-toggle-visibility" title="${conn.hidden ? 'Show Connection' : 'Hide Connection'}" onclick="toggleConnectionVisibility('${conn.id}', event)" style="background: none; border: none; color: ${conn.hidden ? 'var(--text-dim)' : 'var(--primary)'}; cursor: pointer; padding: 4px; font-size: 0.85rem; display: flex; align-items: center; justify-content: center;">
                            <i class="fa-regular ${conn.hidden ? 'fa-eye-slash' : 'fa-eye'}"></i>
                        </button>
                        <button class="btn-delete-row" title="Delete Connection" onclick="deleteConnectionRow('${conn.id}')" ${isEditDisabled ? 'disabled style="opacity: 0.4; cursor: not-allowed;"' : ''}>
                            <i class="fa-regular fa-trash-can"></i>
                        </button>
                    </td>
                `;
                
                tr.querySelectorAll("input, select").forEach(input => {
                    input.addEventListener("change", (e) => handleNmsSpreadsheetEdit("connection", conn.id, e.target));
                });
                
                tr.style.cursor = "pointer";
                tr.addEventListener("click", (e) => {
                    if (appState.nms.editModeEnabled && e.target.tagName.match(/INPUT|SELECT|BUTTON|I/)) {
                        return;
                    }
                    selectNmsConnection(conn.id);
                });
                
                connBody.appendChild(tr);
            });
        }
    }
    
    // Disable action buttons in view mode
    const addDeviceRowBtn = document.getElementById("add-device-row-btn");
    const addConnectionRowBtn = document.getElementById("add-connection-row-btn");
    const batchBtn = document.getElementById("nms-batch-btn");
    const connBatchBtn = document.getElementById("nms-conn-batch-btn");
    const saveBtn = document.getElementById("nms-save-btn");
    
    if (addDeviceRowBtn) addDeviceRowBtn.disabled = isEditDisabled;
    if (addConnectionRowBtn) addConnectionRowBtn.disabled = isEditDisabled;
    if (batchBtn) batchBtn.disabled = isEditDisabled;
    if (connBatchBtn) connBatchBtn.disabled = isEditDisabled;
    if (saveBtn) {
        saveBtn.disabled = isEditDisabled || !appState.nms.hasChanges;
    }
}

function handleNmsSpreadsheetEdit(type, id, target) {
    const field = target.getAttribute("data-field");
    const val = target.type === "checkbox" ? target.checked : target.value;
    
    appState.nms.hasChanges = true;
    markUnsavedChanges(true);
    
    if (type === "device") {
        const dev = appState.nms.devices.find(d => d.id === id);
        if (!dev) return;
        
        if (field === "name") {
            const oldName = dev.name;
            const newName = val.trim();
            dev.name = newName;
            
            // Sync connection node name fields
            appState.nms.connections.forEach(c => {
                if (c.source === oldName) c.source = newName;
                if (c.target === oldName) c.target = newName;
            });
            
            // Re-render
            renderNmsSpreadsheet();
            renderNmsGraph();
        } else if (field === "brandModel") {
            const parts = val.trim().split(/\s+/);
            dev.brand = parts[0] || "";
            dev.model = parts.slice(1).join(" ") || "";
        } else if (field === "type") {
            dev.type = val;
            renderNmsGraph();
            renderNmsSpreadsheet();
        } else if (field === "ip") {
            dev.ip = val.trim();
            renderNmsGraph();
        } else if (field === "status") {
            dev.status = val;
            renderNmsGraph();
        } else if (field === "latitude") {
            dev.latitude = parseFloat(val) || 0;
            if (appState.nms.layoutMode === "geo") {
                projectGeographicCoords();
            }
            renderNmsGraph();
        } else if (field === "longitude") {
            dev.longitude = parseFloat(val) || 0;
            if (appState.nms.layoutMode === "geo") {
                projectGeographicCoords();
            }
            renderNmsGraph();
        } else if (field === "outside_managed") {
            dev.outside_managed = val;
            updateNmsSummaryDashboard();
        }
    } else if (type === "connection") {
        const conn = appState.nms.connections.find(c => c.id === id);
        if (!conn) return;
        
        if (field === "source") {
            conn.source = val;
            const sDev = appState.nms.devices.find(d => d.name === conn.source);
            const tDev = appState.nms.devices.find(d => d.name === conn.target);
            conn.type = (sDev && tDev && sDev.type === "Router" && tDev.type === "Router") ? "Interlink" : "Uplink";
            renderNmsGraph();
            renderNmsSpreadsheet();
        } else if (field === "source_interface") {
            conn.source_interface = val.trim();
            renderNmsGraph();
        } else if (field === "source_lag") {
            conn.source_lag = val.trim();
            renderNmsGraph();
        } else if (field === "target") {
            conn.target = val;
            const sDev = appState.nms.devices.find(d => d.name === conn.source);
            const tDev = appState.nms.devices.find(d => d.name === conn.target);
            conn.type = (sDev && tDev && sDev.type === "Router" && tDev.type === "Router") ? "Interlink" : "Uplink";
            renderNmsGraph();
            renderNmsSpreadsheet();
        } else if (field === "target_interface") {
            conn.target_interface = val.trim();
            renderNmsGraph();
        } else if (field === "target_lag") {
            conn.target_lag = val.trim();
            renderNmsGraph();
        } else if (field === "bitrate") {
            conn.bitrate = parseInt(val) || 10;
            renderNmsGraph();
        } else if (field === "link") {
            conn.link = val.trim();
            renderNmsGraph();
        } else if (field === "status") {
            conn.status = val;
            renderNmsGraph();
        } else if (field === "dual_track") {
            conn.dual_track = target.checked;
            if (appState.nms.layoutMode === "geo") {
                renderNmsLeafletMap();
            } else {
                renderNmsGraph();
            }
        } else if (field === "multipath_lag") {
            const isChecked = target.checked;
            conn.multipath_lag = isChecked;
            
            const src = conn.source;
            const tgt = conn.target;
            const srcLag = conn.source_lag ? conn.source_lag.trim() : "";
            const tgtLag = conn.target_lag ? conn.target_lag.trim() : "";
            
            if (srcLag || tgtLag) {
                appState.nms.connections.forEach(c => {
                    if (c.source === src && c.target === tgt) {
                        const matchSrcLag = srcLag && c.source_lag && c.source_lag.trim() === srcLag;
                        const matchTgtLag = tgtLag && c.target_lag && c.target_lag.trim() === tgtLag;
                        if (matchSrcLag || matchTgtLag) {
                            c.multipath_lag = isChecked;
                        }
                    }
                });
            }
            
            renderNmsSpreadsheet();
            if (appState.nms.layoutMode === "geo") {
                renderNmsLeafletMap();
            } else {
                renderNmsGraph();
            }
        }
    }
    
    validateNmsData();
}

function validateNmsData() {
    const errorMsg = document.getElementById("editor-validation-msg");
    if (!errorMsg) return true;
    
    const devices = appState.nms.devices;
    const connections = appState.nms.connections;
    let errors = [];
    
    const names = new Set();
    const ips = new Set();
    
    devices.forEach((dev, idx) => {
        const tr = document.querySelector(`#devices-sheet-body tr[data-id="${dev.id}"]`);
        if (tr) tr.querySelectorAll("td").forEach(td => td.classList.remove("invalid-cell"));
        
        if (!dev.name || dev.name.trim() === "") {
            errors.push(`Row ${idx+1}: Device Name is required.`);
            if (tr) tr.querySelector('input[data-field="name"]').parentElement.classList.add("invalid-cell");
        } else if (names.has(dev.name)) {
            errors.push(`Duplicate device name: "${dev.name}".`);
            if (tr) tr.querySelector('input[data-field="name"]').parentElement.classList.add("invalid-cell");
        } else {
            names.add(dev.name);
        }
        
        const ipPattern = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
        if (!dev.ip || dev.ip.trim() === "") {
            errors.push(`Device "${dev.name || 'Row '+(idx+1)}": IP Address is required.`);
            if (tr) tr.querySelector('input[data-field="ip"]').parentElement.classList.add("invalid-cell");
        } else if (!ipPattern.test(dev.ip)) {
            errors.push(`Device "${dev.name || 'Row '+(idx+1)}": Invalid IP Address format.`);
            if (tr) tr.querySelector('input[data-field="ip"]').parentElement.classList.add("invalid-cell");
        } else if (ips.has(dev.ip)) {
            errors.push(`Duplicate IP Address: "${dev.ip}" on device "${dev.name}".`);
            if (tr) tr.querySelector('input[data-field="ip"]').parentElement.classList.add("invalid-cell");
        } else {
            ips.add(dev.ip);
        }
        
        if (dev.latitude === undefined || dev.latitude === null || isNaN(parseFloat(dev.latitude))) {
            errors.push(`Device "${dev.name || 'Row '+(idx+1)}": Latitude must be a valid decimal number.`);
            if (tr) tr.querySelector('input[data-field="latitude"]').parentElement.classList.add("invalid-cell");
        }
        
        if (dev.longitude === undefined || dev.longitude === null || isNaN(parseFloat(dev.longitude))) {
            errors.push(`Device "${dev.name || 'Row '+(idx+1)}": Longitude must be a valid decimal number.`);
            if (tr) tr.querySelector('input[data-field="longitude"]').parentElement.classList.add("invalid-cell");
        }
    });
    
    connections.forEach((conn, idx) => {
        const tr = document.querySelector(`#connections-sheet-body tr[data-id="${conn.id}"]`);
        if (tr) tr.querySelectorAll("td").forEach(td => td.classList.remove("invalid-cell"));
        
        if (!conn.source || conn.source === "") {
            errors.push(`Connection Row ${idx+1}: Source Device is required.`);
            if (tr) tr.querySelector('select[data-field="source"]').parentElement.classList.add("invalid-cell");
        }
        
        if (!conn.target || conn.target === "") {
            errors.push(`Connection Row ${idx+1}: Target Device is required.`);
            if (tr) tr.querySelector('select[data-field="target"]').parentElement.classList.add("invalid-cell");
        }
        
        if (conn.source && conn.target) {
            if (conn.source === conn.target) {
                errors.push(`Connection Row ${idx+1}: Loopback connection not allowed (Source equals Target: "${conn.source}").`);
                if (tr) {
                    tr.querySelector('select[data-field="source"]').parentElement.classList.add("invalid-cell");
                    tr.querySelector('select[data-field="target"]').parentElement.classList.add("invalid-cell");
                }
            }
            
            const srcExists = devices.some(d => d.name === conn.source);
            const tgtExists = devices.some(d => d.name === conn.target);
            
            if (!srcExists) {
                errors.push(`Connection Row ${idx+1}: Source Device "${conn.source}" does not exist.`);
                if (tr) tr.querySelector('select[data-field="source"]').parentElement.classList.add("invalid-cell");
            }
            if (!tgtExists) {
                errors.push(`Connection Row ${idx+1}: Target Device "${conn.target}" does not exist.`);
                if (tr) tr.querySelector('select[data-field="target"]').parentElement.classList.add("invalid-cell");
            }
        }
        
        if (!conn.source_interface || conn.source_interface.trim() === "") {
            errors.push(`Connection Row ${idx+1}: Source Interface is required.`);
            if (tr) tr.querySelector('input[data-field="source_interface"]').parentElement.classList.add("invalid-cell");
        }
        
        if (!conn.target_interface || conn.target_interface.trim() === "") {
            errors.push(`Connection Row ${idx+1}: Target Interface is required.`);
            if (tr) tr.querySelector('input[data-field="target_interface"]').parentElement.classList.add("invalid-cell");
        }
        
        if (isNaN(conn.bitrate) || conn.bitrate <= 0) {
            errors.push(`Connection Row ${idx+1}: Capacity must be greater than 0.`);
            if (tr) tr.querySelector('input[data-field="bitrate"]').parentElement.classList.add("invalid-cell");
        }
    });
    
    if (errors.length > 0) {
        errorMsg.className = "validation-msg error";
        errorMsg.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> <strong>Validation Errors:</strong> ${errors[0]} (${errors.length} total)`;
        document.getElementById("nms-save-btn").disabled = true;
        return false;
    } else {
        errorMsg.className = "validation-msg success";
        errorMsg.innerHTML = `<i class="fa-solid fa-circle-check"></i> Topology spreadsheet configuration is valid.`;
        document.getElementById("nms-save-btn").disabled = false;
        return true;
    }
}

function addDeviceRow() {
    const newId = `dev-${Date.now()}`;
    const x = Math.round(200 + Math.random() * 600);
    const y = Math.round(150 + Math.random() * 300);
    
    appState.nms.devices.push({
        id: newId,
        name: `New-Device-${appState.nms.devices.length + 1}`,
        type: "Router",
        brand: "Generic",
        model: "Device",
        ip: `192.168.1.${appState.nms.devices.length + 10}`,
        status: "Online",
        x: x,
        y: y,
        logical_x: x,
        logical_y: y,
        latitude: parseFloat((-6.2 - (Math.random() * 0.2)).toFixed(6)),
        longitude: parseFloat((106.8 + (Math.random() * 0.2)).toFixed(6)),
        outside_managed: false
    });
    
    appState.nms.hasChanges = true;
    markUnsavedChanges(true);
    
    renderNmsSpreadsheet();
    renderNmsGraph();
    validateNmsData();
    
    const wrapper = document.querySelector("#editor-devices-panel .spreadsheet-wrapper");
    if (wrapper) setTimeout(() => wrapper.scrollTop = wrapper.scrollHeight, 50);
}

function addConnectionRow() {
    const newId = `conn-${Date.now()}`;
    
    const defaultSrc = appState.nms.devices[0] ? appState.nms.devices[0].name : "";
    const defaultTgt = appState.nms.devices[1] ? appState.nms.devices[1].name : "";
    
    const srcDev = appState.nms.devices.find(d => d.name === defaultSrc);
    const tgtDev = appState.nms.devices.find(d => d.name === defaultTgt);
    const initialType = (srcDev && tgtDev && srcDev.type === "Router" && tgtDev.type === "Router") ? "Interlink" : "Uplink";
    
    appState.nms.connections.push({
        id: newId,
        source: defaultSrc,
        source_interface: "GE-1/0/1",
        source_lag: "",
        target: defaultTgt,
        target_interface: "GE-1/0/1",
        target_lag: "",
        bitrate: 10,
        link: `FO-Link-${appState.nms.connections.length + 1}`,
        type: initialType,
        status: "Active",
        dual_track: false,
        multipath_lag: false
    });
    
    appState.nms.hasChanges = true;
    markUnsavedChanges(true);
    
    renderNmsSpreadsheet();
    renderNmsGraph();
    validateNmsData();
    
    const wrapper = document.querySelector("#editor-connections-panel .spreadsheet-wrapper");
    if (wrapper) setTimeout(() => wrapper.scrollTop = wrapper.scrollHeight, 50);
}

function deleteDeviceRow(id) {
    const dev = appState.nms.devices.find(d => d.id === id);
    if (!dev) return;
    
    if (confirm(`Are you sure you want to delete "${dev.name}"? This removes its linked connections.`)) {
        appState.nms.connections = appState.nms.connections.filter(c => c.source !== dev.name && c.target !== dev.name);
        appState.nms.devices = appState.nms.devices.filter(d => d.id !== id);
        
        if (appState.nms.selectedNodeId === id) {
            document.getElementById("nms-detail-overlay").classList.add("hidden");
            appState.nms.selectedNodeId = null;
        }
        
        appState.nms.hasChanges = true;
        markUnsavedChanges(true);
        
        renderNmsSpreadsheet();
        renderNmsGraph();
        validateNmsData();
    }
}

function deleteConnectionRow(id) {
    if (confirm("Are you sure you want to delete this connection?")) {
        appState.nms.connections = appState.nms.connections.filter(c => c.id !== id);
        
        appState.nms.hasChanges = true;
        markUnsavedChanges(true);
        
        renderNmsSpreadsheet();
        renderNmsGraph();
        validateNmsData();
    }
}

function toggleDeviceVisibility(id, event) {
    if (event) event.stopPropagation();
    const dev = appState.nms.devices.find(d => d.id === id);
    if (dev) {
        dev.hidden = !dev.hidden;
        appState.nms.hasChanges = true;
        markUnsavedChanges(true);
        renderNmsSpreadsheet();
        renderNmsGraph();
        if (appState.nms.layoutMode === "geo") {
            renderNmsLeafletMap();
        }
    }
}

function toggleConnectionVisibility(id, event) {
    if (event) event.stopPropagation();
    const conn = appState.nms.connections.find(c => c.id === id);
    if (conn) {
        conn.hidden = !conn.hidden;
        appState.nms.hasChanges = true;
        markUnsavedChanges(true);
        renderNmsSpreadsheet();
        renderNmsGraph();
        if (appState.nms.layoutMode === "geo") {
            renderNmsLeafletMap();
        }
    }
}

function sidebarToggleConnectionVisibility(id) {
    const conn = appState.nms.connections.find(c => c.id === id);
    if (conn) {
        conn.hidden = !conn.hidden;
        appState.nms.hasChanges = true;
        markUnsavedChanges(true);
        renderNmsSpreadsheet();
        renderNmsGraph();
        if (appState.nms.layoutMode === "geo") {
            renderNmsLeafletMap();
        }
        
        // Refresh connection details sidebar list
        const allConnsInPair = appState.nms.connections.filter(c => 
            (c.source === conn.source && c.target === conn.target) ||
            (c.source === conn.target && c.target === conn.source)
        );
        showNmsConnectionDetailPanel(allConnsInPair, conn);
    }
}
window.sidebarToggleConnectionVisibility = sidebarToggleConnectionVisibility;

async function saveNmsTopology() {
    if (!validateNmsData()) return;
    
    showLoader(true);
    try {
        const payload = {
            devices: appState.nms.devices,
            connections: appState.nms.connections
        };
        
        const res = await fetch(`${API_BASE}/topology`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
        });
        
        if (!res.ok) {
            const errData = await res.json();
            throw new Error(errData.detail || "Failed to save topology config");
        }
        
        appState.nms.hasChanges = false;
        markUnsavedChanges(false);
        
        alert("Topology configuration saved successfully!");
        await initNmsView();
    } catch (err) {
        console.error("Save error:", err);
        alert(`Error saving topology: ${err.message}`);
    } finally {
        showLoader(false);
    }
}

function switchNmsEditorTab(tab) {
    appState.nms.activeTab = tab;
    
    const devBtn = document.getElementById("tab-devices-btn");
    const connBtn = document.getElementById("tab-connections-btn");
    const devPanel = document.getElementById("editor-devices-panel");
    const connPanel = document.getElementById("editor-connections-panel");
    
    const footerActionsDev = document.getElementById("footer-actions-devices");
    const footerActionsConn = document.getElementById("footer-actions-connections");
    
    if (tab === "devices") {
        devBtn.classList.add("active");
        connBtn.classList.remove("active");
        devPanel.classList.add("active");
        connPanel.classList.remove("active");
        if (footerActionsDev) footerActionsDev.classList.remove("hidden");
        if (footerActionsConn) footerActionsConn.classList.add("hidden");
    } else {
        connBtn.classList.add("active");
        devBtn.classList.remove("active");
        connPanel.classList.add("active");
        devPanel.classList.remove("active");
        if (footerActionsDev) footerActionsDev.classList.add("hidden");
        if (footerActionsConn) footerActionsConn.classList.remove("hidden");
        
        renderNmsSpreadsheet();
    }
}

function markUnsavedChanges(hasChanges) {
    const saveBtn = document.getElementById("nms-save-btn");
    if (!saveBtn) return;
    
    if (hasChanges) {
        saveBtn.innerHTML = `<i class="fa-solid fa-floppy-disk"></i> Save & Apply Changes *`;
        saveBtn.style.boxShadow = "0 0 15px rgba(59, 130, 246, 0.4)";
    } else {
        saveBtn.innerHTML = `<i class="fa-solid fa-floppy-disk"></i> Save & Apply Changes`;
        saveBtn.style.boxShadow = "none";
    }
}

function updateNmsCounters() {
    const summary = document.getElementById("nms-status-summary");
    let nokCount = 0;
    (appState.nms.connections || []).forEach(c => {
        if (!c.hidden && getConnectionOpticalInfo(c).isNok) nokCount++;
    });
    const nokBadge = document.getElementById("nms-optical-nok-badge");
    if (nokBadge) {
        nokBadge.innerText = String(nokCount);
    }
    if (summary) {
        summary.innerHTML = `${appState.nms.devices.length} Devices | ${appState.nms.connections.length} Links`;
    }
}

function inspectOpticalNokConnection(connId) {
    if (appState.nms.layoutMode === "summary") {
        switchNmsLayout("geo");
    }
    selectNmsConnection(connId);
}
window.inspectOpticalNokConnection = inspectOpticalNokConnection;

function escapeHTML(str) {
    if (!str) return "";
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

window.deleteDeviceRow = deleteDeviceRow;
window.deleteConnectionRow = deleteConnectionRow;

/* ==========================================================================
   Excel/Spreadsheet Batch Sync & Copy-Paste Helpers
   ========================================================================== */

function openBatchModal() {
    const modal = document.getElementById("nms-batch-modal");
    const pasteArea = document.getElementById("batch-paste-area");
    const previewContainer = document.getElementById("batch-preview-container");
    const errorMsg = document.getElementById("batch-error-msg");
    const applyBtn = document.getElementById("batch-apply-btn");
    
    if (!modal) return;
    
    // Load current devices as tab-separated values
    const headers = "Device Name\tType\tBrand & Model\tIP Address\tStatus\tLatitude\tLongitude\tOutside Party";
    const rows = appState.nms.devices.map(d => `${d.name}\t${d.type}\t${d.brand} ${d.model}\t${d.ip}\t${d.status}\t${d.latitude !== undefined ? d.latitude : -6.2}\t${d.longitude !== undefined ? d.longitude : 106.8}\t${d.outside_managed ? 'Yes' : 'No'}`).join('\n');
    pasteArea.value = headers + '\n' + rows;
    
    previewContainer.classList.add("hidden");
    errorMsg.classList.add("hidden");
    applyBtn.disabled = true;
    
    modal.classList.remove("hidden");
    
    // Parse immediately for initial display
    handleBatchPasteAreaInput();
}

function closeBatchModal() {
    const modal = document.getElementById("nms-batch-modal");
    if (modal) modal.classList.add("hidden");
}

function copyCurrentDevicesToClipboard() {
    const pasteArea = document.getElementById("batch-paste-area");
    if (!pasteArea) return;
    
    pasteArea.select();
    document.execCommand("copy");
    
    const copyBtn = document.getElementById("batch-copy-current-btn");
    const oldText = copyBtn.innerHTML;
    copyBtn.innerHTML = `<i class="fa-solid fa-check"></i> Copied!`;
    setTimeout(() => copyBtn.innerHTML = oldText, 1500);
}

let parsedDevicesBatch = [];

function handleBatchPasteAreaInput() {
    const text = document.getElementById("batch-paste-area").value;
    const previewContainer = document.getElementById("batch-preview-container");
    const previewBody = document.getElementById("batch-preview-body");
    const previewCount = document.getElementById("batch-preview-count");
    const errorMsg = document.getElementById("batch-error-msg");
    const applyBtn = document.getElementById("batch-apply-btn");
    
    parsedDevicesBatch = parseTSV(text);
    
    if (parsedDevicesBatch.length === 0) {
        previewContainer.classList.add("hidden");
        errorMsg.classList.remove("hidden");
        errorMsg.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> No valid device rows found to parse.`;
        applyBtn.disabled = true;
        return;
    }
    
    const errors = validateParsedItems(parsedDevicesBatch);
    
    if (errors.length > 0) {
        errorMsg.classList.remove("hidden");
        errorMsg.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> <strong>Import error:</strong> ${errors[0]}`;
        applyBtn.disabled = true;
    } else {
        errorMsg.classList.add("hidden");
        applyBtn.disabled = false;
    }
    
    // Render Preview
    previewCount.innerText = parsedDevicesBatch.length;
    previewBody.innerHTML = parsedDevicesBatch.map(item => `
        <tr>
            <td style="padding: 4px 10px;">${escapeHTML(item.name)}</td>
            <td style="padding: 4px 10px;">${escapeHTML(item.type)}</td>
            <td style="padding: 4px 10px;">${escapeHTML(item.brand + ' ' + item.model)}</td>
            <td style="padding: 4px 10px;">${escapeHTML(item.ip)}</td>
            <td style="padding: 4px 10px;">${escapeHTML(item.status)}</td>
            <td style="padding: 4px 10px;">${item.latitude !== undefined ? item.latitude : ''}</td>
            <td style="padding: 4px 10px;">${item.longitude !== undefined ? item.longitude : ''}</td>
        </tr>
    `).join('');
    
    previewContainer.classList.remove("hidden");
}

function parseTSV(text) {
    const lines = text.split('\n');
    const parsed = [];
    
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (line === '') continue; // Skip empty lines
        
        // Skip header line if it looks like column names
        if (i === 0 && (line.toLowerCase().includes('name') || line.toLowerCase().includes('ip') || line.toLowerCase().includes('status') || line.toLowerCase().includes('brand'))) {
            continue;
        }
        
        const cols = line.split('\t');
        if (cols.length < 2) continue; // Must have at least name and type or IP
        
        const name = (cols[0] || '').trim();
        const type = (cols[1] || 'Router').trim();
        const brandModel = (cols[2] || 'Generic Device').trim();
        const ip = (cols[3] || '').trim();
        const status = (cols[4] || 'Online').trim();
        const latitude = cols[5] !== undefined ? parseFloat(cols[5]) : undefined;
        const longitude = cols[6] !== undefined ? parseFloat(cols[6]) : undefined;
        const outside_managed = cols[7] !== undefined ? (cols[7].trim().toLowerCase() === 'true' || cols[7].trim() === '1' || cols[7].trim().toLowerCase() === 'yes' || cols[7].trim().toLowerCase() === 'checked') : false;
        
        // Parse brand & model
        const parts = brandModel.split(/\s+/);
        const brand = parts[0] || 'Generic';
        const model = parts.slice(1).join(' ') || 'Device';
        
        parsed.push({ name, type, brand, model, ip, status, latitude, longitude, outside_managed });
    }
    
    return parsed;
}

function validateParsedItems(items) {
    let errors = [];
    const names = new Set();
    const ips = new Set();
    
    const ipPattern = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    
    items.forEach((item, idx) => {
        if (!item.name || item.name === "") {
            errors.push(`Row ${idx+1}: Device Name is required.`);
        } else if (names.has(item.name)) {
            errors.push(`Row ${idx+1}: Duplicate name "${item.name}".`);
        } else {
            names.add(item.name);
        }
        
        if (!item.ip || item.ip === "") {
            errors.push(`Row ${idx+1}: IP Address is required.`);
        } else if (!ipPattern.test(item.ip)) {
            errors.push(`Row ${idx+1} ("${item.name || 'Row '+(idx+1)}"): Invalid IP address format "${item.ip}".`);
        } else if (ips.has(item.ip)) {
            errors.push(`Row ${idx+1}: Duplicate IP Address "${item.ip}".`);
        } else {
            ips.add(item.ip);
        }
        
        // Validate lat/lng
        if (item.latitude !== undefined && isNaN(item.latitude)) {
            errors.push(`Row ${idx+1}: Latitude must be a valid decimal number.`);
        }
        if (item.longitude !== undefined && isNaN(item.longitude)) {
            errors.push(`Row ${idx+1}: Longitude must be a valid decimal number.`);
        }

        // Normalize type
        if (!["Router", "OLT"].includes(item.type)) {
            item.type = item.type.toLowerCase().includes("olt") ? "OLT" : "Router";
        }
        
        // Normalize status
        if (!["Online", "Offline", "Maintenance"].includes(item.status)) {
            if (item.status.toLowerCase().includes("off")) item.status = "Offline";
            else if (item.status.toLowerCase().includes("maint")) item.status = "Maintenance";
            else item.status = "Online";
        }
    });
    
    return errors;
}

function applyBatchImport() {
    if (parsedDevicesBatch.length === 0) return;
    
    const mode = document.getElementById("batch-import-mode").value; // "append" or "replace"
    
    if (mode === "replace") {
        if (appState.nms.connections.length > 0) {
            const clearConns = confirm("Replacing all devices will clear connections that do not match the new device names. Proceed?");
            if (!clearConns) return;
        }
        
        const newDevs = parsedDevicesBatch.map((item, idx) => {
            const existing = appState.nms.devices.find(d => d.name === item.name);
            const defaultLat = -6.2 - (idx * 0.05);
            const defaultLng = 106.8 + (idx * 0.03);
            return {
                id: existing ? existing.id : `dev-${Date.now()}-${idx}`,
                name: item.name,
                type: item.type,
                brand: item.brand,
                model: item.model,
                ip: item.ip,
                status: item.status,
                x: existing ? existing.x : Math.round(200 + Math.random() * 600),
                y: existing ? existing.y : Math.round(150 + Math.random() * 300),
                logical_x: existing ? (existing.logical_x || existing.x) : Math.round(200 + Math.random() * 600),
                logical_y: existing ? (existing.logical_y || existing.y) : Math.round(150 + Math.random() * 300),
                latitude: item.latitude !== undefined && !isNaN(item.latitude) ? item.latitude : defaultLat,
                longitude: item.longitude !== undefined && !isNaN(item.longitude) ? item.longitude : defaultLng,
                outside_managed: item.outside_managed !== undefined ? item.outside_managed : (existing ? !!existing.outside_managed : false)
            };
        });
        
        appState.nms.devices = newDevs;
        
        const deviceNames = new Set(newDevs.map(d => d.name));
        appState.nms.connections = appState.nms.connections.filter(c => deviceNames.has(c.source) && deviceNames.has(c.target));
        
    } else {
        parsedDevicesBatch.forEach((item, idx) => {
            const existing = appState.nms.devices.find(d => d.name === item.name);
            const defaultLat = -6.2 - (idx * 0.05);
            const defaultLng = 106.8 + (idx * 0.03);
            if (existing) {
                existing.type = item.type;
                existing.brand = item.brand;
                existing.model = item.model;
                existing.ip = item.ip;
                existing.status = item.status;
                if (item.latitude !== undefined && !isNaN(item.latitude)) existing.latitude = item.latitude;
                if (item.longitude !== undefined && !isNaN(item.longitude)) existing.longitude = item.longitude;
                if (item.outside_managed !== undefined) existing.outside_managed = item.outside_managed;
            } else {
                const x = Math.round(200 + Math.random() * 600);
                const y = Math.round(150 + Math.random() * 300);
                appState.nms.devices.push({
                    id: `dev-${Date.now()}-${idx}`,
                    name: item.name,
                    type: item.type,
                    brand: item.brand,
                    model: item.model,
                    ip: item.ip,
                    status: item.status,
                    x: x,
                    y: y,
                    logical_x: x,
                    logical_y: y,
                    latitude: item.latitude !== undefined && !isNaN(item.latitude) ? item.latitude : defaultLat,
                    longitude: item.longitude !== undefined && !isNaN(item.longitude) ? item.longitude : defaultLng,
                    outside_managed: item.outside_managed !== undefined ? item.outside_managed : false
                });
            }
        });
    }
    
    appState.nms.hasChanges = true;
    markUnsavedChanges(true);
    
    renderNmsSpreadsheet();
    renderNmsGraph();
    validateNmsData();
    closeBatchModal();
    
    alert(`Successfully synced ${parsedDevicesBatch.length} devices! Click "Save & Apply Changes" to commit.`);
}

/* Connections Excel Batch Import/Export Methods */
let parsedConnsBatch = [];

function openConnBatchModal() {
    const modal = document.getElementById("nms-conn-batch-modal");
    const pasteArea = document.getElementById("batch-conn-paste-area");
    const previewContainer = document.getElementById("batch-conn-preview-container");
    const errorMsg = document.getElementById("batch-conn-error-msg");
    const applyBtn = document.getElementById("batch-conn-apply-btn");
    
    if (!modal) return;
    
    const headers = "Source Device\tSrc Port\tSrc LAG\tTarget Device\tTgt Port\tTgt LAG\tCapacity\tLink Name\tType\tStatus\tDual-Track Port\tMultipath LAG";
    const rows = appState.nms.connections.map(c => 
        `${c.source}\t${c.source_interface || ''}\t${c.source_lag || ''}\t${c.target}\t${c.target_interface || ''}\t${c.target_lag || ''}\t${c.bitrate}\t${c.link || ''}\t${c.type || 'Interlink'}\t${c.status || 'Active'}\t${c.dual_track ? 'true' : 'false'}\t${c.multipath_lag ? 'true' : 'false'}`
    ).join('\n');
    pasteArea.value = headers + '\n' + rows;
    
    previewContainer.classList.add("hidden");
    errorMsg.classList.add("hidden");
    applyBtn.disabled = true;
    
    modal.classList.remove("hidden");
    handleConnBatchPasteAreaInput();
}

function closeConnBatchModal() {
    const modal = document.getElementById("nms-conn-batch-modal");
    if (modal) modal.classList.add("hidden");
}

function copyCurrentConnectionsToClipboard() {
    const pasteArea = document.getElementById("batch-conn-paste-area");
    if (!pasteArea) return;
    
    pasteArea.select();
    document.execCommand("copy");
    
    const copyBtn = document.getElementById("batch-copy-current-conns-btn");
    const oldText = copyBtn.innerHTML;
    copyBtn.innerHTML = `<i class="fa-solid fa-check"></i> Copied!`;
    setTimeout(() => copyBtn.innerHTML = oldText, 1500);
}

function handleConnBatchPasteAreaInput() {
    const text = document.getElementById("batch-conn-paste-area").value;
    const previewContainer = document.getElementById("batch-conn-preview-container");
    const previewBody = document.getElementById("batch-conn-preview-body");
    const previewCount = document.getElementById("batch-conn-preview-count");
    const errorMsg = document.getElementById("batch-conn-error-msg");
    const applyBtn = document.getElementById("batch-conn-apply-btn");
    
    parsedConnsBatch = parseConnTSV(text);
    
    if (parsedConnsBatch.length === 0) {
        previewContainer.classList.add("hidden");
        errorMsg.classList.remove("hidden");
        errorMsg.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> No valid connection rows found to parse.`;
        applyBtn.disabled = true;
        return;
    }
    
    const errors = validateParsedConnections(parsedConnsBatch);
    
    if (errors.length > 0) {
        errorMsg.classList.remove("hidden");
        errorMsg.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> <strong>Import error:</strong> ${errors[0]}`;
        applyBtn.disabled = true;
    } else {
        errorMsg.classList.add("hidden");
        applyBtn.disabled = false;
    }
    
    previewCount.innerText = parsedConnsBatch.length;
    previewBody.innerHTML = parsedConnsBatch.map(item => `
        <tr>
            <td style="padding: 4px 10px;">${escapeHTML(item.source)}</td>
            <td style="padding: 4px 10px;">${escapeHTML(item.source_interface)}</td>
            <td style="padding: 4px 10px;">${escapeHTML(item.source_lag || '')}</td>
            <td style="padding: 4px 10px;">${escapeHTML(item.target)}</td>
            <td style="padding: 4px 10px;">${escapeHTML(item.target_interface)}</td>
            <td style="padding: 4px 10px;">${escapeHTML(item.target_lag || '')}</td>
            <td style="padding: 4px 10px;">${item.bitrate}G</td>
            <td style="padding: 4px 10px;">${escapeHTML(item.link)}</td>
            <td style="padding: 4px 10px;">${escapeHTML(item.type)}</td>
            <td style="padding: 4px 10px;">${escapeHTML(item.status)}</td>
            <td style="padding: 4px 10px;">${item.dual_track ? 'Yes' : 'No'}</td>
            <td style="padding: 4px 10px;">${item.multipath_lag ? 'Yes' : 'No'}</td>
        </tr>
    `).join('');
    
}

function parseConnTSV(text) {
    const lines = text.split('\n');
    const parsed = [];
    
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (line === '') continue;
        
        if (i === 0 && (line.toLowerCase().includes('source') || line.toLowerCase().includes('port') || line.toLowerCase().includes('target') || line.toLowerCase().includes('capacity'))) {
            continue;
        }
        
        const cols = line.split('\t');
        if (cols.length < 3) continue;
        
        const source = (cols[0] || '').trim();
        const source_interface = (cols[1] || '').trim();
        const source_lag = (cols[2] || '').trim();
        const target = (cols[3] || '').trim();
        const target_interface = (cols[4] || '').trim();
        const target_lag = (cols[5] || '').trim();
        const bitrate = parseInt(cols[6]) || 10;
        const link = (cols[7] || `FO-Link-${parsed.length + 1}`).trim();
        const type = (cols[8] || 'Interlink').trim();
        const status = (cols[9] || 'Active').trim();
        const dual_track = (cols[10] || '').trim().toLowerCase() === 'true';
        const multipath_lag = (cols[11] || '').trim().toLowerCase() === 'true';
        
        parsed.push({ source, source_interface, source_lag, target, target_interface, target_lag, bitrate, link, type, status, dual_track, multipath_lag });
    }
    return parsed;
}

function validateParsedConnections(items) {
    let errors = [];
    const devices = new Set(appState.nms.devices.map(d => d.name));
    
    items.forEach((item, idx) => {
        if (!item.source || item.source === "") {
            errors.push(`Row ${idx+1}: Source Device is required.`);
        } else if (!devices.has(item.source)) {
            errors.push(`Row ${idx+1}: Source device "${item.source}" does not exist in Devices list.`);
        }
        
        if (!item.target || item.target === "") {
            errors.push(`Row ${idx+1}: Target Device is required.`);
        } else if (!devices.has(item.target)) {
            errors.push(`Row ${idx+1}: Target device "${item.target}" does not exist in Devices list.`);
        }
        
        if (item.source && item.target && item.source === item.target) {
            errors.push(`Row ${idx+1}: Loopback link not allowed (Source and Target must be different).`);
        }
        
        if (isNaN(item.bitrate) || item.bitrate <= 0) {
            errors.push(`Row ${idx+1}: Capacity must be a positive integer.`);
        }
        
        if (!["Uplink", "Interlink"].includes(item.type)) {
            item.type = item.type.toLowerCase().includes("up") ? "Uplink" : "Interlink";
        }
        
        if (!["Active", "Backup"].includes(item.status)) {
            item.status = item.status.toLowerCase().includes("back") ? "Backup" : "Active";
        }
    });
    
    return errors;
}

function applyConnBatchImport() {
    if (parsedConnsBatch.length === 0) return;
    
    const mode = document.getElementById("batch-conn-import-mode").value;
    
    if (mode === "replace") {
        const newConns = parsedConnsBatch.map((item, idx) => {
            return {
                id: `conn-${Date.now()}-${idx}`,
                source: item.source,
                source_interface: item.source_interface,
                source_lag: item.source_lag || "",
                target: item.target,
                target_interface: item.target_interface,
                target_lag: item.target_lag || "",
                bitrate: item.bitrate,
                link: item.link,
                type: item.type,
                status: item.status,
                dual_track: item.dual_track,
                multipath_lag: item.multipath_lag !== undefined ? item.multipath_lag : false
            };
        });
        appState.nms.connections = newConns;
    } else {
        parsedConnsBatch.forEach((item, idx) => {
            appState.nms.connections.push({
                id: `conn-${Date.now()}-${idx}`,
                source: item.source,
                source_interface: item.source_interface,
                source_lag: item.source_lag || "",
                target: item.target,
                target_interface: item.target_interface,
                target_lag: item.target_lag || "",
                bitrate: item.bitrate,
                link: item.link,
                type: item.type,
                status: item.status,
                dual_track: item.dual_track,
                multipath_lag: item.multipath_lag !== undefined ? item.multipath_lag : false
            });
        });
    }
    
    appState.nms.hasChanges = true;
    markUnsavedChanges(true);
    
    renderNmsSpreadsheet();
    if (appState.nms.layoutMode === "geo") {
        renderNmsLeafletMap();
    } else {
        renderNmsGraph();
    }
    validateNmsData();
    closeConnBatchModal();
    
    alert(`Successfully synced ${parsedConnsBatch.length} connections! Click "Save & Apply Changes" to commit.`);
}

function handleCellPaste(e, devId, field) {
    const text = (e.clipboardData || window.clipboardData).getData('text');
    if (!text) return;
    
    if (text.includes('\t') || text.includes('\n')) {
        e.preventDefault();
        
        const rows = text.split(/\r?\n/).map(r => r.split('\t'));
        if (rows.length > 0 && rows[rows.length - 1].length === 1 && rows[rows.length - 1][0] === '') {
            rows.pop();
        }
        
        if (rows.length === 0) return;
        
        const startIdx = appState.nms.devices.findIndex(d => d.id === devId);
        if (startIdx === -1) return;
        
        const fieldCols = ["name", "type", "brandModel", "ip", "status", "latitude", "longitude", "outside_managed"];
        const startColIdx = fieldCols.indexOf(field);
        if (startColIdx === -1) return;
        
        rows.forEach((row, rOffset) => {
            const currentIdx = startIdx + rOffset;
            let dev = appState.nms.devices[currentIdx];
            
            if (!dev) {
                const newId = `dev-${Date.now()}-${rOffset}`;
                const x = Math.round(200 + Math.random() * 600);
                const y = Math.round(150 + Math.random() * 300);
                dev = {
                    id: newId,
                    name: `New-Device-${currentIdx + 1}`,
                    type: "Router",
                    brand: "Generic",
                    model: "Device",
                    ip: `192.168.1.${currentIdx + 10}`,
                    status: "Online",
                    x: x,
                    y: y,
                    logical_x: x,
                    logical_y: y,
                    latitude: -6.2 - (currentIdx * 0.05),
                    longitude: 106.8 + (currentIdx * 0.03),
                    outside_managed: false
                };
                appState.nms.devices.push(dev);
            }
            
            row.forEach((cellVal, cOffset) => {
                const targetColIdx = startColIdx + cOffset;
                const targetField = fieldCols[targetColIdx];
                if (!targetField) return;
                
                const cleanedVal = cellVal.trim();
                if (targetField === "name") {
                    const oldName = dev.name;
                    dev.name = cleanedVal;
                    appState.nms.connections.forEach(c => {
                        if (c.source === oldName) c.source = cleanedVal;
                        if (c.target === oldName) c.target = cleanedVal;
                    });
                } else if (targetField === "type") {
                    dev.type = cleanedVal.toLowerCase().includes("olt") ? "OLT" : "Router";
                } else if (targetField === "brandModel") {
                    const parts = cleanedVal.split(/\s+/);
                    dev.brand = parts[0] || "Generic";
                    dev.model = parts.slice(1).join(" ") || "Device";
                } else if (targetField === "ip") {
                    dev.ip = cleanedVal;
                } else if (targetField === "status") {
                    if (cleanedVal.toLowerCase().includes("off")) dev.status = "Offline";
                    else if (cleanedVal.toLowerCase().includes("maint")) dev.status = "Maintenance";
                    else dev.status = "Online";
                } else if (targetField === "latitude") {
                    dev.latitude = parseFloat(cleanedVal) || -6.2;
                } else if (targetField === "longitude") {
                    dev.longitude = parseFloat(cleanedVal) || 106.8;
                } else if (targetField === "outside_managed") {
                    dev.outside_managed = cleanedVal.toLowerCase() === "true" || cleanedVal === "1" || cleanedVal.toLowerCase() === "checked" || cleanedVal.toLowerCase() === "yes";
                }
            });
        });
        
        appState.nms.hasChanges = true;
        markUnsavedChanges(true);
        
        renderNmsSpreadsheet();
        renderNmsGraph();
        validateNmsData();
    }
}

function updateNmsSummaryDashboard() {
    const devices = appState.nms.devices;
    const conns = appState.nms.connections;
    
    // Total counts
    const totalDevs = devices.length;
    const totalLinks = conns.length;
    
    const totalDevsEl = document.getElementById("dash-total-devices");
    const totalLinksEl = document.getElementById("dash-total-links");
    if (totalDevsEl) totalDevsEl.innerText = totalDevs;
    if (totalLinksEl) totalLinksEl.innerText = totalLinks;
    
    // Routers vs OLTs
    const routers = devices.filter(d => d.type === "Router" && !d.outside_managed).length;
    const olts = devices.filter(d => d.type === "OLT" && !d.outside_managed).length;
    
    const routerCountEl = document.getElementById("dash-router-count");
    const oltCountEl = document.getElementById("dash-olt-count");
    if (routerCountEl) routerCountEl.innerText = routers;
    if (oltCountEl) oltCountEl.innerText = olts;
    
    const routerPct = totalDevs > 0 ? (routers / totalDevs) * 100 : 0;
    const oltPct = totalDevs > 0 ? (olts / totalDevs) * 100 : 0;
    
    const routerProgEl = document.getElementById("dash-router-progress");
    const oltProgEl = document.getElementById("dash-olt-progress");
    if (routerProgEl) routerProgEl.style.width = `${routerPct}%`;
    if (oltProgEl) oltProgEl.style.width = `${oltPct}%`;
    
    // Interlink vs Uplink
    const interlinks = conns.filter(c => c.type === "Interlink").length;
    const uplinks = conns.filter(c => c.type === "Uplink").length;
    
    const interlinkCountEl = document.getElementById("dash-interlink-count");
    const uplinkCountEl = document.getElementById("dash-uplink-count");
    if (interlinkCountEl) interlinkCountEl.innerText = interlinks;
    if (uplinkCountEl) uplinkCountEl.innerText = uplinks;
    
    const interlinkPct = totalLinks > 0 ? (interlinks / totalLinks) * 100 : 0;
    const uplinkPct = totalLinks > 0 ? (uplinks / totalLinks) * 100 : 0;
    
    const interlinkProgEl = document.getElementById("dash-interlink-progress");
    const uplinkProgEl = document.getElementById("dash-uplink-progress");
    if (interlinkProgEl) interlinkProgEl.style.width = `${interlinkPct}%`;
    if (uplinkProgEl) uplinkProgEl.style.width = `${uplinkPct}%`;
    
    // Health Index & Device Status counts
    const onlineDevs = devices.filter(d => d.status && d.status.toLowerCase() === "online").length;
    const maintDevs = devices.filter(d => d.status && d.status.toLowerCase() === "maintenance").length;
    const offlineDevs = devices.filter(d => d.status && d.status.toLowerCase() === "offline").length;
    
    const onlineStatusEl = document.getElementById("dash-online-status");
    const maintStatusEl = document.getElementById("dash-maint-status");
    const offlineStatusEl = document.getElementById("dash-offline-status");
    if (onlineStatusEl) onlineStatusEl.innerText = `${onlineDevs} / ${totalDevs}`;
    if (maintStatusEl) maintStatusEl.innerText = maintDevs;
    if (offlineStatusEl) offlineStatusEl.innerText = offlineDevs;
    
    const healthDenom = onlineDevs + maintDevs;
    const healthIdx = healthDenom > 0 ? Math.round(((onlineDevs + maintDevs * 0.5) / healthDenom) * 100) : 100;
    const healthEl = document.getElementById("dash-health-index");
    if (healthEl) {
        healthEl.innerText = `${healthIdx}%`;
        if (healthIdx >= 90) {
            healthEl.style.color = "var(--success)";
        } else if (healthIdx >= 70) {
            healthEl.style.color = "var(--warning)";
        } else {
            healthEl.style.color = "var(--danger)";
        }
    }
    
    // Brand Distribution calculation
    const brandMap = {};
    devices.forEach(d => {
        const brandName = d.outside_managed ? "Unmanaged Devices" : (d.brand || "Generic");
        brandMap[brandName] = (brandMap[brandName] || 0) + 1;
    });
    
    const sortedBrands = Object.entries(brandMap).sort((a, b) => b[1] - a[1]);
    const brandListContainer = document.getElementById("dash-brand-list");
    if (brandListContainer) {
        brandListContainer.innerHTML = sortedBrands.map(([brand, count]) => {
            const pct = totalDevs > 0 ? (count / totalDevs) * 100 : 0;
            return `
                <div>
                    <div style="display: flex; justify-content: space-between; font-size: 0.76rem; margin-bottom: 4px;">
                        <span style="font-weight: 500; color: var(--text-main);">${brand}</span>
                        <span style="color: var(--text-muted);">${count} (${Math.round(pct)}%)</span>
                    </div>
                    <div style="height: 5px; background: rgba(255,255,255,0.05); border-radius: 3px; overflow: hidden;">
                        <div style="height: 100%; width: ${pct}%; background: var(--primary); opacity: 0.85;"></div>
                    </div>
                </div>
            `;
        }).join("") || `<p style="font-size: 0.72rem; color: var(--text-muted); margin: 10px 0 0 0;">No equipment brand records found.</p>`;
    }
    
    // Connection capacity allocation (divided for Interlinks and Uplinks)
    let totalInterlinkBandwidth = 0;
    let totalUplinkBandwidth = 0;
    const interlinkCapacityMap = {};
    const uplinkCapacityMap = {};
    
    conns.forEach(c => {
        const capacity = parseInt(c.bitrate) || 10;
        const capacityKey = `${capacity} Gbps`;
        if (c.type === "Interlink") {
            totalInterlinkBandwidth += capacity;
            interlinkCapacityMap[capacityKey] = (interlinkCapacityMap[capacityKey] || 0) + 1;
        } else {
            totalUplinkBandwidth += capacity;
            uplinkCapacityMap[capacityKey] = (uplinkCapacityMap[capacityKey] || 0) + 1;
        }
    });
    
    const interlinkBandwidthEl = document.getElementById("dash-interlink-bandwidth");
    const uplinkBandwidthEl = document.getElementById("dash-uplink-bandwidth");
    if (interlinkBandwidthEl) interlinkBandwidthEl.innerText = `${totalInterlinkBandwidth} Gbps`;
    if (uplinkBandwidthEl) uplinkBandwidthEl.innerText = `${totalUplinkBandwidth} Gbps`;
    
    const sortedInterlinkCapacities = Object.entries(interlinkCapacityMap).sort((a, b) => parseInt(b[0]) - parseInt(a[0]));
    const sortedUplinkCapacities = Object.entries(uplinkCapacityMap).sort((a, b) => parseInt(b[0]) - parseInt(a[0]));
    
    const interlinksCount = conns.filter(c => c.type === "Interlink").length;
    const uplinksCount = conns.filter(c => c.type === "Uplink").length;
    
    const interlinkCapacityListEl = document.getElementById("dash-interlink-capacity-list");
    if (interlinkCapacityListEl) {
        interlinkCapacityListEl.innerHTML = sortedInterlinkCapacities.map(([capacity, count]) => {
            const pct = interlinksCount > 0 ? (count / interlinksCount) * 100 : 0;
            return `
                <div>
                    <div style="display: flex; justify-content: space-between; font-size: 0.74rem; margin-bottom: 4px;">
                        <span style="font-weight: 500; color: var(--text-main);">${capacity}</span>
                        <span style="color: var(--text-muted);">${count} links (${Math.round(pct)}%)</span>
                    </div>
                    <div style="height: 5px; background: rgba(255,255,255,0.05); border-radius: 3px; overflow: hidden;">
                        <div style="height: 100%; width: ${pct}%; background: var(--primary); opacity: 0.85;"></div>
                    </div>
                </div>
            `;
        }).join("") || `<p style="font-size: 0.72rem; color: var(--text-muted); margin: 5px 0 0 0;">No interlinks mapped.</p>`;
    }
    
    const uplinkCapacityListEl = document.getElementById("dash-uplink-capacity-list");
    if (uplinkCapacityListEl) {
        uplinkCapacityListEl.innerHTML = sortedUplinkCapacities.map(([capacity, count]) => {
            const pct = uplinksCount > 0 ? (count / uplinksCount) * 100 : 0;
            return `
                <div>
                    <div style="display: flex; justify-content: space-between; font-size: 0.74rem; margin-bottom: 4px;">
                        <span style="font-weight: 500; color: var(--text-main);">${capacity}</span>
                        <span style="color: var(--text-muted);">${count} links (${Math.round(pct)}%)</span>
                    </div>
                    <div style="height: 5px; background: rgba(255,255,255,0.05); border-radius: 3px; overflow: hidden;">
                        <div style="height: 100%; width: ${pct}%; background: hsl(280, 80%, 65%); opacity: 0.85;"></div>
                    </div>
                </div>
            `;
        }).join("") || `<p style="font-size: 0.72rem; color: var(--text-muted); margin: 5px 0 0 0;">No uplinks mapped.</p>`;
    }
    
    // 1. Router Specific Data
    const routerDevs = devices.filter(d => d.type === "Router" && !d.outside_managed);
    const routerTotal = routerDevs.length;
    const routerCore = routerDevs.filter(r => r.name.toLowerCase().includes("core") || (r.ip && r.ip.startsWith("10.0."))).length;
    const routerAgg = routerTotal - routerCore;
    const routerOnline = routerDevs.filter(r => r.status && r.status.toLowerCase() === "online").length;
    const routerMaint = routerDevs.filter(r => r.status && r.status.toLowerCase() === "maintenance").length;
    const routerOffline = routerDevs.filter(r => r.status && r.status.toLowerCase() === "offline").length;

    const routerTotalEl = document.getElementById("dash-router-total");
    const routerCoreEl = document.getElementById("dash-router-core");
    const routerAggEl = document.getElementById("dash-router-agg");
    const routerOnlineEl = document.getElementById("dash-router-online");
    const routerMaintEl = document.getElementById("dash-router-maint");
    const routerOfflineEl = document.getElementById("dash-router-offline");

    if (routerTotalEl) routerTotalEl.innerText = routerTotal;
    if (routerCoreEl) routerCoreEl.innerText = routerCore;
    if (routerAggEl) routerAggEl.innerText = routerAgg;
    if (routerOnlineEl) routerOnlineEl.innerText = routerOnline;
    if (routerMaintEl) routerMaintEl.innerText = routerMaint;
    if (routerOfflineEl) routerOfflineEl.innerText = routerOffline;

    // Router SPOF and resiliency analysis calculations
    let spofRouters = routerDevs.filter(r => {
        const connectedLinks = conns.filter(c => c.source === r.name || c.target === r.name);
        return connectedLinks.length === 1 && !connectedLinks[0].dual_track;
    });

    const rawSpofRouters = [...spofRouters];

    // Update Router Resiliency Analysis graph
    const routerSpofCount = rawSpofRouters.length;
    const routerResilientCount = Math.max(0, routerTotal - routerSpofCount);
    const routerResilientPct = routerTotal > 0 ? (routerResilientCount / routerTotal) * 100 : 0;
    const routerSpofPct = routerTotal > 0 ? (routerSpofCount / routerTotal) * 100 : 0;

    const routerResBarEl = document.getElementById("dash-router-resilient-bar");
    const routerSpofBarEl = document.getElementById("dash-router-spof-bar");
    const routerResCountEl = document.getElementById("dash-router-resilient-count");
    const routerSpofCountEl = document.getElementById("dash-router-spof-count");

    if (routerResBarEl) routerResBarEl.style.width = `${routerResilientPct}%`;
    if (routerSpofBarEl) routerSpofBarEl.style.width = `${routerSpofPct}%`;
    if (routerResCountEl) routerResCountEl.innerText = `${routerResilientCount} (${Math.round(routerResilientPct)}%)`;
    if (routerSpofCountEl) routerSpofCountEl.innerText = `${routerSpofCount} (${Math.round(routerSpofPct)}%)`;

    // Handle Router name input query filtering
    const routerNameFilterInput = document.getElementById("dash-router-spof-name-filter");
    if (routerNameFilterInput) {
        if (!routerNameFilterInput.dataset.listenerBound) {
            routerNameFilterInput.addEventListener("input", () => {
                updateNmsSummaryDashboard();
            });
            routerNameFilterInput.dataset.listenerBound = "true";
        }
        const nameQuery = routerNameFilterInput.value.toLowerCase().trim();
        if (nameQuery) {
            spofRouters = spofRouters.filter(r => r.name.toLowerCase().includes(nameQuery));
        }
    }

    // Handle Router dynamic brand filter loading and selection mapping
    const routerBrandFilterSelect = document.getElementById("dash-router-spof-brand-filter");
    if (routerBrandFilterSelect) {
        const currentSelectedBrand = routerBrandFilterSelect.value || "all";
        
        // Extract unique brands from raw unfiltered SPOF Routers
        const spofBrands = [...new Set(rawSpofRouters.map(r => r.brand || "Generic"))].sort();
        
        let filterHtml = `<option value="all" ${currentSelectedBrand === "all" ? "selected" : ""}>All Brands</option>`;
        spofBrands.forEach(b => {
            filterHtml += `<option value="${b}" ${currentSelectedBrand === b ? "selected" : ""}>${b}</option>`;
        });
        routerBrandFilterSelect.innerHTML = filterHtml;
        
        if (!routerBrandFilterSelect.dataset.listenerBound) {
            routerBrandFilterSelect.addEventListener("change", () => {
                updateNmsSummaryDashboard();
            });
            routerBrandFilterSelect.dataset.listenerBound = "true";
        }
        
        const selectedBrand = routerBrandFilterSelect.value;
        if (selectedBrand && selectedBrand !== "all") {
            spofRouters = spofRouters.filter(r => (r.brand || "Generic") === selectedBrand);
        }
    }

    const routerSpofListContainer = document.getElementById("dash-router-spof-list");
    if (routerSpofListContainer) {
        if (spofRouters.length > 0) {
            routerSpofListContainer.innerHTML = spofRouters.map(router => {
                let statusColor = "var(--success)";
                if (router.status && router.status.toLowerCase() === "offline") statusColor = "var(--danger)";
                else if (router.status && router.status.toLowerCase() === "maintenance") statusColor = "var(--warning)";
                
                return `
                    <div style="display: flex; align-items: center; justify-content: space-between; background: rgba(239, 68, 68, 0.04); border: 1px solid rgba(239, 68, 68, 0.12); border-radius: 6px; padding: 10px 14px; font-size: 0.8rem; cursor: pointer; transition: background 0.2s, border-color 0.2s;" 
                         onclick="selectNmsNode('${router.id}')"
                         onmouseover="this.style.background='rgba(239, 68, 68, 0.08)'; this.style.borderColor='rgba(239, 68, 68, 0.25)';"
                         onmouseout="this.style.background='rgba(239, 68, 68, 0.04)'; this.style.borderColor='rgba(239, 68, 68, 0.12)';">
                        <span style="font-weight: 600; color: var(--text-main); display: flex; align-items: center; gap: 8px;">
                            <i class="fa-solid fa-triangle-exclamation" style="color: var(--danger); font-size: 0.85rem;"></i>
                            ${router.name} <span style="font-size: 0.7rem; color: var(--text-muted); font-weight: normal; margin-left: 5px;">(${router.brand || "Generic"})</span>
                        </span>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span style="display: inline-block; width: 7px; height: 7px; border-radius: 50%; background: ${statusColor};"></span>
                            <span style="color: var(--text-muted); font-size: 0.74rem; font-weight: 500;">${router.status || "Unknown"}</span>
                            <i class="fa-solid fa-chevron-right" style="color: var(--text-muted); font-size: 0.65rem; margin-left: 4px;"></i>
                        </div>
                    </div>
                `;
            }).join("");
        } else {
            routerSpofListContainer.innerHTML = `
                <div style="display: flex; align-items: center; gap: 6px; background: rgba(16, 185, 129, 0.05); border: 1px solid rgba(16, 185, 129, 0.15); border-radius: 4px; padding: 10px 14px; font-size: 0.78rem; color: var(--success); font-weight: 500; width: 100%; box-sizing: border-box;">
                    <i class="fa-solid fa-circle-check" style="font-size: 0.85rem;"></i>
                    <span>No SPOF vulnerabilities detected for selected criteria.</span>
                </div>
            `;
        }
    }

    // 2. OLT Specific Data
    const oltDevs = devices.filter(d => d.type === "OLT" && !d.outside_managed);
    const oltTotal = oltDevs.length;
    const oltOnline = oltDevs.filter(o => o.status && o.status.toLowerCase() === "online").length;
    const oltMaint = oltDevs.filter(o => o.status && o.status.toLowerCase() === "maintenance").length;
    const oltOffline = oltDevs.filter(o => o.status && o.status.toLowerCase() === "offline").length;

    // Uplinks connected to OLTs
    const oltUplinks = conns.filter(c => {
        const hasOlt = oltDevs.some(o => o.name === c.source || o.name === c.target);
        return hasOlt;
    });
    const oltUplinksCount = oltUplinks.length;
    let oltAggregatedCapacity = 0;
    oltUplinks.forEach(c => {
        oltAggregatedCapacity += parseInt(c.bitrate) || 10;
    });

    const oltTotalEl = document.getElementById("dash-olt-total");
    const oltUplinksEl = document.getElementById("dash-olt-uplinks");
    const oltOnlineEl = document.getElementById("dash-olt-online");
    const oltMaintEl = document.getElementById("dash-olt-maint");
    const oltOfflineEl = document.getElementById("dash-olt-offline");
    const oltCapacityEl = document.getElementById("dash-olt-capacity");

    if (oltTotalEl) oltTotalEl.innerText = oltTotal;
    if (oltUplinksEl) oltUplinksEl.innerText = oltUplinksCount;
    if (oltOnlineEl) oltOnlineEl.innerText = oltOnline;
    if (oltMaintEl) oltMaintEl.innerText = oltMaint;
    if (oltOfflineEl) oltOfflineEl.innerText = oltOffline;
    if (oltCapacityEl) oltCapacityEl.innerText = `${oltAggregatedCapacity} Gbps`;

    // List OLTs with SPOF connection (only 1 non-dual-track link)
    // Find OLTs co-located with a router (sharing same lat/long)
    const coLocatedOltNames = new Set();
    oltDevs.forEach(olt => {
        const isCoLocated = devices.some(d => 
            d.type === "Router" && 
            d.latitude === olt.latitude && 
            d.longitude === olt.longitude
        );
        if (isCoLocated) {
            coLocatedOltNames.add(olt.name);
        }
    });

    let spofOlts = oltDevs.filter(olt => {
        // Exclude co-located OLTs
        if (coLocatedOltNames.has(olt.name)) return false;
        
        const connectedLinks = conns.filter(c => c.source === olt.name || c.target === olt.name);
        return connectedLinks.length === 1 && !connectedLinks[0].dual_track;
    });

    const rawSpofOlts = [...spofOlts];

    // Update OLT Resiliency Analysis graph
    const spofCount = rawSpofOlts.length;
    const resilientCount = Math.max(0, oltTotal - spofCount);
    const resilientPct = oltTotal > 0 ? (resilientCount / oltTotal) * 100 : 0;
    const spofPct = oltTotal > 0 ? (spofCount / oltTotal) * 100 : 0;

    const resBarEl = document.getElementById("dash-olt-resilient-bar");
    const spofBarEl = document.getElementById("dash-olt-spof-bar");
    const resCountEl = document.getElementById("dash-olt-resilient-count");
    const spofCountEl = document.getElementById("dash-olt-spof-count");

    if (resBarEl) resBarEl.style.width = `${resilientPct}%`;
    if (spofBarEl) spofBarEl.style.width = `${spofPct}%`;
    if (resCountEl) resCountEl.innerText = `${resilientCount} (${Math.round(resilientPct)}%)`;
    if (spofCountEl) spofCountEl.innerText = `${spofCount} (${Math.round(spofPct)}%)`;

    // Handle name input query filtering
    const nameFilterInput = document.getElementById("dash-olt-spof-name-filter");
    if (nameFilterInput) {
        if (!nameFilterInput.dataset.listenerBound) {
            nameFilterInput.addEventListener("input", () => {
                updateNmsSummaryDashboard();
            });
            nameFilterInput.dataset.listenerBound = "true";
        }
        const nameQuery = nameFilterInput.value.toLowerCase().trim();
        if (nameQuery) {
            spofOlts = spofOlts.filter(o => o.name.toLowerCase().includes(nameQuery));
        }
    }

    // Handle dynamic brand filter loading and selection mapping
    const brandFilterSelect = document.getElementById("dash-olt-spof-brand-filter");
    if (brandFilterSelect) {
        const currentSelectedBrand = brandFilterSelect.value || "all";
        
        // Extract unique brands from raw unfiltered SPOF OLTs
        const spofBrands = [...new Set(rawSpofOlts.map(o => o.brand || "Generic"))].sort();
        
        let filterHtml = `<option value="all" ${currentSelectedBrand === "all" ? "selected" : ""}>All Brands</option>`;
        spofBrands.forEach(b => {
            filterHtml += `<option value="${b}" ${currentSelectedBrand === b ? "selected" : ""}>${b}</option>`;
        });
        brandFilterSelect.innerHTML = filterHtml;
        
        if (!brandFilterSelect.dataset.listenerBound) {
            brandFilterSelect.addEventListener("change", () => {
                updateNmsSummaryDashboard();
            });
            brandFilterSelect.dataset.listenerBound = "true";
        }
        
        const selectedBrand = brandFilterSelect.value;
        if (selectedBrand && selectedBrand !== "all") {
            spofOlts = spofOlts.filter(o => (o.brand || "Generic") === selectedBrand);
        }
    }

    const oltSpofListContainer = document.getElementById("dash-olt-spof-list");
    if (oltSpofListContainer) {
        if (spofOlts.length > 0) {
            oltSpofListContainer.innerHTML = spofOlts.map(olt => {
                let statusColor = "var(--success)";
                if (olt.status && olt.status.toLowerCase() === "offline") statusColor = "var(--danger)";
                else if (olt.status && olt.status.toLowerCase() === "maintenance") statusColor = "var(--warning)";
                
                return `
                    <div style="display: flex; align-items: center; justify-content: space-between; background: rgba(239, 68, 68, 0.04); border: 1px solid rgba(239, 68, 68, 0.12); border-radius: 6px; padding: 10px 14px; font-size: 0.8rem; cursor: pointer; transition: background 0.2s, border-color 0.2s;" 
                         onclick="selectNmsNode('${olt.id}')"
                         onmouseover="this.style.background='rgba(239, 68, 68, 0.08)'; this.style.borderColor='rgba(239, 68, 68, 0.25)';"
                         onmouseout="this.style.background='rgba(239, 68, 68, 0.04)'; this.style.borderColor='rgba(239, 68, 68, 0.12)';">
                        <span style="font-weight: 600; color: var(--text-main); display: flex; align-items: center; gap: 8px;">
                            <i class="fa-solid fa-triangle-exclamation" style="color: var(--danger); font-size: 0.85rem;"></i>
                            ${olt.name} <span style="font-size: 0.7rem; color: var(--text-muted); font-weight: normal; margin-left: 5px;">(${olt.brand || "Generic"})</span>
                        </span>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span style="display: inline-block; width: 7px; height: 7px; border-radius: 50%; background: ${statusColor};"></span>
                            <span style="color: var(--text-muted); font-size: 0.74rem; font-weight: 500;">${olt.status || "Unknown"}</span>
                            <i class="fa-solid fa-chevron-right" style="color: var(--text-muted); font-size: 0.65rem; margin-left: 4px;"></i>
                        </div>
                    </div>
                `;
            }).join("");
        } else {
            oltSpofListContainer.innerHTML = `
                <div style="display: flex; align-items: center; gap: 6px; background: rgba(16, 185, 129, 0.05); border: 1px solid rgba(16, 185, 129, 0.15); border-radius: 4px; padding: 10px 14px; font-size: 0.78rem; color: var(--success); font-weight: 500; width: 100%; box-sizing: border-box;">
                    <i class="fa-solid fa-circle-check" style="font-size: 0.85rem;"></i>
                    <span>No SPOF vulnerabilities detected for selected criteria.</span>
                </div>
            `;
        }
    }

    // 3. Optical Power Telemetry & NOK Connections Summary
    const optScan = appState.nms.opticalScan || { updated_at: null, results: [] };
    const optResults = Array.isArray(optScan.results) ? optScan.results : [];
    let optNormalCount = 0;
    let optWarnCount = 0;
    let optAlarmCount = 0;

    optResults.forEach(r => {
        const h = evaluatePortOpticalHealth(r);
        if (h.severity === "normal") optNormalCount++;
        else if (h.severity === "warning") optWarnCount++;
        else if (h.severity === "alarm") optAlarmCount++;
    });

    const optTsEl = document.getElementById("dash-optical-timestamp");
    const optTotalEl = document.getElementById("dash-opt-total");
    const optNormalEl = document.getElementById("dash-opt-normal");
    const optWarnEl = document.getElementById("dash-opt-warning");
    const optAlarmEl = document.getElementById("dash-opt-alarm");
    const optNokListEl = document.getElementById("dash-opt-nok-list");

    if (optTsEl) optTsEl.innerText = optScan.updated_at ? `Last Scan: ${optScan.updated_at}` : "Last Scan: Not available";
    if (optTotalEl) optTotalEl.innerText = optResults.length;
    if (optNormalEl) optNormalEl.innerText = optNormalCount;
    if (optWarnEl) optWarnEl.innerText = optWarnCount;
    if (optAlarmEl) optAlarmEl.innerText = optAlarmCount;

    if (optNokListEl) {
        const nokConnections = [];
        conns.forEach(c => {
            const info = getConnectionOpticalInfo(c);
            if (info.isNok) {
                nokConnections.push({ conn: c, info });
            }
        });

        nokConnections.sort((a, b) => {
            if (a.info.worstSeverity === "alarm" && b.info.worstSeverity !== "alarm") return -1;
            if (a.info.worstSeverity !== "alarm" && b.info.worstSeverity === "alarm") return 1;
            return 0;
        });

        if (nokConnections.length > 0) {
            optNokListEl.innerHTML = nokConnections.map(({ conn, info }) => {
                const isAlarm = info.worstSeverity === "alarm";
                const col = isAlarm ? "#ef4444" : "#f97316";
                const bg = isAlarm ? "rgba(239, 68, 68, 0.06)" : "rgba(249, 115, 22, 0.06)";
                const border = isAlarm ? "rgba(239, 68, 68, 0.25)" : "rgba(249, 115, 22, 0.25)";
                const h = info.primaryHealth;
                return `
                    <div onclick="inspectOpticalNokConnection('${conn.id}')"
                         style="display: flex; align-items: center; justify-content: space-between; gap: 10px; background: ${bg}; border: 1px solid ${border}; border-radius: 6px; padding: 10px 14px; font-size: 0.78rem; cursor: pointer; transition: all 0.2s;"
                         onmouseover="this.style.borderColor='${col}'"
                         onmouseout="this.style.borderColor='${border}'">
                        <div style="display: flex; flex-direction: column; gap: 2px; min-width: 0;">
                            <span style="font-weight: 700; color: var(--text-main); display: flex; align-items: center; gap: 6px;">
                                <i class="fa-solid fa-triangle-exclamation" style="color: ${col};"></i>
                                ${escapeHTML(conn.source)} <span style="color: var(--text-muted); font-weight: 400;">[${escapeHTML(conn.source_interface)}]</span>
                                ↔ ${escapeHTML(conn.target)}
                            </span>
                            <span style="font-size: 0.68rem; color: var(--text-muted); font-family: monospace;">
                                Link: ${escapeHTML(conn.link || 'Unnamed')} • ${conn.bitrate}G
                            </span>
                        </div>
                        <div style="display: flex; flex-direction: column; align-items: flex-end; gap: 2px; flex-shrink: 0;">
                            <span style="font-family: monospace; font-weight: 800; color: ${col}; font-size: 0.85rem;">${escapeHTML(h.rxText)}</span>
                            <span class="badge" style="font-size: 0.62rem; padding: 1px 6px; background: ${bg}; color: ${col}; border: 1px solid ${border};">${escapeHTML(h.statusText)}</span>
                        </div>
                    </div>
                `;
            }).join("");
        } else {
            optNokListEl.innerHTML = `
                <div style="grid-column: 1 / -1; display: flex; align-items: center; gap: 6px; background: rgba(16, 185, 129, 0.05); border: 1px solid rgba(16, 185, 129, 0.15); border-radius: 4px; padding: 10px 14px; font-size: 0.78rem; color: var(--success); font-weight: 500;">
                    <i class="fa-solid fa-circle-check"></i>
                    <span>All scanned optical links are operating within normal DDM power thresholds.</span>
                </div>
            `;
        }
    }
}

/* ==========================================================================
   SSH Console Controller
   ========================================================================== */

let consoleState = {
    connected: false,
    selectedDevice: null,
    jumpboxes: {
        router_ip: "10.0.0.1",
        olt_ip: "10.0.0.2"
    },
    jumpboxConnected: false,
    jumpboxAuth: null,
    scanRunning: false,
    scanPaused: false,
    scanStopped: false
};

async function initConsoleView() {
    const routerJbInput = document.getElementById("console-router-jb");
    const oltJbInput = document.getElementById("console-olt-jb");
    const jbSelect = document.getElementById("console-jb-select");
    const jbUserInput = document.getElementById("console-ssh-jb-user");
    const jbPassInput = document.getElementById("console-ssh-jb-pass");
    const jbConnectBtn = document.getElementById("console-jb-connect-btn");
    
    const deviceSelect = document.getElementById("console-device-select");
    const saveJbBtn = document.getElementById("console-save-jb-btn");
    const connectBtn = document.getElementById("console-connect-btn");
    const clearBtn = document.getElementById("console-clear-btn");
    const terminalInput = document.getElementById("console-terminal-input");
    const targetCard = document.getElementById("console-target-card");
    
    // Helper to refresh jumpbox selector option text
    const updateJbSelectorLabels = () => {
        if (jbSelect) {
            jbSelect.options[0].text = `Router Jumpbox (IP: ${consoleState.jumpboxes.router_ip || "10.0.0.1"})`;
            jbSelect.options[1].text = `OLT Jumpbox (IP: ${consoleState.jumpboxes.olt_ip || "10.0.0.2"})`;
        }
    };

    // Load jumpbox settings
    try {
        const response = await fetch(API_BASE + "/console/settings");
        if (response.ok) {
            const config = await response.json();
            consoleState.jumpboxes = config;
            if (routerJbInput) routerJbInput.value = config.router_ip || "10.0.0.1";
            if (oltJbInput) oltJbInput.value = config.olt_ip || "10.0.0.2";
            updateJbSelectorLabels();
        }
    } catch (err) {
        console.error("Failed to load jumpbox settings:", err);
    }
    
    // Load devices list if empty
    if (!appState.nms.devices || appState.nms.devices.length === 0) {
        try {
            await loadNmsTopology();
        } catch (err) {
            console.error("Failed to load topology for console:", err);
        }
    }
    
    // Populate device dropdown
    const populateDevices = () => {
        if (deviceSelect) {
            let optionsHtml = '<option value="">-- Select a Device --</option>';
            if (appState.nms.devices && appState.nms.devices.length > 0) {
                let filtered = appState.nms.devices;
                if (consoleState.jumpboxConnected && consoleState.jumpboxAuth) {
                    const jbType = consoleState.jumpboxAuth.type.toLowerCase(); // "router" or "olt"
                    filtered = appState.nms.devices.filter(d => {
                        return d.type && d.type.toLowerCase() === jbType;
                    });
                }
                filtered.forEach(d => {
                    optionsHtml += `<option value="${escapeHTML(d.name)}">${escapeHTML(d.name)} (${escapeHTML(d.type)})</option>`;
                });
            }
            deviceSelect.innerHTML = optionsHtml;
        }
    };
    populateDevices();
    
    // Bind device select change listener
    if (deviceSelect && !deviceSelect.dataset.listenerBound) {
        deviceSelect.addEventListener("change", (e) => {
            const devName = e.target.value;
            const devInfo = appState.nms.devices.find(d => d.name === devName);
            const previewContainer = document.getElementById("console-device-info-preview");
            
            if (devInfo) {
                consoleState.selectedDevice = devInfo;
                document.getElementById("console-info-ip").innerText = devInfo.ip || "-";
                document.getElementById("console-info-type").innerText = devInfo.type || "-";
                document.getElementById("console-info-brand").innerText = `${devInfo.brand || ""} ${devInfo.model || ""}`.trim() || "-";
                previewContainer.classList.remove("hidden");
                
                // Alert if target device type does not match connected jumpbox type
                if (consoleState.jumpboxConnected && consoleState.jumpboxAuth) {
                    const connectedType = consoleState.jumpboxAuth.type; // "router" or "olt"
                    const targetType = devInfo.type; // "Router" or "OLT"
                    if (connectedType.toLowerCase() !== targetType.toLowerCase()) {
                        appendTerminalLine(`[Warning: Selected target ${devInfo.name} is a ${targetType}, but you are connected to the ${connectedType.toUpperCase()} Jumpbox. Connections may fail if jumpboxes are isolated.]`, "#f59e0b");
                    }
                }
            } else {
                consoleState.selectedDevice = null;
                previewContainer.classList.add("hidden");
            }
        });
        deviceSelect.dataset.listenerBound = "true";
    }
    
    // Save jumpbox configuration
    if (saveJbBtn && !saveJbBtn.dataset.listenerBound) {
        saveJbBtn.addEventListener("click", async () => {
            const routerIp = (routerJbInput.value || "").trim();
            const oltIp = (oltJbInput.value || "").trim();
            
            if (!routerIp || !oltIp) {
                alert("Please specify valid IP addresses for both jumpboxes.");
                return;
            }
            
            try {
                const response = await fetch(API_BASE + "/console/settings", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ router_ip: routerIp, olt_ip: oltIp })
                });
                
                if (response.ok) {
                    consoleState.jumpboxes = { router_ip: routerIp, olt_ip: oltIp };
                    updateJbSelectorLabels();
                    alert("Jumpbox configuration updated successfully!");
                } else {
                    alert("Failed to save jumpbox configuration.");
                }
            } catch (err) {
                console.error("Error saving jumpbox config:", err);
                alert("Error connecting to server to save settings.");
            }
        });
        saveJbBtn.dataset.listenerBound = "true";
    }
    
    // Auto-commands configuration Modal bindings
    const openAutoCmdBtn = document.getElementById("console-open-auto-cmd-btn");
    const autoCmdModal = document.getElementById("console-auto-cmd-modal");
    const autoCmdCloseBtn = document.getElementById("console-auto-cmd-close-btn");
    const autoCmdCancelBtn = document.getElementById("console-auto-cmd-cancel-btn");
    const autoCmdSaveBtn = document.getElementById("console-auto-cmd-save-btn");
    const autoCmdTbody = document.getElementById("console-auto-cmd-tbody");
    const addPatternBtn = document.getElementById("console-add-pattern-btn");
    
    const sshRulesTbody = document.getElementById("console-ssh-rules-tbody");
    const addSshRuleBtn = document.getElementById("console-add-ssh-rule-btn");
    
    let autoCmdsDraft = {}; 
    let sshRulesDraft = {};

    const renderAutoCmdsTable = () => {
        if (!autoCmdTbody) return;
        autoCmdTbody.innerHTML = "";
        
        const keys = Object.keys(autoCmdsDraft);
        if (keys.length === 0) {
            autoCmdTbody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-muted); padding: 15px;">No auto-commands configured. Add one below.</td></tr>`;
            return;
        }
        
        keys.forEach(pattern => {
            const cmd = autoCmdsDraft[pattern];
            const tr = document.createElement("tr");
            tr.style.borderBottom = "1px solid rgba(255, 255, 255, 0.05)";
            tr.innerHTML = `
                <td style="padding: 10px 15px; font-weight: 600; color: var(--text-main); font-family: monospace;">${escapeHTML(pattern)}</td>
                <td style="padding: 10px 15px; color: #10b981; font-family: monospace;">${escapeHTML(cmd)}</td>
                <td style="padding: 5px; text-align: center;">
                    <button class="btn btn-danger btn-sm delete-cmd-btn" data-pattern="${escapeHTML(pattern)}" style="padding: 4px 8px; font-size: 0.75rem; border-radius: 4px; cursor: pointer;">
                        <i class="fa-solid fa-trash-can"></i>
                    </button>
                </td>
            `;
            autoCmdTbody.appendChild(tr);
        });
        
        // Bind delete buttons
        autoCmdTbody.querySelectorAll(".delete-cmd-btn").forEach(btn => {
            btn.addEventListener("click", (e) => {
                const pattern = btn.currentTarget.dataset.pattern;
                delete autoCmdsDraft[pattern];
                renderAutoCmdsTable();
            });
        });
    };

    const renderSshRulesTable = () => {
        if (!sshRulesTbody) return;
        sshRulesTbody.innerHTML = "";
        
        const keys = Object.keys(sshRulesDraft);
        if (keys.length === 0) {
            sshRulesTbody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-muted); padding: 15px;">No SSH command rules configured. Add one below.</td></tr>`;
            return;
        }
        
        keys.forEach(pattern => {
            const template = sshRulesDraft[pattern];
            const tr = document.createElement("tr");
            tr.style.borderBottom = "1px solid rgba(255, 255, 255, 0.05)";
            tr.innerHTML = `
                <td style="padding: 10px 15px; font-weight: 600; color: var(--text-main); font-family: monospace;">${escapeHTML(pattern)}</td>
                <td style="padding: 10px 15px; color: #10b981; font-family: monospace;">${escapeHTML(template)}</td>
                <td style="padding: 5px; text-align: center;">
                    <button class="btn btn-danger btn-sm delete-ssh-btn" data-pattern="${escapeHTML(pattern)}" style="padding: 4px 8px; font-size: 0.75rem; border-radius: 4px; cursor: pointer;">
                        <i class="fa-solid fa-trash-can"></i>
                    </button>
                </td>
            `;
            sshRulesTbody.appendChild(tr);
        });
        
        sshRulesTbody.querySelectorAll(".delete-ssh-btn").forEach(btn => {
            btn.addEventListener("click", (e) => {
                const pattern = btn.currentTarget.dataset.pattern;
                delete sshRulesDraft[pattern];
                renderSshRulesTable();
            });
        });
    };

    if (openAutoCmdBtn && !openAutoCmdBtn.dataset.listenerBound) {
        openAutoCmdBtn.addEventListener("click", async () => {
            try {
                const response = await fetch(API_BASE + "/console/auto-commands");
                const sshResponse = await fetch(API_BASE + "/console/ssh-rules");
                
                if (response.ok && sshResponse.ok) {
                    autoCmdsDraft = await response.json();
                    sshRulesDraft = await sshResponse.json();
                    renderAutoCmdsTable();
                    renderSshRulesTable();
                    if (autoCmdModal) autoCmdModal.classList.remove("hidden");
                }
            } catch (err) {
                console.error("Failed to load configurations:", err);
                alert("Failed to load configurations from server.");
            }
        });
        openAutoCmdBtn.dataset.listenerBound = "true";
    }

    const closeAutoCmdModal = () => {
        if (autoCmdModal) autoCmdModal.classList.add("hidden");
        // Clear input inputs
        const patInput = document.getElementById("console-new-pattern");
        const cmdInput = document.getElementById("console-new-command");
        const sshPatInput = document.getElementById("console-new-ssh-pattern");
        const sshTmplInput = document.getElementById("console-new-ssh-template");
        if (patInput) patInput.value = "";
        if (cmdInput) cmdInput.value = "";
        if (sshPatInput) sshPatInput.value = "";
        if (sshTmplInput) sshTmplInput.value = "";
    };

    if (autoCmdCloseBtn) autoCmdCloseBtn.addEventListener("click", closeAutoCmdModal);
    if (autoCmdCancelBtn) autoCmdCancelBtn.addEventListener("click", closeAutoCmdModal);

    if (addPatternBtn && !addPatternBtn.dataset.listenerBound) {
        addPatternBtn.addEventListener("click", () => {
            const patInput = document.getElementById("console-new-pattern");
            const cmdInput = document.getElementById("console-new-command");
            if (!patInput || !cmdInput) return;
            
            const pattern = patInput.value.trim();
            const command = cmdInput.value.trim();
            
            if (!pattern || !command) {
                alert("Please fill in both the pattern and the command.");
                return;
            }
            
            autoCmdsDraft[pattern] = command;
            patInput.value = "";
            cmdInput.value = "";
            renderAutoCmdsTable();
        });
        addPatternBtn.dataset.listenerBound = "true";
    }

    if (addSshRuleBtn && !addSshRuleBtn.dataset.listenerBound) {
        addSshRuleBtn.addEventListener("click", () => {
            const sshPatInput = document.getElementById("console-new-ssh-pattern");
            const sshTmplInput = document.getElementById("console-new-ssh-template");
            if (!sshPatInput || !sshTmplInput) return;
            
            const pattern = sshPatInput.value.trim();
            const template = sshTmplInput.value.trim();
            
            if (!pattern || !template) {
                alert("Please fill in both the pattern and the command template.");
                return;
            }
            
            sshRulesDraft[pattern] = template;
            sshPatInput.value = "";
            sshTmplInput.value = "";
            renderSshRulesTable();
        });
        addSshRuleBtn.dataset.listenerBound = "true";
    }

    if (autoCmdSaveBtn && !autoCmdSaveBtn.dataset.listenerBound) {
        autoCmdSaveBtn.addEventListener("click", async () => {
            autoCmdSaveBtn.disabled = true;
            autoCmdSaveBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving...';
            
            try {
                const response = await fetch(API_BASE + "/console/auto-commands", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(autoCmdsDraft)
                });
                
                const sshResponse = await fetch(API_BASE + "/console/ssh-rules", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(sshRulesDraft)
                });
                
                if (response.ok && sshResponse.ok) {
                    closeAutoCmdModal();
                    appendTerminalLine("\n[System Gateway Console: Auto-commands and SSH rules configurations updated successfully.]", "#10b981");
                } else {
                    alert("Failed to save configurations.");
                }
            } catch (err) {
                console.error("Failed to save configurations:", err);
                alert("Failed to save configurations: connection error.");
            } finally {
                autoCmdSaveBtn.disabled = false;
                autoCmdSaveBtn.innerHTML = '<i class="fa-solid fa-circle-check"></i> Save Configurations';
            }
        });
        autoCmdSaveBtn.dataset.listenerBound = "true";
    }
    
    // Bind Jumpbox connection toggle button listener
    if (jbConnectBtn && !jbConnectBtn.dataset.listenerBound) {
        jbConnectBtn.addEventListener("click", async () => {
            if (consoleState.jumpboxConnected) {
                // DISCONNECT JUMPBOX
                // Disconnect target device first if connected
                if (consoleState.connected && connectBtn) {
                    connectBtn.click();
                }
                
                consoleState.jumpboxConnected = false;
                consoleState.jumpboxAuth = null;
                
                // Repopulate device dropdown to default (all devices) and reset preview
                populateDevices();
                if (deviceSelect) deviceSelect.value = "";
                const previewContainer = document.getElementById("console-device-info-preview");
                if (previewContainer) previewContainer.classList.add("hidden");
                consoleState.selectedDevice = null;
                
                // Reset UI
                jbConnectBtn.innerHTML = '<i class="fa-solid fa-link"></i> Connect to Jumpbox';
                jbConnectBtn.className = "btn btn-primary";
                jbSelect.disabled = false;
                jbUserInput.disabled = false;
                jbPassInput.disabled = false;
                
                document.getElementById("console-diagnose-all-btn").classList.add("hidden");
                const diagAllOltsBtn = document.getElementById("console-diagnose-all-olts-btn");
                if (diagAllOltsBtn) diagAllOltsBtn.classList.add("hidden");
                
                // Fade and disable target card
                if (targetCard) {
                    targetCard.style.opacity = "0.5";
                    targetCard.style.pointerEvents = "none";
                }
                
                document.getElementById("console-status-led").style.background = "#ef4444";
                document.getElementById("console-status-led").style.boxShadow = "0 0 6px #ef4444";
                document.getElementById("console-status-text").innerText = "CONSOLE DISCONNECTED";
                
                appendTerminalLine("\n[System Console: Jumpbox gateway disconnected.]", "var(--text-muted)");
            } else {
                // CONNECT JUMPBOX
                const jbType = jbSelect.value; // "router" or "olt"
                const activeJbIp = jbType === "router" ? consoleState.jumpboxes.router_ip : consoleState.jumpboxes.olt_ip;
                const user = jbUserInput.value || "admin";
                const pass = jbPassInput.value || "";
                
                if (!activeJbIp) {
                    alert("Active Jumpbox IP is not configured. Please save configuration first.");
                    return;
                }
                
                jbConnectBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Connecting...';
                jbConnectBtn.disabled = true;
                jbSelect.disabled = true;
                jbUserInput.disabled = true;
                jbPassInput.disabled = true;
                
                appendTerminalLine(`\nSSH: Connecting to Jumpbox gateway at ${activeJbIp}...`, "#e2e8f0");
                
                try {
                    const response = await fetch(API_BASE + "/console/jumpbox/connect", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({
                            jumpbox_ip: activeJbIp,
                            username: user,
                            password: pass
                        })
                    });
                    
                    jbConnectBtn.disabled = false;
                    if (response.ok) {
                        const res = await response.json();
                        if (res.status === "error") {
                            jbConnectBtn.innerHTML = '<i class="fa-solid fa-link"></i> Connect to Jumpbox';
                            jbConnectBtn.className = "btn btn-primary";
                            jbSelect.disabled = false;
                            jbUserInput.disabled = false;
                            jbPassInput.disabled = false;
                            
                            appendTerminalLine(`SSH Jumpbox Connection Error:\n${res.message}`, "var(--danger)");
                            return;
                        }
                        
                        consoleState.jumpboxConnected = true;
                        consoleState.jumpboxAuth = { ip: activeJbIp, username: user, password: pass, type: jbType };
                        
                        // Repopulate device list filtered by jumpbox type
                        populateDevices();
                        
                        jbConnectBtn.innerHTML = '<i class="fa-solid fa-link-slash"></i> Disconnect Jumpbox';
                        jbConnectBtn.className = "btn btn-danger";
                        
                        // Enable target card
                        if (targetCard) {
                            targetCard.style.opacity = "1";
                            targetCard.style.pointerEvents = "auto";
                        }
                        
                        document.getElementById("console-status-led").style.background = "#f59e0b";
                        document.getElementById("console-status-led").style.boxShadow = "0 0 6px #f59e0b";
                        document.getElementById("console-status-text").innerText = `JUMPBOX GATEWAY CONNECTED: ${activeJbIp.toUpperCase()}`;
                        
                        document.getElementById("console-diagnose-all-btn").classList.remove("hidden");
                        const diagAllOltsBtn = document.getElementById("console-diagnose-all-olts-btn");
                        if (diagAllOltsBtn) diagAllOltsBtn.classList.remove("hidden");
                        
                        appendTerminalLine(res.message, "#10b981");
                        appendTerminalLine("[SSH: Jumpbox session verified. You may now connect to target network devices below.]", "#e2e8f0");
                        
                        if (res.is_simulation) {
                            document.getElementById("console-mode-badge").classList.remove("hidden");
                        } else {
                            document.getElementById("console-mode-badge").classList.add("hidden");
                        }
                    } else {
                        jbConnectBtn.innerHTML = '<i class="fa-solid fa-link"></i> Connect to Jumpbox';
                        jbConnectBtn.className = "btn btn-primary";
                        jbSelect.disabled = false;
                        jbUserInput.disabled = false;
                        jbPassInput.disabled = false;
                        appendTerminalLine(`SSH Jumpbox Connect Error: Server responded with status ${response.status}`, "var(--danger)");
                    }
                } catch (err) {
                    jbConnectBtn.disabled = false;
                    jbConnectBtn.innerHTML = '<i class="fa-solid fa-link"></i> Connect to Jumpbox';
                    jbConnectBtn.className = "btn btn-primary";
                    jbSelect.disabled = false;
                    jbUserInput.disabled = false;
                    jbPassInput.disabled = false;
                    appendTerminalLine("SSH Jumpbox Connect Error: Network request failed.", "var(--danger)");
                }
            }
        });
        jbConnectBtn.dataset.listenerBound = "true";
    }
    
    // Toggle SSH Target Device connection
    if (connectBtn && !connectBtn.dataset.listenerBound) {
        connectBtn.addEventListener("click", () => {
            if (consoleState.connected) {
                // Disconnect target
                consoleState.connected = false;
                connectBtn.innerHTML = '<i class="fa-solid fa-plug"></i> Establish Tunnel';
                connectBtn.className = "btn btn-primary";
                
                // Close active WS session if open
                if (consoleState.ws) {
                    consoleState.ws.close();
                }
                
                document.getElementById("console-diagnose-btn").classList.add("hidden");
                document.getElementById("console-diagnostics-card").classList.add("hidden");
                
                // Fall back status text to connected jumpbox
                if (consoleState.jumpboxConnected && consoleState.jumpboxAuth) {
                    document.getElementById("console-status-led").style.background = "#f59e0b";
                    document.getElementById("console-status-led").style.boxShadow = "0 0 6px #f59e0b";
                    document.getElementById("console-status-text").innerText = `JUMPBOX GATEWAY CONNECTED: ${consoleState.jumpboxAuth.ip.toUpperCase()}`;
                } else {
                    document.getElementById("console-status-led").style.background = "#ef4444";
                    document.getElementById("console-status-led").style.boxShadow = "0 0 6px #ef4444";
                    document.getElementById("console-status-text").innerText = "CONSOLE DISCONNECTED";
                }
                
                document.getElementById("console-input-row").classList.add("hidden");
                appendTerminalLine("[System Gateway Console: Tunnel connection to target terminated.]", "var(--text-muted)");
            } else {
                // Connect target device
                if (!consoleState.jumpboxConnected || !consoleState.jumpboxAuth) {
                    alert("Please connect to Jumpbox gateway first.");
                    return;
                }
                if (!consoleState.selectedDevice) {
                    alert("Please select a target device to connect to.");
                    return;
                }
                
                const dev = consoleState.selectedDevice;
                const jbAuth = consoleState.jumpboxAuth;
                const devUser = document.getElementById("console-ssh-dev-user").value || "admin";
                const devPass = document.getElementById("console-ssh-dev-pass").value || "";
                
                connectBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Tunneling...';
                connectBtn.disabled = true;
                
                document.getElementById("console-status-led").style.background = "#f59e0b";
                document.getElementById("console-status-led").style.boxShadow = "0 0 6px #f59e0b";
                document.getElementById("console-status-text").innerText = "ESTABLISHING SSH VIA JUMPBOX...";
                
                appendTerminalLine(`\nSSH: Initiating SSH connection to target device ${dev.name} (${dev.ip}) via Jumpbox (${jbAuth.ip})...`, "#e2e8f0");
                
                // Initialize WebSocket connection
                const loc = window.location;
                const wsProtocol = loc.protocol === "https:" ? "wss:" : "ws:";
                // Decouple relative WS path
                const wsUrl = `${wsProtocol}//${loc.host}${API_BASE}/console/ws`;
                
                const ws = new WebSocket(wsUrl);
                consoleState.ws = ws;
                
                ws.onopen = () => {
                    ws.send(JSON.stringify({
                        jumpbox_ip: jbAuth.ip,
                        jumpbox_username: jbAuth.username,
                        jumpbox_password: jbAuth.password,
                        device_ip: dev.ip,
                        device_username: devUser,
                        device_password: devPass,
                        device_type: dev.type,
                        device_brand: dev.brand,
                        device_model: dev.model
                    }));
                };
                
                ws.onmessage = (event) => {
                    try {
                        const msg = JSON.parse(event.data);
                        if (msg.type === "status") {
                            appendTerminalLine(msg.data, "#e2e8f0");
                        } else if (msg.type === "output") {
                            // Convert carriage returns to clean line breaks
                            const cleanText = msg.data.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
                            appendTerminalLine(cleanText, "#10b981");
                            
                            // Check if prompt appeared to set connected state
                            if (!consoleState.connected && (msg.data.includes("#") || msg.data.includes(">"))) {
                                consoleState.connected = true;
                                connectBtn.disabled = false;
                                connectBtn.innerHTML = '<i class="fa-solid fa-plug-circle-xmark"></i> Disconnect Tunnel';
                                connectBtn.className = "btn btn-danger";
                                
                                document.getElementById("console-status-led").style.background = "#10b981";
                                document.getElementById("console-status-led").style.boxShadow = "0 0 6px #10b981";
                                document.getElementById("console-status-text").innerText = `SSH SHELL ACTIVE: ${dev.name.toUpperCase()} (${dev.ip})`;
                                
                                document.getElementById("console-prompt").innerText = `${dev.name.toLowerCase()}#`;
                                document.getElementById("console-input-row").classList.remove("hidden");
                                document.getElementById("console-diagnose-btn").classList.remove("hidden");
                                if (terminalInput) {
                                    terminalInput.focus();
                                }
                            }
                        } else if (msg.type === "error") {
                            appendTerminalLine(`\nSSH Gateway Error:\n${msg.data}`, "var(--danger)");
                            ws.close();
                        }
                    } catch (e) {
                        console.error("Failed to parse WebSocket message:", e);
                    }
                };
                
                ws.onerror = () => {
                    appendTerminalLine("\nSSH Error: WebSocket connection failed.", "var(--danger)");
                };
                
                ws.onclose = () => {
                    consoleState.connected = false;
                    consoleState.ws = null;
                    connectBtn.disabled = false;
                    connectBtn.innerHTML = '<i class="fa-solid fa-plug"></i> Establish Tunnel';
                    connectBtn.className = "btn btn-primary";
                    
                    document.getElementById("console-diagnose-btn").classList.add("hidden");
                    document.getElementById("console-diagnostics-card").classList.add("hidden");
                    
                    if (consoleState.jumpboxConnected && consoleState.jumpboxAuth) {
                        document.getElementById("console-status-led").style.background = "#f59e0b";
                        document.getElementById("console-status-led").style.boxShadow = "0 0 6px #f59e0b";
                        document.getElementById("console-status-text").innerText = `JUMPBOX GATEWAY CONNECTED: ${consoleState.jumpboxAuth.ip.toUpperCase()}`;
                    } else {
                        document.getElementById("console-status-led").style.background = "#ef4444";
                        document.getElementById("console-status-led").style.boxShadow = "0 0 6px #ef4444";
                        document.getElementById("console-status-text").innerText = "CONSOLE DISCONNECTED";
                    }
                    
                    document.getElementById("console-input-row").classList.add("hidden");
                    appendTerminalLine("\n[System Gateway Console: Tunnel connection to target terminated.]", "var(--text-muted)");
                };
            }
        });
        connectBtn.dataset.listenerBound = "true";
    }
    
    // Clear terminal screen
    if (clearBtn && !clearBtn.dataset.listenerBound) {
        clearBtn.addEventListener("click", () => {
            const screen = document.getElementById("console-terminal-screen");
            if (screen) {
                screen.innerHTML = '<div style="color: var(--text-muted);">[Terminal cleared]</div>';
            }
        });
        clearBtn.dataset.listenerBound = "true";
    }
    
    // Command submission input
    if (terminalInput && !terminalInput.dataset.listenerBound) {
        terminalInput.addEventListener("keydown", async (e) => {
            if (e.key === "Enter") {
                const command = (terminalInput.value || "").trim();
                terminalInput.value = "";
                if (!command) return;
                
                const promptText = document.getElementById("console-prompt").innerText;
                appendTerminalLine(`<span style="color: #3b82f6;">${escapeHTML(promptText)} </span><span style="color: #ffffff; font-weight: 600;">${escapeHTML(command)}</span>`);
                
                if (command.toLowerCase() === "clear") {
                    document.getElementById("console-terminal-screen").innerHTML = '<div style="color: var(--text-muted);">[Terminal cleared]</div>';
                    return;
                }
                
                if (consoleState.ws && consoleState.ws.readyState === WebSocket.OPEN) {
                    consoleState.ws.send(JSON.stringify({ type: "input", data: command + "\n" }));
                } else {
                    appendTerminalLine("SSH Error: WebSocket connection is not active.", "var(--danger)");
                }
            }
        });
        terminalInput.dataset.listenerBound = "true";
    }
    
    // Port Power Diagnostics Logic
    const diagnoseBtn = document.getElementById("console-diagnose-btn");
    const diagCard = document.getElementById("console-diagnostics-card");
    const diagCloseBtn = document.getElementById("console-close-diagnostics-btn");
    const diagTbody = document.getElementById("console-diagnostics-tbody");
    const diagProgress = document.getElementById("console-diagnose-progress");

    if (diagCloseBtn) {
        diagCloseBtn.addEventListener("click", () => {
            if (diagCard) diagCard.classList.add("hidden");
            if (consoleState.scanRunning) {
                consoleState.scanStopped = true;
                const scanControls = document.getElementById("console-scan-controls");
                if (scanControls) scanControls.classList.add("hidden");
                appendTerminalLine("\n[Diagnostics: Scan cancelled because diagnostics card was closed.]", "var(--danger)");
            }
        });
    }

    // Helper functions
    function getQueryPort(portStr) {
        if (!portStr) return "";
        const parts = portStr.split("/");
        if (parts.length === 4) {
            return parts.slice(0, 3).join("/");
        }
        return portStr;
    }

    function executeCommandViaSocket(commandText, timeoutMs = 8000) {
        return new Promise((resolve, reject) => {
            if (!consoleState.ws || consoleState.ws.readyState !== WebSocket.OPEN) {
                reject(new Error("WebSocket connection not open"));
                return;
            }
            
            let outputBuffer = "";
            let timeoutId = setTimeout(() => {
                consoleState.ws.removeEventListener("message", handleMsg);
                reject(new Error("Command execution timed out"));
            }, timeoutMs);
            
            const handleMsg = (event) => {
                try {
                    const msg = JSON.parse(event.data);
                    if (msg.type === "output") {
                        outputBuffer += msg.data;
                        const lowerData = msg.data.toLowerCase();
                        if (lowerData.includes("{ <cr>") || lowerData.includes("---- more ----") || lowerData.includes("--more--")) {
                            consoleState.ws.send(JSON.stringify({ type: "input", data: "\n" }));
                        }
                        const lines = outputBuffer.split(/\r?\n/);
                        if (lines.length > 1) {
                            const lastLine = lines[lines.length - 1].trim();
                            // If prompt has returned (ends with #, >, or ])
                            if ((lastLine.endsWith("#") || lastLine.endsWith(">") || lastLine.endsWith("]")) && !lastLine.includes("{ <cr>")) {
                                clearTimeout(timeoutId);
                                consoleState.ws.removeEventListener("message", handleMsg);
                                resolve(outputBuffer);
                            }
                        }
                    } else if (msg.type === "error") {
                        clearTimeout(timeoutId);
                        consoleState.ws.removeEventListener("message", handleMsg);
                        reject(new Error(msg.data));
                    }
                } catch (e) {
                    // Ignore parsing error
                }
            };
            
            consoleState.ws.addEventListener("message", handleMsg);
            consoleState.ws.send(JSON.stringify({ type: "input", data: commandText + "\n" }));
        });
    }

    function parseNokiaDdm(output) {
        const lines = output.split(/\r?\n/);
        
        // Check if output contains multi-lane lane diagnostics
        const isMultiLane = output.includes("Lane Rx Optical Pwr") || output.includes("Transceiver Lane Digital Diagnostic");
        
        if (isMultiLane) {
            let lowAlarm = -16.00;
            let lowWarn = -13.00;
            let highWarn = 4.00;
            let highAlarm = 4.50;
            
            // 1. Parse thresholds
            for (let line of lines) {
                if (line.includes("Lane Rx Optical Pwr") || line.includes("Lane Rx Optical")) {
                    const matches = line.match(/-?\d+\.\d+/g);
                    if (matches && matches.length >= 4) {
                        // Order in CFP2 output: High Alarm, High Warn, Low Warn, Low Alarm
                        highAlarm = parseFloat(matches[0]);
                        highWarn = parseFloat(matches[1]);
                        lowWarn = parseFloat(matches[2]);
                        lowAlarm = parseFloat(matches[3]);
                    }
                }
            }
            
            // 2. Parse individual lanes
            let inLaneTable = false;
            const lanes = [];
            
            for (let line of lines) {
                const cleanLine = line.trim();
                if (cleanLine.includes("Lane ID") && cleanLine.includes("Rx Pwr")) {
                    inLaneTable = true;
                    continue;
                }
                if (inLaneTable) {
                    if (cleanLine.startsWith("===") || cleanLine.startsWith("---")) {
                        if (lanes.length > 0) {
                            inLaneTable = false;
                        }
                        continue;
                    }
                    
                    const parts = cleanLine.split(/\s+/);
                    if (parts.length >= 5) {
                        const laneId = parseInt(parts[0]);
                        const rxPowerStr = parts[parts.length - 1]; // last column is Rx Pwr
                        const rxPower = parseFloat(rxPowerStr);
                        if (!isNaN(laneId) && !isNaN(rxPower)) {
                            lanes.push({
                                id: laneId,
                                rxPower: rxPower
                            });
                        }
                    }
                }
            }
            
            if (lanes.length > 0) {
                // Find worst-performing lane (minimum rxPower)
                let worstLane = lanes[0];
                lanes.forEach(l => {
                    if (l.rxPower < worstLane.rxPower) {
                        worstLane = l;
                    }
                });
                
                return {
                    value: worstLane.rxPower,
                    highAlarm: highAlarm,
                    highWarn: highWarn,
                    lowWarn: lowWarn,
                    lowAlarm: lowAlarm,
                    displayText: lanes.map(l => l.rxPower.toFixed(2)).join(" | "),
                    toolTip: lanes.map(l => `Lane ${l.id}: ${l.rxPower.toFixed(2)} dBm`).join("\n")
                };
            }
        }
        
        // Single-lane parsing fallback
        for (let line of lines) {
            if (line.includes("Rx Optical Power") || line.includes("Rx Power") || line.includes("Rx Optical")) {
                const matches = line.match(/-?\d+\.\d+/g);
                if (matches && matches.length >= 5) {
                    const rxVal = parseFloat(matches[0]);
                    return {
                        value: rxVal,
                        highAlarm: parseFloat(matches[1]),
                        highWarn: parseFloat(matches[2]),
                        lowWarn: parseFloat(matches[3]),
                        lowAlarm: parseFloat(matches[4]),
                        displayText: `${rxVal.toFixed(2)} dBm`,
                        toolTip: ""
                    };
                }
            }
        }
        return null;
    }

    function getThresholdStatus(val, lowAlarm, lowWarn, highWarn, highAlarm) {
        if (val <= lowAlarm) return "Low Alarm";
        if (val <= lowWarn) return "Low Warning";
        if (val >= highAlarm) return "High Alarm";
        if (val >= highWarn) return "High Warning";
        return "Normal";
    }

    function classifyDevicePlatform(dev) {
        if (!dev) return "nokia_router";
        const combined = `${dev.brand || ""} ${dev.model || ""} ${dev.type || ""}`.toLowerCase();
        if (combined.includes("ma56") || combined.includes("ma58") || combined.includes("huawei")) {
            return "huawei_olt";
        }
        if (combined.includes("c600") || combined.includes("c620") || combined.includes("c650") || combined.includes("c610")) {
            return "zte_c600";
        }
        if (combined.includes("c300") || combined.includes("c320")) {
            return "zte_c300";
        }
        if (combined.includes("c220")) {
            return "zte_c220";
        }
        if ((dev.type || "").toLowerCase() === "olt" || combined.includes("zte")) {
            return "zte_c600";
        }
        return "nokia_router";
    }

    function parseOltDdm(output, platform, portLabel = "") {
        if (!output) return null;
        const lines = output.split(/\r?\n/);

        if (platform === "huawei_olt") {
            let rxVal = null;
            let lowAlarm = -19.00;
            let lowWarn = -16.00;
            let highWarn = -1.00;
            let highAlarm = 1.00;

            for (const line of lines) {
                const lower = line.toLowerCase();
                const numMatch = line.match(/:\s*(-?\d+(?:\.\d+)?)/);
                if (!numMatch) continue;
                const val = parseFloat(numMatch[1]);
                if (isNaN(val)) continue;

                if ((lower.includes("rx power(dbm)") || lower.includes("rx optical power")) && !lower.includes("threshold")) {
                    rxVal = val;
                } else if (lower.includes("rx power") && lower.includes("lowalarm")) {
                    lowAlarm = val;
                } else if (lower.includes("rx power") && lower.includes("lowwarn")) {
                    lowWarn = val;
                } else if (lower.includes("rx power") && lower.includes("highwarn")) {
                    highWarn = val;
                } else if (lower.includes("rx power") && lower.includes("highalarm")) {
                    highAlarm = val;
                }
            }

            if (rxVal !== null && rxVal > -60 && rxVal < 20) {
                return {
                    value: rxVal,
                    highAlarm,
                    highWarn,
                    lowWarn,
                    lowAlarm,
                    displayText: `${rxVal.toFixed(2)} dBm`,
                    toolTip: portLabel ? `Huawei GIU Port: ${portLabel}` : "Huawei SmartAX OLT DDM"
                };
            }
        }

        // ZTE OLT (C600v1, C620v1, C620, C300v210, C320v210, C220v1.2)
        let rxVal = null;
        let lowAlarm = -18.00;
        let lowWarn = -15.00;
        let highWarn = -1.00;
        let highAlarm = 1.00;

        for (const line of lines) {
            const lower = line.toLowerCase();
            // Match RxPower : -8.45(dbm) or Rx-Power : -8.45 dBm
            if ((lower.includes("rxpower") || lower.includes("rx-power") || lower.includes("rx power")) &&
                !lower.includes("high") && !lower.includes("low") && !lower.includes("alarm") && !lower.includes("warn")) {
                const rxMatch = line.match(/(?:rxpower|rx-power|rx\s+power)\s*(?:\(dbm\))?\s*[:=]\s*(-?\d+(?:\.\d+)?)/i);
                if (rxMatch) {
                    const parsedRx = parseFloat(rxMatch[1]);
                    if (!isNaN(parsedRx)) rxVal = parsedRx;
                }
            }

            // Threshold lines on ZTE C600/C620/C300/C320:
            // RxPower-High-Alarm:  1.00(dbm)        RxPower-Low-Alarm: -18.00(dbm)
            // RxPower-High-Warn : -1.00(dbm)        RxPower-Low-Warn : -15.00(dbm)
            const haMatch = line.match(/rx(?:power|-power)?[-_\s]*high[-_\s]*alarm\s*[:=]\s*(-?\d+(?:\.\d+)?)/i);
            if (haMatch) highAlarm = parseFloat(haMatch[1]);

            const laMatch = line.match(/rx(?:power|-power)?[-_\s]*low[-_\s]*alarm\s*[:=]\s*(-?\d+(?:\.\d+)?)/i);
            if (laMatch) lowAlarm = parseFloat(laMatch[1]);

            const hwMatch = line.match(/rx(?:power|-power)?[-_\s]*high[-_\s]*warn(?:ing)?\s*[:=]\s*(-?\d+(?:\.\d+)?)/i);
            if (hwMatch) highWarn = parseFloat(hwMatch[1]);

            const lwMatch = line.match(/rx(?:power|-power)?[-_\s]*low[-_\s]*warn(?:ing)?\s*[:=]\s*(-?\d+(?:\.\d+)?)/i);
            if (lwMatch) lowWarn = parseFloat(lwMatch[1]);

            // Combined format on some ZTE C300/C220 versions: RxPower-High : 2.00/0.00(dbm)  RxPower-Low : -18.00/-15.00(dbm)
            const combHigh = line.match(/rx(?:power|-power)?[-_\s]*high\s*[:=]\s*(-?\d+(?:\.\d+)?)\s*\/\s*(-?\d+(?:\.\d+)?)/i);
            if (combHigh) {
                highAlarm = parseFloat(combHigh[1]);
                highWarn = parseFloat(combHigh[2]);
            }
            const combLow = line.match(/rx(?:power|-power)?[-_\s]*low\s*[:=]\s*(-?\d+(?:\.\d+)?)\s*\/\s*(-?\d+(?:\.\d+)?)/i);
            if (combLow) {
                lowAlarm = parseFloat(combLow[1]);
                lowWarn = parseFloat(combLow[2]);
            }
        }

        if (rxVal !== null && rxVal > -60 && rxVal < 20) {
            return {
                value: rxVal,
                highAlarm,
                highWarn,
                lowWarn,
                lowAlarm,
                displayText: `${rxVal.toFixed(2)} dBm`,
                toolTip: portLabel ? `OLT Uplink: ${portLabel}` : "ZTE OLT Optical Module DDM"
            };
        }

        return parseNokiaDdm(output);
    }

    async function queryPortOpticalPower(dev, rawPort, execCmdFn) {
        const platform = classifyDevicePlatform(dev);

        if (platform === "nokia_router") {
            const queryPort = getQueryPort(rawPort);
            const output = await execCmdFn(`show port ${queryPort} optical`);
            return parseNokiaDdm(output);
        }

        if (platform === "huawei_olt") {
            // Huawei SmartAX MA5600T / MA5680T
            let candidates = [];
            const fspMatch = (rawPort || "").match(/(\d+)\/(\d+)\/(\d+)/);
            if (fspMatch && rawPort !== "ge0/0/0") {
                candidates.push({ frame: fspMatch[1], slot: fspMatch[2], port: fspMatch[3] });
            } else {
                // Default GIU uplink slots on MA5600T / MA5680T
                candidates.push({ frame: "0", slot: "19", port: "0" });
                candidates.push({ frame: "0", slot: "20", port: "0" });
                candidates.push({ frame: "0", slot: "9", port: "0" });
            }

            try {
                await execCmdFn("config", 5000);
            } catch (e) { /* ignore */ }

            let parsedResult = null;
            for (const cand of candidates) {
                try {
                    await execCmdFn(`interface giu ${cand.frame}/${cand.slot}`, 5000);
                    const ddmOut = await execCmdFn(`display port ddm-info ${cand.port}`, 8000);
                    await execCmdFn("quit", 4000);
                    const parsed = parseOltDdm(ddmOut, "huawei_olt", `giu ${cand.frame}/${cand.slot}/${cand.port}`);
                    if (parsed) {
                        parsedResult = parsed;
                        break;
                    }
                } catch (e) {
                    // Try next candidate
                }
            }
            try {
                await execCmdFn("quit", 4000);
            } catch (e) { /* ignore */ }
            return parsedResult;
        }

        // ZTE OLT (zte_c600, zte_c300, zte_c220)
        const isTitanC600 = platform === "zte_c600";
        let candidatePorts = [];

        if (!rawPort || rawPort === "ge0/0/0") {
            // Auto-discover active uplink port (xgei or gei) via show interface brief
            try {
                const briefOut = await execCmdFn("show interface brief", 8000);
                const briefLines = briefOut.split(/\r?\n/);
                for (const line of briefLines) {
                    const m = line.match(/((?:xgei|gei|xge|ge)[-_]\d+\/\d+\/\d+)/i);
                    if (m && /\bup\b/i.test(line)) {
                        const foundPort = m[1];
                        if (!candidatePorts.includes(foundPort)) {
                            candidatePorts.push(foundPort);
                        }
                    }
                }
            } catch (e) {
                // Fallback if show interface brief fails
            }
            if (candidatePorts.length === 0) {
                if (isTitanC600) {
                    candidatePorts = ["xgei-1/4/1", "xgei-1/5/1"];
                } else if (platform === "zte_c300") {
                    const isC320 = (dev.model || "").toLowerCase().includes("c320");
                    candidatePorts = isC320 ? ["xgei_1/3/1", "gei_1/3/1"] : ["xgei_1/19/1", "xgei_1/20/1"];
                } else {
                    candidatePorts = ["gei_0/14/1", "gei_0/13/1"];
                }
            }
        } else {
            const clean = rawPort.trim();
            if (isTitanC600) {
                // C600/C620 uses hyphen (e.g. xgei-1/4/1)
                const hyphenPort = clean.replace("_", "-");
                candidatePorts.push(hyphenPort);
                if (!hyphenPort.startsWith("xgei") && !hyphenPort.startsWith("gei") && /^\d+\/\d+\/\d+$/.test(hyphenPort)) {
                    candidatePorts.unshift(`xgei-${hyphenPort}`);
                }
            } else {
                // C300/C320/C220 uses underscore (e.g. xgei_1/19/1) or hyphen depending on patch
                const underPort = clean.replace("-", "_");
                const hyphenPort = clean.replace("_", "-");
                candidatePorts.push(underPort);
                if (hyphenPort !== underPort) candidatePorts.push(hyphenPort);
            }
        }

        for (const candPort of candidatePorts) {
            const cmdsToTry = isTitanC600
                ? [`show optical-module-info ${candPort}`, `show interface optical-module-info ${candPort}`]
                : [`show interface optical-module-info ${candPort}`, `show optical-module-info ${candPort}`];

            for (const cmd of cmdsToTry) {
                try {
                    const out = await execCmdFn(cmd, 8000);
                    const parsed = parseOltDdm(out, platform, `${candPort} (${dev.model || dev.brand || "OLT"})`);
                    if (parsed) {
                        return parsed;
                    }
                } catch (e) {
                    // Try next command variant
                }
            }
        }

        return null;
    }

    if (diagnoseBtn && !diagnoseBtn.dataset.listenerBound) {
        diagnoseBtn.addEventListener("click", async () => {
            if (!consoleState.connected || !consoleState.selectedDevice) {
                alert("Please connect to a target device first.");
                return;
            }
            
            const activeDev = consoleState.selectedDevice;
            const connections = (appState.nms && appState.nms.connections) || [];
            
            // Find connection ports where this device is either source or target
            const portsToTest = [];
            connections.forEach(conn => {
                if (conn.source === activeDev.name) {
                    portsToTest.push({
                        target: conn.target,
                        port: conn.source_interface,
                        connectionId: conn.id
                    });
                } else if (conn.target === activeDev.name) {
                    portsToTest.push({
                        target: conn.source,
                        port: conn.target_interface,
                        connectionId: conn.id
                    });
                }
            });
            
            // Keep unique ports only
            const uniquePorts = [];
            const seenPorts = new Set();
            portsToTest.forEach(p => {
                if (!seenPorts.has(p.port)) {
                    seenPorts.add(p.port);
                    uniquePorts.push(p);
                }
            });
            
            if (uniquePorts.length === 0) {
                appendTerminalLine("\n[Diagnostics: No ports found for this device in Network Topology connections.]", "#f59e0b");
                alert("No ports found on the connection list for this device in the Network Topology.");
                return;
            }
            
            // Show card and clear table
            if (diagCard) diagCard.classList.remove("hidden");
            if (diagTbody) diagTbody.innerHTML = "";
            if (diagProgress) diagProgress.innerText = `0 / ${uniquePorts.length} complete`;
            
            // Disable buttons and terminal inputs to prevent interference
            diagnoseBtn.disabled = true;
            diagnoseBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Diagnosing...';
            if (terminalInput) terminalInput.disabled = true;
            
            appendTerminalLine(`\n[Diagnostics: Starting optical power scan on ${uniquePorts.length} connection ports...]`, "#e2e8f0");
            
            // Render queued placeholders
            uniquePorts.forEach((task, idx) => {
                const tr = document.createElement("tr");
                tr.id = `console-diag-row-${idx}`;
                tr.style.borderBottom = "1px solid rgba(255, 255, 255, 0.05)";
                tr.innerHTML = `
                    <td style="padding: 8px 10px; font-weight: 600; color: var(--text-muted);">${escapeHTML(activeDev.name)}</td>
                    <td style="padding: 8px 10px; font-weight: 600;">${escapeHTML(task.target)}</td>
                    <td style="padding: 8px 10px; font-family: monospace;">${escapeHTML(task.port)}</td>
                    <td colspan="5" style="padding: 8px 10px; text-align: center; color: var(--text-muted);"><i class="fa-solid fa-hourglass-start"></i> Waiting...</td>
                    <td style="padding: 8px 10px; text-align: center;"><span class="badge" style="background: rgba(255,255,255,0.05); color: var(--text-muted);">Queued</span></td>
                `;
                diagTbody.appendChild(tr);
            });
            
            // Run scan sequentially
            const collectedSingleResults = [];
            try {
                for (let idx = 0; idx < uniquePorts.length; idx++) {
                    const task = uniquePorts[idx];
                    const row = document.getElementById(`console-diag-row-${idx}`);
                    if (!row) continue;
                    
                    row.innerHTML = `
                        <td style="padding: 8px 10px; font-weight: 600; color: var(--primary);">${escapeHTML(activeDev.name)}</td>
                        <td style="padding: 8px 10px; font-weight: 600;">${escapeHTML(task.target)}</td>
                        <td style="padding: 8px 10px; font-family: monospace;">${escapeHTML(task.port)}</td>
                        <td colspan="5" style="padding: 8px 10px; text-align: center; color: var(--primary);"><i class="fa-solid fa-spinner fa-spin"></i> Polling optical diagnostics...</td>
                        <td style="padding: 8px 10px; text-align: center;"><span class="badge" style="background: rgba(59, 130, 246, 0.15); color: var(--primary);">Testing</span></td>
                    `;
                    
                    try {
                        // Execute command over stateful shell with a 500ms prompt buffer delay
                        await new Promise(r => setTimeout(r, 500));
                        const parsed = await queryPortOpticalPower(activeDev, task.port, executeCommandViaSocket);
                        
                        if (parsed) {
                            const status = getThresholdStatus(parsed.value, parsed.lowAlarm, parsed.lowWarn, parsed.highWarn, parsed.highAlarm);
                            
                            let badgeStyle = "background: rgba(16, 185, 129, 0.15); color: #10b981;"; // Normal
                            if (status.includes("Warning")) {
                                badgeStyle = "background: rgba(245, 158, 11, 0.15); color: #f59e0b;"; // Warning
                            } else if (status.includes("Alarm")) {
                                badgeStyle = "background: rgba(239, 68, 68, 0.15); color: #ef4444;"; // Alarm
                            }
                            
                            row.innerHTML = `
                                <td style="padding: 8px 10px; font-weight: 600; color: var(--text-muted);">${escapeHTML(activeDev.name)}</td>
                                <td style="padding: 8px 10px; font-weight: 600;">${escapeHTML(task.target)}</td>
                                <td style="padding: 8px 10px; font-family: monospace;">${escapeHTML(task.port)}</td>
                                <td style="padding: 8px 10px; text-align: right; font-weight: bold; color: ${status.includes("Alarm") ? '#ef4444' : status.includes("Warning") ? '#f59e0b' : '#10b981'}; font-family: monospace;" title="${escapeHTML(parsed.toolTip || '')}">${escapeHTML(parsed.displayText)}</td>
                                <td style="padding: 8px 10px; text-align: right; color: var(--text-muted); font-family: monospace;">${parsed.lowAlarm.toFixed(2)}</td>
                                <td style="padding: 8px 10px; text-align: right; color: var(--text-muted); font-family: monospace;">${parsed.lowWarn.toFixed(2)}</td>
                                <td style="padding: 8px 10px; text-align: right; color: var(--text-muted); font-family: monospace;">${parsed.highWarn.toFixed(2)}</td>
                                <td style="padding: 8px 10px; text-align: right; color: var(--text-muted); font-family: monospace;">${parsed.highAlarm.toFixed(2)}</td>
                                <td style="padding: 8px 10px; text-align: center;"><span class="badge" style="${badgeStyle}">${status}</span></td>
                            `;
                            collectedSingleResults.push({
                                router: activeDev.name,
                                target: task.target,
                                port: task.port,
                                status: "success",
                                displayText: parsed.displayText,
                                toolTip: parsed.toolTip || "",
                                value: parsed.value,
                                lowAlarm: parsed.lowAlarm,
                                lowWarn: parsed.lowWarn,
                                highWarn: parsed.highWarn,
                                highAlarm: parsed.highAlarm,
                                thresholdStatus: status
                            });
                        } else {
                            row.innerHTML = `
                                <td style="padding: 8px 10px; font-weight: 600; color: var(--text-muted);">${escapeHTML(activeDev.name)}</td>
                                <td style="padding: 8px 10px; font-weight: 600;">${escapeHTML(task.target)}</td>
                                <td style="padding: 8px 10px; font-family: monospace;">${escapeHTML(task.port)}</td>
                                <td colspan="5" style="padding: 8px 10px; text-align: center; color: var(--text-muted);">DDM parameters not supported on port.</td>
                                <td style="padding: 8px 10px; text-align: center;"><span class="badge" style="background: rgba(255, 255, 255, 0.05); color: var(--text-muted);">N/A</span></td>
                            `;
                            collectedSingleResults.push({
                                router: activeDev.name,
                                target: task.target,
                                port: task.port,
                                status: "unsupported"
                            });
                        }
                    } catch (err) {
                        row.innerHTML = `
                            <td style="padding: 8px 10px; font-weight: 600; color: var(--text-muted);">${escapeHTML(activeDev.name)}</td>
                            <td style="padding: 8px 10px; font-weight: 600;">${escapeHTML(task.target)}</td>
                            <td style="padding: 8px 10px; font-family: monospace;">${escapeHTML(task.port)}</td>
                            <td colspan="5" style="padding: 8px 10px; text-align: center; color: var(--danger); font-family: monospace;">Error: ${escapeHTML(err.message)}</td>
                            <td style="padding: 8px 10px; text-align: center;"><span class="badge" style="background: rgba(239, 68, 68, 0.15); color: #ef4444;">Failed</span></td>
                        `;
                        collectedSingleResults.push({
                            router: activeDev.name,
                            target: task.target,
                            port: task.port,
                            status: "failed",
                            errorMsg: err.message
                        });
                    }
                    
                    if (diagProgress) {
                        diagProgress.innerText = `${idx + 1} / ${uniquePorts.length} complete`;
                    }
                }
                
                appendTerminalLine("[Diagnostics: Optical power scan completed successfully.]", "#10b981");
                if (collectedSingleResults.length > 0) {
                    await saveOpticalScanToServer(collectedSingleResults, false);
                }
            } catch (globalErr) {
                console.error("Global diagnostics loop error:", globalErr);
            } finally {
                // Re-enable inputs
                diagnoseBtn.disabled = false;
                diagnoseBtn.innerHTML = '<i class="fa-solid fa-square-poll-horizontal"></i> Diagnose Port Power';
                if (terminalInput) {
                    terminalInput.disabled = false;
                    terminalInput.focus();
                }
            }
        });
        diagnoseBtn.dataset.listenerBound = "true";
    }

    // Helper to scan a single router's ports over a dedicated WebSocket connection
    function scanSingleRouter(router, jbAuth, devUser, devPass, onProgress) {
        return new Promise((resolve, reject) => {
            const loc = window.location;
            const wsProtocol = loc.protocol === "https:" ? "wss:" : "ws:";
            const wsUrl = `${wsProtocol}//${loc.host}${API_BASE}/console/ws`;
            
            const ws = new WebSocket(wsUrl);
            let hasPromptReturned = false;
            let outputBuffer = "";
            let timeoutId = setTimeout(() => {
                cleanup();
                reject(new Error("Timeout establishing SSH connection via Jumpbox"));
            }, 12000); // 12 seconds connection timeout per router
            
            function cleanup() {
                clearTimeout(timeoutId);
                ws.close();
            }
            
            ws.onopen = () => {
                ws.send(JSON.stringify({
                    jumpbox_ip: jbAuth.ip,
                    jumpbox_username: jbAuth.username,
                    jumpbox_password: jbAuth.password,
                    device_ip: router.ip,
                    device_username: devUser,
                    device_password: devPass,
                    device_type: router.type,
                    device_brand: router.brand,
                    device_model: router.model
                }));
            };
            
            ws.onmessage = (event) => {
                try {
                    const msg = JSON.parse(event.data);
                    if (msg.type === "output") {
                        outputBuffer += msg.data;
                        if (!hasPromptReturned) {
                            const lines = outputBuffer.split(/\r?\n/);
                            if (lines.length > 1) {
                                const lastLine = lines[lines.length - 1].trim();
                                if (lastLine.endsWith("#") || lastLine.endsWith(">") || lastLine.endsWith("]")) {
                                    hasPromptReturned = true;
                                    clearTimeout(timeoutId);
                                    runPortScans();
                                }
                            }
                        }
                    } else if (msg.type === "error") {
                        cleanup();
                        reject(new Error(msg.data));
                    }
                } catch (e) {
                    // Ignore
                }
            };
            
            ws.onerror = () => {
                cleanup();
                reject(new Error("WebSocket connection error"));
            };
            
            ws.onclose = () => {
                cleanup();
                if (!hasPromptReturned) {
                    reject(new Error("WebSocket closed prematurely during connection"));
                }
            };
            
            async function runPortScans() {
                const activeDevName = router.name;
                const connections = (appState.nms && appState.nms.connections) || [];
                const portsToTest = [];
                connections.forEach(conn => {
                    if (conn.source === activeDevName) {
                        portsToTest.push({
                            target: conn.target,
                            port: conn.source_interface,
                            connectionId: conn.id
                        });
                    } else if (conn.target === activeDevName) {
                        portsToTest.push({
                            target: conn.source,
                            port: conn.target_interface,
                            connectionId: conn.id
                        });
                    }
                });
                
                const uniquePorts = [];
                const seenPorts = new Set();
                portsToTest.forEach(p => {
                    if (!seenPorts.has(p.port)) {
                        seenPorts.add(p.port);
                        uniquePorts.push(p);
                    }
                });
                
                if (uniquePorts.length === 0) {
                    cleanup();
                    resolve([]);
                    return;
                }
                
                const results = [];
                
                function execCmd(commandText, commandTimeout = 8000) {
                    return new Promise((resolveCmd, rejectCmd) => {
                        let cmdBuffer = "";
                        let cmdTimeoutId = setTimeout(() => {
                            ws.removeEventListener("message", handleCmdMsg);
                            rejectCmd(new Error("Port query timed out"));
                        }, commandTimeout);
                        
                        const handleCmdMsg = (e) => {
                            try {
                                const msg = JSON.parse(e.data);
                                if (msg.type === "output") {
                                    cmdBuffer += msg.data;
                                    const lowerChunk = msg.data.toLowerCase();
                                    if (lowerChunk.includes("{ <cr>") || lowerChunk.includes("---- more ----") || lowerChunk.includes("--more--")) {
                                        ws.send(JSON.stringify({ type: "input", data: "\n" }));
                                    }
                                    const lines = cmdBuffer.split(/\r?\n/);
                                    if (lines.length > 1) {
                                        const lastLine = lines[lines.length - 1].trim();
                                        if ((lastLine.endsWith("#") || lastLine.endsWith(">") || lastLine.endsWith("]")) && !lastLine.includes("{ <cr>")) {
                                            clearTimeout(cmdTimeoutId);
                                            ws.removeEventListener("message", handleCmdMsg);
                                            resolveCmd(cmdBuffer);
                                        }
                                    }
                                } else if (msg.type === "error") {
                                    clearTimeout(cmdTimeoutId);
                                    ws.removeEventListener("message", handleCmdMsg);
                                    rejectCmd(new Error(msg.data));
                                }
                            } catch (err) {
                                // Ignore
                            }
                        };
                        
                        ws.addEventListener("message", handleCmdMsg);
                        ws.send(JSON.stringify({ type: "input", data: commandText + "\n" }));
                    });
                }
                
                try {
                    for (let idx = 0; idx < uniquePorts.length; idx++) {
                        if (consoleState.scanStopped) {
                            break;
                        }
                        while (consoleState.scanPaused && !consoleState.scanStopped) {
                            await new Promise(r => setTimeout(r, 200));
                        }
                        if (consoleState.scanStopped) {
                            break;
                        }
                        
                        const task = uniquePorts[idx];
                        onProgress(task, idx, uniquePorts.length, "scanning");
                        
                        try {
                            // Execute command with a 500ms prompt buffer delay to ensure target stability
                            await new Promise(r => setTimeout(r, 500));
                            const parsed = await queryPortOpticalPower(router, task.port, execCmd);
                            if (parsed) {
                                onProgress(task, idx, uniquePorts.length, "success", parsed);
                                results.push({ task, parsed, success: true });
                            } else {
                                onProgress(task, idx, uniquePorts.length, "unsupported");
                                results.push({ task, success: false, reason: "Unsupported or DDM disabled" });
                            }
                        } catch (err) {
                            onProgress(task, idx, uniquePorts.length, "failed", err.message);
                            results.push({ task, success: false, reason: err.message });
                        }
                    }
                } catch (loopErr) {
                    // Ignore
                } finally {
                    cleanup();
                    resolve(results);
                }
            }
        });
    }

    const scanControls = document.getElementById("console-scan-controls");
    const pauseBtn = document.getElementById("console-scan-pause-btn");
    const stopBtn = document.getElementById("console-scan-stop-btn");
    
    if (pauseBtn && !pauseBtn.dataset.listenerBound) {
        pauseBtn.dataset.listenerBound = "true";
        pauseBtn.addEventListener("click", () => {
            consoleState.scanPaused = !consoleState.scanPaused;
            const pauseText = document.getElementById("console-scan-pause-text");
            if (consoleState.scanPaused) {
                if (pauseText) pauseText.innerText = "Resume";
                pauseBtn.innerHTML = '<i class="fa-solid fa-play"></i> <span id="console-scan-pause-text">Resume</span>';
                pauseBtn.style.background = "rgba(16, 185, 129, 0.15)";
                pauseBtn.style.color = "#10b981";
                pauseBtn.style.borderColor = "rgba(16, 185, 129, 0.4)";
                appendTerminalLine("\n[Diagnostics: Scan paused by user.]", "#f59e0b");
            } else {
                if (pauseText) pauseText.innerText = "Pause";
                pauseBtn.innerHTML = '<i class="fa-solid fa-pause"></i> <span id="console-scan-pause-text">Pause</span>';
                pauseBtn.style.background = "rgba(245, 158, 11, 0.15)";
                pauseBtn.style.color = "#f59e0b";
                pauseBtn.style.borderColor = "rgba(245, 158, 11, 0.4)";
                appendTerminalLine("\n[Diagnostics: Scan resumed by user.]", "#10b981");
            }
        });
    }
    
    if (stopBtn && !stopBtn.dataset.listenerBound) {
        stopBtn.dataset.listenerBound = "true";
        stopBtn.addEventListener("click", () => {
            consoleState.scanStopped = true;
            appendTerminalLine("\n[Diagnostics: Stopping scan...]", "var(--danger)");
            if (scanControls) scanControls.classList.add("hidden");
        });
    }

    const diagnoseAllBtn = document.getElementById("console-diagnose-all-btn");
    const diagnoseAllOltsBtn = document.getElementById("console-diagnose-all-olts-btn");

    async function runBulkOpticalScan(targetDeviceType = "Router") {
        if (!consoleState.jumpboxConnected || !consoleState.jumpboxAuth) {
            alert("Please connect to a Jumpbox gateway first.");
            return;
        }

        const isOltScan = targetDeviceType.toUpperCase() === "OLT";
        const labelPlural = isOltScan ? "OLTs" : "routers";
        const labelSingular = isOltScan ? "OLT" : "router";

        const jbAuth = consoleState.jumpboxAuth;
        const devUser = document.getElementById("console-ssh-dev-user").value || "admin";
        const devPass = document.getElementById("console-ssh-dev-pass").value || "";

        // Warn if connected jumpbox type differs from target device type
        if (jbAuth.type && jbAuth.type.toLowerCase() !== targetDeviceType.toLowerCase()) {
            appendTerminalLine(`[Warning: Starting bulk scan for ${labelPlural} while connected to the ${jbAuth.type.toUpperCase()} Jumpbox (${jbAuth.ip}).]`, "#f59e0b");
        }

        const targetDevices = (appState.nms && appState.nms.devices || [])
            .filter(d => (d.type || "").toLowerCase() === targetDeviceType.toLowerCase() && !d.outside_managed);

        if (targetDevices.length === 0) {
            alert(`No ${labelPlural} found in Network Topology to scan.`);
            return;
        }

        // Initialize/Reset scan states
        consoleState.scanRunning = true;
        consoleState.scanPaused = false;
        consoleState.scanStopped = false;

        // Reset Pause Button UI to default "Pause"
        if (pauseBtn) {
            const pauseText = document.getElementById("console-scan-pause-text");
            if (pauseText) pauseText.innerText = "Pause";
            pauseBtn.innerHTML = '<i class="fa-solid fa-pause"></i> <span id="console-scan-pause-text">Pause</span>';
            pauseBtn.style.background = "rgba(245, 158, 11, 0.15)";
            pauseBtn.style.color = "#f59e0b";
            pauseBtn.style.borderColor = "rgba(245, 158, 11, 0.4)";
        }

        // Show control buttons and disable manual controls
        if (scanControls) scanControls.classList.remove("hidden");
        if (diagnoseAllBtn) {
            diagnoseAllBtn.disabled = true;
            if (!isOltScan) diagnoseAllBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Scanning Routers...';
        }
        if (diagnoseAllOltsBtn) {
            diagnoseAllOltsBtn.disabled = true;
            if (isOltScan) diagnoseAllOltsBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Scanning OLTs...';
        }
        if (diagnoseBtn) diagnoseBtn.disabled = true;
        if (terminalInput) terminalInput.disabled = true;

        // Show diagnostics card and clear tbody
        if (diagCard) diagCard.classList.remove("hidden");
        if (diagTbody) diagTbody.innerHTML = "";
        if (diagProgress) diagProgress.innerText = `Preparing serial scan...`;

        appendTerminalLine(`\n[Diagnostics: Starting sequential optical power scan on ${targetDevices.length} ${labelPlural}...]`, isOltScan ? "#c084fc" : "#3b82f6");

        // Calculate total unique ports across all target devices to render placeholders
        const scanQueue = [];
        const connections = (appState.nms && appState.nms.connections) || [];

        targetDevices.forEach(dev => {
            const devPorts = [];
            connections.forEach(conn => {
                if (conn.source === dev.name) {
                    devPorts.push({
                        router: dev,
                        target: conn.target,
                        port: conn.source_interface,
                        connectionId: conn.id
                    });
                } else if (conn.target === dev.name) {
                    devPorts.push({
                        router: dev,
                        target: conn.source,
                        port: conn.target_interface,
                        connectionId: conn.id
                    });
                }
            });

            // Filter unique local ports
            const uniquePorts = [];
            const seen = new Set();
            devPorts.forEach(p => {
                if (!seen.has(p.port)) {
                    seen.add(p.port);
                    uniquePorts.push(p);
                }
            });

            if (uniquePorts.length > 0) {
                scanQueue.push({
                    router: dev,
                    ports: uniquePorts
                });
            }
        });

        const restoreScanButtons = () => {
            consoleState.scanRunning = false;
            consoleState.scanPaused = false;
            consoleState.scanStopped = false;
            if (scanControls) scanControls.classList.add("hidden");
            if (diagnoseAllBtn) {
                diagnoseAllBtn.disabled = false;
                diagnoseAllBtn.innerHTML = '<i class="fa-solid fa-network-wired"></i> Scan All Routers';
            }
            if (diagnoseAllOltsBtn) {
                diagnoseAllOltsBtn.disabled = false;
                diagnoseAllOltsBtn.innerHTML = '<i class="fa-solid fa-server"></i> Scan All OLTs (ZTE / Huawei)';
            }
            if (diagnoseBtn && consoleState.connected) diagnoseBtn.disabled = false;
            if (terminalInput) {
                terminalInput.disabled = false;
                terminalInput.focus();
            }
        };

        if (scanQueue.length === 0) {
            appendTerminalLine(`[Diagnostics: No connection ports found on any of the ${labelPlural}.]`, "#f59e0b");
            alert(`No active ports found on any ${labelPlural} in the Network Topology connections.`);
            restoreScanButtons();
            return;
        }

        // Render placeholders for all ports of all devices in the queue
        let globalPortIdx = 0;
        const portElementsMap = {};

        scanQueue.forEach(sq => {
            sq.ports.forEach(task => {
                const tr = document.createElement("tr");
                const mapKey = `${sq.router.name}-${task.port}`;
                tr.id = `console-diag-all-row-${globalPortIdx}`;
                tr.style.borderBottom = "1px solid rgba(255, 255, 255, 0.05)";
                tr.innerHTML = `
                    <td style="padding: 8px 10px; font-weight: 600; color: var(--text-muted);">${escapeHTML(sq.router.name)}</td>
                    <td style="padding: 8px 10px; font-weight: 600;">${escapeHTML(task.target)}</td>
                    <td style="padding: 8px 10px; font-family: monospace;">${escapeHTML(task.port)}</td>
                    <td colspan="5" style="padding: 8px 10px; text-align: center; color: var(--text-muted);"><i class="fa-solid fa-hourglass-start"></i> Waiting...</td>
                    <td style="padding: 8px 10px; text-align: center;"><span class="badge" style="background: rgba(255,255,255,0.05); color: var(--text-muted);">Queued</span></td>
                `;
                diagTbody.appendChild(tr);
                portElementsMap[mapKey] = tr;
                globalPortIdx++;
            });
        });

        const totalPorts = globalPortIdx;
        let finishedPortsCount = 0;
        const collectedAllResults = [];

        // Loop through each device sequentially
        for (let rIdx = 0; rIdx < scanQueue.length; rIdx++) {
            if (consoleState.scanStopped) {
                break;
            }
            while (consoleState.scanPaused && !consoleState.scanStopped) {
                await new Promise(r => setTimeout(r, 200));
            }
            if (consoleState.scanStopped) {
                break;
            }

            if (rIdx > 0) {
                appendTerminalLine(`[System: Cooling down Jumpbox gateway connection for 3 seconds...]`, "var(--text-muted)");
                await new Promise(r => setTimeout(r, 3000));
            }

            if (consoleState.scanStopped) {
                break;
            }

            const sq = scanQueue[rIdx];
            const modelInfo = `${sq.router.brand || ""} ${sq.router.model || ""}`.trim();
            appendTerminalLine(`\nSSH: Serial Scan - Connecting to ${labelSingular} ${sq.router.name} [${modelInfo}] (${sq.router.ip})...`, "#e2e8f0");

            // Set all ports of this device to "Connecting"
            sq.ports.forEach(task => {
                const mapKey = `${sq.router.name}-${task.port}`;
                const row = portElementsMap[mapKey];
                if (row) {
                    row.innerHTML = `
                        <td style="padding: 8px 10px; font-weight: 600; color: var(--primary);">${escapeHTML(sq.router.name)}</td>
                        <td style="padding: 8px 10px; font-weight: 600;">${escapeHTML(task.target)}</td>
                        <td style="padding: 8px 10px; font-family: monospace;">${escapeHTML(task.port)}</td>
                        <td colspan="5" style="padding: 8px 10px; text-align: center; color: var(--primary);"><i class="fa-solid fa-spinner fa-spin"></i> Connecting to ${escapeHTML(labelSingular)}...</td>
                        <td style="padding: 8px 10px; text-align: center;"><span class="badge" style="background: rgba(59, 130, 246, 0.15); color: var(--primary);">Connecting</span></td>
                    `;
                }
            });

            try {
                await scanSingleRouter(sq.router, jbAuth, devUser, devPass, (task, idx, len, status, extra) => {
                    const mapKey = `${sq.router.name}-${task.port}`;
                    const row = portElementsMap[mapKey];
                    if (!row) return;

                    if (status === "scanning") {
                        row.innerHTML = `
                            <td style="padding: 8px 10px; font-weight: 600; color: var(--primary);">${escapeHTML(sq.router.name)}</td>
                            <td style="padding: 8px 10px; font-weight: 600;">${escapeHTML(task.target)}</td>
                            <td style="padding: 8px 10px; font-family: monospace;">${escapeHTML(task.port)}</td>
                            <td colspan="5" style="padding: 8px 10px; text-align: center; color: var(--primary);"><i class="fa-solid fa-spinner fa-spin"></i> Polling optical diagnostics...</td>
                            <td style="padding: 8px 10px; text-align: center;"><span class="badge" style="background: rgba(59, 130, 246, 0.15); color: var(--primary);">Scanning</span></td>
                        `;
                    } else if (status === "success") {
                        const parsed = extra;
                        const tStatus = getThresholdStatus(parsed.value, parsed.lowAlarm, parsed.lowWarn, parsed.highWarn, parsed.highAlarm);

                        let badgeStyle = "background: rgba(16, 185, 129, 0.15); color: #10b981;";
                        if (tStatus.includes("Warning")) {
                            badgeStyle = "background: rgba(245, 158, 11, 0.15); color: #f59e0b;";
                        } else if (tStatus.includes("Alarm")) {
                            badgeStyle = "background: rgba(239, 68, 68, 0.15); color: #ef4444;";
                        }

                        row.innerHTML = `
                            <td style="padding: 8px 10px; font-weight: 600; color: var(--text-muted);">${escapeHTML(sq.router.name)}</td>
                            <td style="padding: 8px 10px; font-weight: 600;">${escapeHTML(task.target)}</td>
                            <td style="padding: 8px 10px; font-family: monospace;">${escapeHTML(task.port)}</td>
                            <td style="padding: 8px 10px; text-align: right; font-weight: bold; color: ${tStatus.includes("Alarm") ? '#ef4444' : tStatus.includes("Warning") ? '#f59e0b' : '#10b981'}; font-family: monospace;" title="${escapeHTML(parsed.toolTip || '')}">${escapeHTML(parsed.displayText)}</td>
                            <td style="padding: 8px 10px; text-align: right; color: var(--text-muted); font-family: monospace;">${parsed.lowAlarm.toFixed(2)}</td>
                            <td style="padding: 8px 10px; text-align: right; color: var(--text-muted); font-family: monospace;">${parsed.lowWarn.toFixed(2)}</td>
                            <td style="padding: 8px 10px; text-align: right; color: var(--text-muted); font-family: monospace;">${parsed.highWarn.toFixed(2)}</td>
                            <td style="padding: 8px 10px; text-align: right; color: var(--text-muted); font-family: monospace;">${parsed.highAlarm.toFixed(2)}</td>
                            <td style="padding: 8px 10px; text-align: center;"><span class="badge" style="${badgeStyle}">${tStatus}</span></td>
                        `;
                        collectedAllResults.push({
                            router: sq.router.name,
                            target: task.target,
                            port: task.port,
                            status: "success",
                            displayText: parsed.displayText,
                            toolTip: parsed.toolTip || "",
                            value: parsed.value,
                            lowAlarm: parsed.lowAlarm,
                            lowWarn: parsed.lowWarn,
                            highWarn: parsed.highWarn,
                            highAlarm: parsed.highAlarm,
                            thresholdStatus: tStatus
                        });
                        finishedPortsCount++;
                    } else if (status === "unsupported") {
                        row.innerHTML = `
                            <td style="padding: 8px 10px; font-weight: 600; color: var(--text-muted);">${escapeHTML(sq.router.name)}</td>
                            <td style="padding: 8px 10px; font-weight: 600;">${escapeHTML(task.target)}</td>
                            <td style="padding: 8px 10px; font-family: monospace;">${escapeHTML(task.port)}</td>
                            <td colspan="5" style="padding: 8px 10px; text-align: center; color: var(--text-muted);">DDM parameters not supported on port.</td>
                            <td style="padding: 8px 10px; text-align: center;"><span class="badge" style="background: rgba(255, 255, 255, 0.05); color: var(--text-muted);">N/A</span></td>
                        `;
                        collectedAllResults.push({
                            router: sq.router.name,
                            target: task.target,
                            port: task.port,
                            status: "unsupported"
                        });
                        finishedPortsCount++;
                    } else if (status === "failed") {
                        const errorMsg = extra;
                        row.innerHTML = `
                            <td style="padding: 8px 10px; font-weight: 600; color: var(--text-muted);">${escapeHTML(sq.router.name)}</td>
                            <td style="padding: 8px 10px; font-weight: 600;">${escapeHTML(task.target)}</td>
                            <td style="padding: 8px 10px; font-family: monospace;">${escapeHTML(task.port)}</td>
                            <td colspan="5" style="padding: 8px 10px; text-align: center; color: var(--danger); font-family: monospace;">Error: ${escapeHTML(errorMsg)}</td>
                            <td style="padding: 8px 10px; text-align: center;"><span class="badge" style="background: rgba(239, 68, 68, 0.15); color: #ef4444;">Failed</span></td>
                        `;
                        collectedAllResults.push({
                            router: sq.router.name,
                            target: task.target,
                            port: task.port,
                            status: "failed",
                            errorMsg: errorMsg
                        });
                        finishedPortsCount++;
                    }

                    if (diagProgress) {
                        diagProgress.innerText = `Ports: ${finishedPortsCount} / ${totalPorts} complete`;
                    }
                });

                appendTerminalLine(`SSH: Serial Scan - Completed scan for ${labelSingular} ${sq.router.name}.`, "#10b981");
            } catch (routerErr) {
                appendTerminalLine(`SSH: Serial Scan - Failed to connect to ${sq.router.name}: ${routerErr.message}`, "var(--danger)");
                sq.ports.forEach(task => {
                    const mapKey = `${sq.router.name}-${task.port}`;
                    const row = portElementsMap[mapKey];
                    if (row) {
                        row.innerHTML = `
                            <td style="padding: 8px 10px; font-weight: 600; color: var(--text-muted);">${escapeHTML(sq.router.name)}</td>
                            <td style="padding: 8px 10px; font-weight: 600;">${escapeHTML(task.target)}</td>
                            <td style="padding: 8px 10px; font-family: monospace;">${escapeHTML(task.port)}</td>
                            <td colspan="5" style="padding: 8px 10px; text-align: center; color: var(--danger); font-family: monospace;">Device connection failed: ${escapeHTML(routerErr.message)}</td>
                            <td style="padding: 8px 10px; text-align: center;"><span class="badge" style="background: rgba(239, 68, 68, 0.15); color: #ef4444;">Unreachable</span></td>
                        `;
                        collectedAllResults.push({
                            router: sq.router.name,
                            target: task.target,
                            port: task.port,
                            status: "unreachable",
                            errorMsg: routerErr.message
                        });
                        finishedPortsCount++;
                    }
                });

                if (diagProgress) {
                    diagProgress.innerText = `Ports: ${finishedPortsCount} / ${totalPorts} complete`;
                }
            }
        }

        if (consoleState.scanStopped) {
            appendTerminalLine(`\n[Diagnostics: Sequential multi-${labelSingular} optical scan aborted by user.]`, "var(--danger)");
        } else {
            appendTerminalLine(`\n[Diagnostics: Sequential multi-${labelSingular} optical scan finished. Total ports: ${totalPorts}.]`, "#10b981");
        }
        if (collectedAllResults.length > 0) {
            await saveOpticalScanToServer(collectedAllResults, !consoleState.scanStopped);
        }

        restoreScanButtons();
    }

    if (diagnoseAllBtn && !diagnoseAllBtn.dataset.listenerBound) {
        diagnoseAllBtn.addEventListener("click", () => runBulkOpticalScan("Router"));
        diagnoseAllBtn.dataset.listenerBound = "true";
    }

    if (diagnoseAllOltsBtn && !diagnoseAllOltsBtn.dataset.listenerBound) {
        diagnoseAllOltsBtn.addEventListener("click", () => runBulkOpticalScan("OLT"));
        diagnoseAllOltsBtn.dataset.listenerBound = "true";
    }

    // --- Saved Optical Power Scan Persistence & Display ---
    const opticalTimestampEl = document.getElementById("console-optical-timestamp");
    const showSavedScanBtn = document.getElementById("console-show-saved-scan-btn");

    async function saveOpticalScanToServer(resultsArray, replaceAll = false) {
        if (appState.isStaticMode || !resultsArray || resultsArray.length === 0) return;
        try {
            const res = await fetch(`${API_BASE}/console/optical-scan`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ results: resultsArray, replace_all: replaceAll })
            });
            if (res.ok) {
                const data = await res.json();
                await syncNmsOpticalScanData();
                if (opticalTimestampEl && data.updated_at) {
                    opticalTimestampEl.innerText = `Saved: ${data.updated_at}`;
                    opticalTimestampEl.classList.remove("hidden");
                }
                if (showSavedScanBtn) {
                    showSavedScanBtn.classList.remove("hidden");
                }
            }
        } catch (err) {
            console.error("Failed to persist optical scan:", err);
        }
    }

    function renderSavedOpticalScan(scanData) {
        if (!scanData || !Array.isArray(scanData.results) || scanData.results.length === 0) return;
        if (!diagCard || !diagTbody) return;

        diagTbody.innerHTML = "";
        scanData.results.forEach(item => {
            const tr = document.createElement("tr");
            tr.style.borderBottom = "1px solid rgba(255, 255, 255, 0.05)";
            if (item.status === "success") {
                const tStatus = item.thresholdStatus || getThresholdStatus(item.value, item.lowAlarm, item.lowWarn, item.highWarn, item.highAlarm);
                let badgeStyle = "background: rgba(16, 185, 129, 0.15); color: #10b981;";
                if (tStatus.includes("Warning")) {
                    badgeStyle = "background: rgba(245, 158, 11, 0.15); color: #f59e0b;";
                } else if (tStatus.includes("Alarm")) {
                    badgeStyle = "background: rgba(239, 68, 68, 0.15); color: #ef4444;";
                }
                tr.innerHTML = `
                    <td style="padding: 8px 10px; font-weight: 600; color: var(--text-muted);">${escapeHTML(item.router || "-")}</td>
                    <td style="padding: 8px 10px; font-weight: 600;">${escapeHTML(item.target || "-")}</td>
                    <td style="padding: 8px 10px; font-family: monospace;">${escapeHTML(item.port || "-")}</td>
                    <td style="padding: 8px 10px; text-align: right; font-weight: bold; color: ${tStatus.includes("Alarm") ? '#ef4444' : tStatus.includes("Warning") ? '#f59e0b' : '#10b981'}; font-family: monospace;" title="${escapeHTML(item.toolTip || '')}">${escapeHTML(item.displayText || String(item.value ?? "-"))}</td>
                    <td style="padding: 8px 10px; text-align: right; color: var(--text-muted); font-family: monospace;">${Number(item.lowAlarm ?? 0).toFixed(2)}</td>
                    <td style="padding: 8px 10px; text-align: right; color: var(--text-muted); font-family: monospace;">${Number(item.lowWarn ?? 0).toFixed(2)}</td>
                    <td style="padding: 8px 10px; text-align: right; color: var(--text-muted); font-family: monospace;">${Number(item.highWarn ?? 0).toFixed(2)}</td>
                    <td style="padding: 8px 10px; text-align: right; color: var(--text-muted); font-family: monospace;">${Number(item.highAlarm ?? 0).toFixed(2)}</td>
                    <td style="padding: 8px 10px; text-align: center;"><span class="badge" style="${badgeStyle}">${escapeHTML(tStatus)}</span></td>
                `;
            } else if (item.status === "unsupported") {
                tr.innerHTML = `
                    <td style="padding: 8px 10px; font-weight: 600; color: var(--text-muted);">${escapeHTML(item.router || "-")}</td>
                    <td style="padding: 8px 10px; font-weight: 600;">${escapeHTML(item.target || "-")}</td>
                    <td style="padding: 8px 10px; font-family: monospace;">${escapeHTML(item.port || "-")}</td>
                    <td colspan="5" style="padding: 8px 10px; text-align: center; color: var(--text-muted);">DDM parameters not supported on port.</td>
                    <td style="padding: 8px 10px; text-align: center;"><span class="badge" style="background: rgba(255, 255, 255, 0.05); color: var(--text-muted);">N/A</span></td>
                `;
            } else {
                const label = item.status === "unreachable" ? "Unreachable" : "Failed";
                tr.innerHTML = `
                    <td style="padding: 8px 10px; font-weight: 600; color: var(--text-muted);">${escapeHTML(item.router || "-")}</td>
                    <td style="padding: 8px 10px; font-weight: 600;">${escapeHTML(item.target || "-")}</td>
                    <td style="padding: 8px 10px; font-family: monospace;">${escapeHTML(item.port || "-")}</td>
                    <td colspan="5" style="padding: 8px 10px; text-align: center; color: var(--danger); font-family: monospace;">${escapeHTML(item.errorMsg || "Connection failed")}</td>
                    <td style="padding: 8px 10px; text-align: center;"><span class="badge" style="background: rgba(239, 68, 68, 0.15); color: #ef4444;">${label}</span></td>
                `;
            }
            diagTbody.appendChild(tr);
        });

        if (opticalTimestampEl && scanData.updated_at) {
            opticalTimestampEl.innerText = `Last Scan: ${scanData.updated_at}`;
            opticalTimestampEl.classList.remove("hidden");
        }
        if (diagProgress) {
            diagProgress.innerText = `${scanData.results.length} saved ports`;
        }
        diagCard.classList.remove("hidden");
    }

    async function loadSavedOpticalScan(autoOpen = false) {
        try {
            const res = await fetch(`${API_BASE}/console/optical-scan`);
            if (res.ok) {
                const scanData = await res.json();
                if (scanData && Array.isArray(scanData.results) && scanData.results.length > 0) {
                    if (showSavedScanBtn) showSavedScanBtn.classList.remove("hidden");
                    if (autoOpen || appState.isStaticMode) {
                        renderSavedOpticalScan(scanData);
                    }
                } else if (appState.isStaticMode && diagCard && diagTbody) {
                    diagCard.classList.remove("hidden");
                    diagTbody.innerHTML = `
                        <tr>
                            <td colspan="9" style="padding: 36px 20px; text-align: center; color: var(--text-muted); font-size: 0.85rem;">
                                <i class="fa-solid fa-circle-info" style="margin-right: 6px; color: var(--primary);"></i>
                                No optical power scan results have been published yet. Run <strong>Scan All Routers</strong> from the local collector app and click <strong>Publish to GitHub</strong>.
                            </td>
                        </tr>
                    `;
                }
            }
        } catch (err) {
            console.error("Failed to load saved optical scan:", err);
        }
    }

    if (showSavedScanBtn && !showSavedScanBtn.dataset.listenerBound) {
        showSavedScanBtn.addEventListener("click", () => loadSavedOpticalScan(true));
        showSavedScanBtn.dataset.listenerBound = "true";
    }

    await loadSavedOpticalScan(true);
}

function appendTerminalLine(text, color = null) {
    const screen = document.getElementById("console-terminal-screen");
    if (!screen) return;
    
    const div = document.createElement("div");
    if (color) {
        div.style.color = color;
    }
    div.style.whiteSpace = "pre-wrap";
    
    // Support parsing innerHTML directly or escaping it
    if (text.includes("<span")) {
        div.innerHTML = text;
    } else {
        div.innerText = text;
    }
    
    screen.appendChild(div);
    screen.scrollTop = screen.scrollHeight;
}


