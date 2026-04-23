"""
TEA Forensic Collector - HTML Report Generator
Generates a professional, self-contained HTML forensic report.
"""

import json
import datetime
import html


def sanitize(value):
    """Safely convert any value to HTML-safe string."""
    if value is None:
        return '<span class="null">null</span>'
    if isinstance(value, bool):
        return f'<span class="bool">{"true" if value else "false"}</span>'
    if isinstance(value, (int, float)):
        return f'<span class="num">{value}</span>'
    if isinstance(value, dict):
        return format_dict(value)
    if isinstance(value, list):
        return format_list(value)
    text = str(value).strip()
    if not text:
        return '<span class="empty">—</span>'
    return html.escape(text)


def format_dict(d, depth=0):
    if not d:
        return '<span class="empty">{}</span>'
    rows = ""
    for k, v in d.items():
        rows += f'<tr><td class="key">{html.escape(str(k))}</td><td>{sanitize(v)}</td></tr>'
    return f'<table class="inner-table">{rows}</table>'


def format_list(lst, depth=0):
    if not lst:
        return '<span class="empty">[]</span>'
    items = ""
    for item in lst[:200]:  # cap at 200 items
        items += f"<li>{sanitize(item)}</li>"
    extra = f'<li class="more">...and {len(lst)-200} more items</li>' if len(lst) > 200 else ""
    return f'<ul class="data-list">{items}{extra}</ul>'


def parse_json_field(value):
    """Try to parse a JSON string, return original if fails."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except:
            return value
    return value


def render_section(title, icon, data, section_id):
    """Render a collapsible forensic section."""
    content = render_data(data)
    return f"""
<section class="artifact-section" id="{section_id}">
    <div class="section-header" onclick="toggleSection('{section_id}')">
        <div class="section-title">
            <span class="section-icon">{icon}</span>
            <span>{title}</span>
        </div>
        <div class="section-meta">
            <span class="toggle-btn" id="toggle-{section_id}">▼</span>
        </div>
    </div>
    <div class="section-body" id="body-{section_id}">
        {content}
    </div>
</section>
"""


def render_data(data):
    """Recursively render data into HTML."""
    if isinstance(data, dict):
        html_out = ""
        for key, value in data.items():
            parsed = parse_json_field(value)
            html_out += f"""
<div class="data-block">
    <div class="data-key">{html.escape(str(key))}</div>
    <div class="data-value">{render_data(parsed)}</div>
</div>"""
        return html_out
    elif isinstance(data, list):
        if not data:
            return '<span class="empty">No data collected</span>'
        html_out = '<div class="list-container">'
        for i, item in enumerate(data[:500]):
            if isinstance(item, dict):
                html_out += '<div class="list-item">'
                for k, v in item.items():
                    html_out += f'<span class="item-field"><span class="item-key">{html.escape(str(k))}</span>: <span class="item-val">{sanitize(v)}</span></span>'
                html_out += '</div>'
            else:
                html_out += f'<div class="list-item simple">{html.escape(str(item))}</div>'
        if len(data) > 500:
            html_out += f'<div class="list-item more">... {len(data)-500} more records truncated</div>'
        html_out += '</div>'
        return html_out
    elif isinstance(data, str):
        parsed = parse_json_field(data)
        if isinstance(parsed, (dict, list)):
            return render_data(parsed)
        # Multi-line text block
        if '\n' in data and len(data) > 100:
            return f'<pre class="raw-output">{html.escape(data[:10000])}{"..." if len(data)>10000 else ""}</pre>'
        return f'<span class="string-val">{html.escape(str(data))}</span>'
    elif isinstance(data, bool):
        cls = "bool-true" if data else "bool-false"
        return f'<span class="{cls}">{"✓ True" if data else "✗ False"}</span>'
    elif isinstance(data, (int, float)):
        return f'<span class="num-val">{data}</span>'
    elif data is None:
        return '<span class="null-val">—</span>'
    return f'<span>{html.escape(str(data))}</span>'


def generate_html_report(data, output_path):
    """Generate the full HTML forensic report."""

    meta = data.get("meta", {})
    hostname = data.get("system_info", {}).get("hostname", "Unknown")
    username = data.get("system_info", {}).get("username", "Unknown")
    collection_time = meta.get("start_time", datetime.datetime.now().isoformat())
    duration = meta.get("duration_seconds", 0)

    # Determine risk indicators
    indicators = []
    processes = data.get("processes", {})
    network = data.get("network", {})
    registry = data.get("registry", {})

    def _is_valid_result(value):
        """Collector ciktisinin gercek veri icerip icermedigini kontrol eder.
        [ERROR] veya [TIMEOUT] string'leri false positive indicator uretmemeli."""
        s = str(value)
        return bool(value) and value not in ("[]", "null") \
            and "[ERROR]" not in s and "[TIMEOUT]" not in s

    # Check for temp executables
    fs = data.get("filesystem", {})
    temp_exes = fs.get("temp_executables", "")
    if _is_valid_result(temp_exes):
        indicators.append({"level": "HIGH",     "msg": "Executable files detected in TEMP directories", "section": "filesystem"})

    # Check for alternate data streams
    ads = fs.get("ads_detection", "")
    if _is_valid_result(ads):
        indicators.append({"level": "HIGH",     "msg": "Alternate Data Streams (ADS) detected on filesystem", "section": "filesystem"})

    # Suspicious service paths
    susp_services = data.get("tasks_services", {}).get("services_suspicious_paths", "")
    if _is_valid_result(susp_services):
        indicators.append({"level": "MEDIUM",   "msg": "Services with non-standard binary paths detected", "section": "tasks_services"})

    # Son 5 dakikada yazılan dosyalar
    rw = data.get("filesystem", {}).get("recently_written_files", "")
    if rw and rw not in ("[]","{}") and "[ERROR]" not in str(rw) and "[TIMEOUT]" not in str(rw):
        try:
            import json as _j3
            rw_items = _j3.loads(rw) if isinstance(rw, str) else []
            if isinstance(rw_items, dict): rw_items = [rw_items]
            if rw_items:
                indicators.append({"level": "MEDIUM", "msg": f"Active Write: {len(rw_items)} file(s) written in last 5 minutes", "section": "filesystem"})
        except Exception:
            pass

    # Log temizleme tespiti
    log_cleared = data.get("event_logs", {}).get("security_log_cleared", "")
    if _is_valid_result(log_cleared) and log_cleared not in ("[]", "{}"):
        indicators.append({"level": "CRITICAL", "msg": "Event log cleared — possible anti-forensic activity (EID 1102/104)", "section": "event_logs"})

    # Brute force: son 24 saatte çok sayıda başarısız logon
    bf = data.get("event_logs", {}).get("brute_force_summary", "")
    if _is_valid_result(bf) and bf not in ("[]", "{}"):
        try:
            import json as _json
            bf_data = _json.loads(bf) if isinstance(bf, str) else bf
            if isinstance(bf_data, list) and any(int(x.get("FailCount", 0)) > 10 for x in bf_data):
                indicators.append({"level": "HIGH",     "msg": "Brute force suspected: >10 failed logons for same account in 24h", "section": "event_logs"})
        except Exception:
            pass

    # Scheduled task değişikliği
    stc = data.get("event_logs", {}).get("scheduled_task_changes", "")
    if _is_valid_result(stc) and stc not in ("[]", "{}"):
        indicators.append({"level": "MEDIUM",   "msg": "Scheduled task created/modified/deleted (EID 4698-4702)", "section": "event_logs"})

    # Son 30 gün task
    rt_data = data.get("tasks_services", {}).get("recent_tasks_30d", "")
    if rt_data and rt_data not in ("[]", "{}") and "[ERROR]" not in str(rt_data):
        try:
            import json as _j2
            rt_items = _j2.loads(rt_data) if isinstance(rt_data, str) else []
            if isinstance(rt_items, dict): rt_items = [rt_items]
            if rt_items:
                indicators.append({"level": "MEDIUM", "msg": f"Recent Tasks: {len(rt_items)} scheduled task(s) created/modified in last 30 days", "section": "tasks_services"})
        except Exception:
            pass

    # Gizli iframe/subframe ziyaretler
    for bkey in ["chrome_history", "edge_history"]:
        bh = data.get("browsers", {}).get(bkey, {})
        hv = bh.get("hidden_visits", []) if isinstance(bh, dict) else []
        if hv:
            indicators.append({"level": "MEDIUM", "msg": f"Hidden Browser Visits: {len(hv)} iframe/subframe visit(s) in {bkey.split('_')[0].title()}", "section": "browser_history"})

    # Parent-child anomali
    pc_data = data.get("parent_child", {})
    pc_findings = pc_data.get("findings", [])
    critical_pc = [f for f in pc_findings if f.get("severity") == "CRITICAL"]
    if critical_pc:
        indicators.append({"level": "CRITICAL", "msg": f"Parent-Child Anomaly: {len(critical_pc)} Office/browser → shell spawn detected", "section": "parent_child"})
    elif pc_findings:
        indicators.append({"level": "HIGH",     "msg": f"Parent-Child Anomaly: {len(pc_findings)} suspicious process relationship(s)", "section": "parent_child"})

    # İmzasız process
    up_data = data.get("unsigned_processes", {})
    up_findings = up_data.get("findings", [])
    critical_up = [f for f in up_findings if f.get("severity") == "CRITICAL"]
    if critical_up:
        indicators.append({"level": "CRITICAL", "msg": f"Unsigned/Tampered: {len(critical_up)} process(es) with hash mismatch or untrusted signature", "section": "unsigned_processes"})
    elif up_findings:
        indicators.append({"level": "HIGH",     "msg": f"Unsigned Process: {len(up_findings)} unsigned process(es) in suspicious paths", "section": "unsigned_processes"})

    # Network IOC
    nioc_data = data.get("network_ioc", {})
    nioc_matches = nioc_data.get("matches", [])
    if nioc_matches:
        indicators.append({"level": "CRITICAL", "msg": f"Network IOC: {len(nioc_matches)} connection(s) to known malicious IP/domain", "section": "network_ioc"})

    # Hollow process
    hp_data = data.get("hollow_process", {})
    hp_total = hp_data.get("total_findings", 0)
    if hp_total > 0:
        indicators.append({"level": "HIGH",     "msg": f"Hollow Process: {hp_total} suspicious memory/path indicator(s)", "section": "hollow_process"})

    # IOC hash matches
    ioc_data = data.get("ioc_matches", {})
    ioc_matches = ioc_data.get("matches", [])
    if ioc_matches:
        indicators.append({"level": "CRITICAL", "msg": f"IOC Hash Match: {len(ioc_matches)} known malicious file(s) detected", "section": "ioc_matches"})

    # LOLBAS findings
    lolbas_data = data.get("lolbas", {})
    lolbas_findings = lolbas_data.get("findings", [])
    if lolbas_findings:
        indicators.append({"level": "HIGH",     "msg": f"LOLBAS Abuse: {len(lolbas_findings)} suspicious process(es) detected", "section": "lolbas"})

    # Webshell findings
    webshell_data = data.get("webshell", {})
    webshell_findings = webshell_data.get("findings", [])
    if webshell_findings:
        indicators.append({"level": "CRITICAL", "msg": f"Webshell: {len(webshell_findings)} suspicious web file(s) detected", "section": "webshell"})

    # VirusTotal findings
    vt_data = data.get("virustotal", {})
    vt_findings = vt_data.get("findings", [])
    if vt_findings:
        mal = sum(1 for f in vt_findings if f.get("verdict") == "MALICIOUS")
        sus = sum(1 for f in vt_findings if f.get("verdict") == "SUSPICIOUS")
        if mal > 0:
            indicators.append({"level": "CRITICAL", "msg": f"VirusTotal: {mal} MALICIOUS file(s) confirmed", "section": "virustotal"})
        if sus > 0:
            indicators.append({"level": "HIGH",     "msg": f"VirusTotal: {sus} SUSPICIOUS file(s) flagged", "section": "virustotal"})

    # YARA findings
    yara_data = data.get("yara", {})
    yara_findings = yara_data.get("findings", [])
    if yara_findings:
        indicators.append({"level": "HIGH",     "msg": f"YARA: {len(yara_findings)} file(s) matched malware rules", "section": "yara"})

    # Summary stats
    sections = [
        ("system_info",   "System Information",          "🖥"),
        ("processes",     "Process List",                 "⚙"),
        ("network",       "Network Connections",          "🌐"),
        ("registry",      "Registry Persistence",         "🔑"),
        ("event_logs",    "Event Logs",                   "📋"),
        ("filesystem",    "Filesystem Artifacts",         "📁"),
        ("active_files",  "Active Files (last 5min)",     "✍"),
        ("browsers",      "Browser Artifacts",            "🌍"),
        ("browser_history","Browser History",               "🔍"),
        ("tasks_services","Scheduled Tasks & Services",   "⏱"),
        ("recent_tasks",   "Recent Tasks (30d)",            "🆕"),
        ("memory",        "Memory Information",           "💾"),
        ("users",         "User Accounts",                "👤"),
        ("ioc_matches",   "IOC Hash Matches",             "☠"),
        ("lolbas",        "LOLBAS Detection",             "🎯"),
        ("webshell",      "Webshell Scan",                "🕷"),
        ("yara",          "YARA Scan",                    "🔬"),
        ("virustotal",    "VirusTotal Reputation",        "🛡"),
        ("parent_child",   "Parent-Child Anomalies",       "🌲"),
        ("unsigned_processes", "Unsigned Processes",       "🔓"),
        ("network_ioc",    "Network IOC Matches",          "🕸"),
        ("hollow_process", "Hollow Process Detection",     "👻"),
    ]

    # Nav items
    nav_html = ""
    for key, title, icon in sections:
        nav_html += f"""
<a href="#{key}" class="nav-item" onclick="scrollToSection('{key}')">
    <span class="nav-icon">{icon}</span>
    <span class="nav-label">{title}</span>
</a>"""

    # Indicator badges
    ind_html = ""
    if not indicators:
        ind_html = '<div class="indicator clear">✓ No automated indicators triggered</div>'
    for i, ind in enumerate(indicators):
        lvl_cls   = "critical" if ind["level"] == "CRITICAL" else ("high" if ind["level"] == "HIGH" else "medium")
        section   = ind.get("section", "")
        click_attr= f'onclick="jumpToIndicator(\'{section}\');"' if section else ""
        cursor    = "cursor:pointer;" if section else ""
        arrow     = " ↗" if section else ""
        title_txt = f"Click to jump to {section} section" if section else ""
        ind_html += (
            f'<div class="indicator {lvl_cls}" {click_attr} style="{cursor}" title="{title_txt}">'
            f'<span class="ind-level">{ind["level"]}</span> {ind["msg"]}{arrow}</div>'
        )

    # Section bodies
    sections_html = ""
    for key, title, icon in sections:
        sections_html += render_section(title, icon, data.get(key, {}), key)

    # Full HTML
    report = f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TEA Forensic Report — {html.escape(hostname)}</title>
<style>
/* Fonts: CDN kullanilmiyor — forensic ortamlarda network izolasyonu olabilir.
   System font stack: monospace ve sans-serif fallback zinciri kullanilir. */

:root {{
    --bg: #0a0c0f;
    --bg2: #0f1318;
    --bg3: #141a22;
    --bg4: #1a2230;
    --border: #1e2d3d;
    --border2: #243447;
    --accent: #00d4ff;
    --accent2: #0099bb;
    --accent3: #005577;
    --red: #ff4757;
    --orange: #ffa502;
    --green: #2ed573;
    --text: #c8d8e8;
    --text2: #7a9ab5;
    --text3: #4a6a85;
    --high: #ff4757;
    --medium: #ffa502;
    --low: #2ed573;
    --font-mono: 'Cascadia Code', 'Consolas', 'Courier New', monospace;
    --font-ui: 'Segoe UI', 'Arial', sans-serif;
}}

* {{ margin: 0; padding: 0; box-sizing: border-box; }}

body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-mono);
    font-size: 12px;
    line-height: 1.6;
    display: flex;
    min-height: 100vh;
}}

/* SIDEBAR */
.sidebar {{
    width: 220px;
    min-width: 220px;
    background: var(--bg2);
    border-right: 1px solid var(--border);
    position: fixed;
    top: 0; left: 0; bottom: 0;
    overflow-y: auto;
    z-index: 100;
    display: flex;
    flex-direction: column;
}}

.sidebar-logo {{
    padding: 20px 16px;
    border-bottom: 1px solid var(--border);
}}

.logo-text {{
    font-family: var(--font-ui);
    font-weight: 800;
    font-size: 16px;
    color: var(--accent);
    letter-spacing: -0.5px;
}}

.logo-sub {{
    font-size: 9px;
    color: var(--text3);
    text-transform: uppercase;
    letter-spacing: 2px;
    margin-top: 2px;
}}

.nav-section {{
    padding: 12px 0;
    flex: 1;
}}

.nav-item {{
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 16px;
    cursor: pointer;
    color: var(--text2);
    text-decoration: none;
    font-size: 11px;
    transition: all 0.15s;
    border-left: 2px solid transparent;
}}

.nav-item:hover {{
    background: var(--bg3);
    color: var(--accent);
    border-left-color: var(--accent);
}}

.nav-icon {{ font-size: 14px; min-width: 20px; }}
.nav-label {{ font-family: var(--font-ui); font-size: 11px; font-weight: 600; }}

.sidebar-footer {{
    padding: 12px 16px;
    border-top: 1px solid var(--border);
    font-size: 9px;
    color: var(--text3);
}}

/* MAIN CONTENT */
.main {{
    margin-left: 220px;
    flex: 1;
    display: flex;
    flex-direction: column;
}}

/* HEADER */
.report-header {{
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    padding: 24px 32px;
    position: sticky;
    top: 0;
    z-index: 50;
}}

.header-top {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 16px;
}}

.report-title {{
    font-family: var(--font-ui);
    font-weight: 800;
    font-size: 22px;
    color: #fff;
    letter-spacing: -0.5px;
}}

.report-subtitle {{
    font-size: 11px;
    color: var(--text3);
    margin-top: 4px;
    font-family: var(--font-mono);
}}

.report-badge {{
    background: var(--accent3);
    border: 1px solid var(--accent);
    color: var(--accent);
    padding: 4px 12px;
    font-size: 10px;
    font-family: var(--font-ui);
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
}}

.meta-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
    margin-bottom: 16px;
}}

.meta-card {{
    background: var(--bg3);
    border: 1px solid var(--border);
    padding: 10px 14px;
}}

.meta-label {{
    font-size: 9px;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--text3);
    margin-bottom: 4px;
    font-family: var(--font-ui);
}}

.meta-value {{
    font-size: 13px;
    color: var(--accent);
    font-weight: 500;
}}

/* INDICATORS */
.indicators {{
    padding: 0 32px 16px;
    border-bottom: 1px solid var(--border);
    background: var(--bg2);
}}

.indicators-title {{
    font-family: var(--font-ui);
    font-size: 11px;
    font-weight: 700;
    color: var(--text3);
    text-transform: uppercase;
    letter-spacing: 1.5px;
    margin-bottom: 8px;
}}

.indicator {{
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 5px 12px;
    margin: 3px 4px 3px 0;
    font-size: 11px;
    border: 1px solid;
}}

.indicator.high {{ background: rgba(255,71,87,0.1); border-color: var(--red); color: var(--red); }}
.indicator.medium {{ background: rgba(255,165,2,0.1); border-color: var(--orange); color: var(--orange); }}
.indicator.clear {{ background: rgba(46,213,115,0.1); border-color: var(--green); color: var(--green); }}

.ind-level {{
    font-family: var(--font-ui);
    font-weight: 700;
    font-size: 9px;
    letter-spacing: 1px;
    background: currentColor;
    color: var(--bg);
    padding: 1px 5px;
}}

/* CONTENT AREA */
.content {{
    padding: 24px 32px;
    flex: 1;
}}

/* SECTIONS */
.artifact-section {{
    margin-bottom: 12px;
    border: 1px solid var(--border);
    background: var(--bg2);
}}

.section-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 16px;
    cursor: pointer;
    background: var(--bg3);
    border-bottom: 1px solid transparent;
    transition: all 0.15s;
    user-select: none;
}}

.section-header:hover {{
    background: var(--bg4);
    border-bottom-color: var(--border);
}}

.section-title {{
    display: flex;
    align-items: center;
    gap: 10px;
    font-family: var(--font-ui);
    font-weight: 700;
    font-size: 13px;
    color: #fff;
}}

.section-icon {{ font-size: 16px; }}

.toggle-btn {{
    color: var(--accent);
    font-size: 12px;
    transition: transform 0.2s;
}}

.section-body {{
    padding: 16px;
    overflow-x: auto;
}}

.section-body.collapsed {{
    display: none;
}}

/* DATA RENDERING */
.data-block {{
    margin-bottom: 12px;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--border);
}}

.data-block:last-child {{
    border-bottom: none;
    margin-bottom: 0;
}}

.data-key {{
    font-family: var(--font-ui);
    font-weight: 700;
    font-size: 11px;
    color: var(--accent);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 6px;
}}

.data-value {{
    color: var(--text);
}}

.raw-output {{
    background: var(--bg);
    border: 1px solid var(--border);
    padding: 12px;
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--text2);
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 300px;
    overflow-y: auto;
    line-height: 1.5;
}}

.list-container {{
    display: flex;
    flex-direction: column;
    gap: 4px;
}}

.list-item {{
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 10px 14px;
    font-size: 11px;
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 6px 16px;
    margin-bottom: 4px;
}}

.list-item.simple {{ color: var(--text2); display: block; }}
.list-item.more {{ color: var(--text3); font-style: italic; display: flex; justify-content: center; }}

.item-field {{
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
}}
.item-key {{
    color: var(--accent2);
    font-weight: 600;
    font-size: 9px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}
.item-val {{
    color: var(--text);
    word-break: break-word;
    overflow-wrap: anywhere;
    white-space: pre-wrap;
}}

.string-val {{ color: var(--text); }}
.num-val {{ color: #a8dadc; }}
.null-val {{ color: var(--text3); font-style: italic; }}
.bool-true {{ color: var(--green); }}
.bool-false {{ color: var(--red); }}
.empty {{ color: var(--text3); font-style: italic; }}

/* SCROLLBAR */
::-webkit-scrollbar {{ width: 6px; height: 6px; }}
::-webkit-scrollbar-track {{ background: var(--bg2); }}
::-webkit-scrollbar-thumb {{ background: var(--border2); }}
::-webkit-scrollbar-thumb:hover {{ background: var(--accent3); }}

/* SEARCH */
.search-bar {{
    padding: 0 32px 16px;
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
}}

.search-input {{
    width: 100%;
    max-width: 500px;
    background: var(--bg3);
    border: 1px solid var(--border2);
    color: var(--text);
    font-family: var(--font-mono);
    font-size: 11px;
    padding: 8px 14px;
    outline: none;
    transition: border-color 0.2s;
}}

.search-input:focus {{ border-color: var(--accent); }}
.search-input::placeholder {{ color: var(--text3); }}

/* PRINT */
@media print {{
    .sidebar {{ display: none; }}
    .main {{ margin-left: 0; }}
    .section-body.collapsed {{ display: block !important; }}
    .section-header {{ cursor: default; }}
}}
</style>
</head>
<body>

<nav class="sidebar">
    <div class="sidebar-logo">
        <div class="logo-text">TEA</div>
        <div class="logo-sub">Forensic Collector</div>
    </div>
    <div class="nav-section">
        {nav_html}
    </div>
    <div class="sidebar-footer">
        v1.0.0 · TEA Security<br>
        {datetime.datetime.now().strftime('%Y-%m-%d')}
    </div>
</nav>

<div class="main">
    <header class="report-header">
        <div class="header-top">
            <div>
                <div class="report-title">Forensic Acquisition Report</div>
                <div class="report-subtitle">Generated by TEA Forensic Collector · {html.escape(collection_time)}</div>
            </div>
            <div class="report-badge">CONFIDENTIAL</div>
        </div>
        <div class="meta-grid">
            <div class="meta-card">
                <div class="meta-label">Hostname</div>
                <div class="meta-value">{html.escape(hostname)}</div>
            </div>
            <div class="meta-card">
                <div class="meta-label">User</div>
                <div class="meta-value">{html.escape(username)}</div>
            </div>
            <div class="meta-card">
                <div class="meta-label">Collection Time</div>
                <div class="meta-value">{html.escape(collection_time[:19])}</div>
            </div>
            <div class="meta-card">
                <div class="meta-label">Duration</div>
                <div class="meta-value">{duration}s</div>
            </div>
            <div class="meta-card">
                <div class="meta-label">Platform</div>
                <div class="meta-value">{html.escape(meta.get("platform", "Windows"))}</div>
            </div>
            <div class="meta-card">
                <div class="meta-label">Indicators</div>
                <div class="meta-value" style="color:{'var(--red)' if indicators else 'var(--green)'}">
                    {"⚠ " + str(len(indicators)) + " triggered" if indicators else "✓ Clear"}
                </div>
            </div>
        </div>
    </header>

    <div class="indicators">
        <div class="indicators-title">🔍 Automated Indicators</div>
        {ind_html}
    </div>

    <div class="search-bar">
        <input type="text" class="search-input" id="searchInput"
            placeholder="Search within report... (Ctrl+F)" 
            oninput="searchReport(this.value)">
    </div>

    <div class="content" id="reportContent">
        {sections_html}
    </div>
</div>

<script>
function jumpToIndicator(sectionId) {{
    if (!sectionId) return;
    const el = document.getElementById(sectionId);
    if (!el) return;
    const body = document.getElementById('body-' + sectionId);
    const toggle = document.getElementById('toggle-' + sectionId);
    if (body && body.classList.contains('collapsed')) {{
        body.classList.remove('collapsed');
        if (toggle) toggle.style.transform = 'rotate(0deg)';
    }}
    setTimeout(() => {{
        el.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
        el.style.transition = 'box-shadow 0.3s ease, border-color 0.3s ease';
        el.style.boxShadow  = '0 0 0 2px #00d4ff, 0 0 20px rgba(0,212,255,0.4)';
        el.style.borderColor = '#00d4ff';
        setTimeout(() => {{
            el.style.boxShadow  = '';
            el.style.borderColor = '';
        }}, 2500);
    }}, 100);
}}

function toggleSection(id) {{
    const body = document.getElementById('body-' + id);
    const toggle = document.getElementById('toggle-' + id);
    if (body.classList.contains('collapsed')) {{
        body.classList.remove('collapsed');
        toggle.style.transform = 'rotate(0deg)';
    }} else {{
        body.classList.add('collapsed');
        toggle.style.transform = 'rotate(-90deg)';
    }}
}}

function scrollToSection(id) {{
    const el = document.getElementById(id);
    if (el) {{
        const body = document.getElementById('body-' + id);
        if (body.classList.contains('collapsed')) {{
            toggleSection(id);
        }}
        el.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
    }}
}}

function searchReport(query) {{
    if (!query || query.length < 2) {{
        document.querySelectorAll('.data-block').forEach(el => el.style.display = '');
        return;
    }}
    const lower = query.toLowerCase();
    document.querySelectorAll('.data-block').forEach(el => {{
        const text = el.textContent.toLowerCase();
        el.style.display = text.includes(lower) ? '' : 'none';
    }});
}}

// Keyboard shortcut
document.addEventListener('keydown', (e) => {{
    if (e.ctrlKey && e.key === 'f') {{
        e.preventDefault();
        document.getElementById('searchInput').focus();
    }}
    if (e.key === 'Escape') {{
        document.getElementById('searchInput').value = '';
        searchReport('');
    }}
}});

// Collapse all sections by default except system info
document.addEventListener('DOMContentLoaded', () => {{
    ['processes','network','registry','event_logs','filesystem','browsers','tasks_services','memory','users','browser_history','recent_tasks','active_files','ioc_matches','lolbas','webshell','yara','virustotal','parent_child','unsigned_processes','network_ioc','hollow_process'].forEach(id => {{
        const body = document.getElementById('body-' + id);
        const toggle = document.getElementById('toggle-' + id);
        if(body) {{
            body.classList.add('collapsed');
            if(toggle) toggle.style.transform = 'rotate(-90deg)';
        }}
    }});
}});
</script>
</body>
</html>"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report)

    return output_path
