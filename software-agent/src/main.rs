use reqwest::blocking::Client;
use serde::Serialize;
#[cfg(target_os = "windows")]
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fs;
use std::net::{IpAddr, UdpSocket};
use std::process::Command;

#[derive(Debug, Clone, Serialize)]
struct SoftwareEntry {
    name: String,
    version: String,
}

#[derive(Debug, Serialize)]
struct AgentPayload {
    host_ip: String,
    software: Vec<SoftwareEntry>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let config_path = env::var("SOFTWARE_AGENT_CONFIG")
        .unwrap_or_else(|_| "/etc/cve3po-agent/agent.env".to_string());
    let file_config = load_env_file(&config_path)?;

    let api_url = get_required_setting("SOFTWARE_API_URL", &file_config)?;
    let host_ip = get_setting("HOST_IP", &file_config)
        .unwrap_or_else(|| detect_host_ip().unwrap_or_else(|_| "127.0.0.1".to_string()));
    let token = get_setting("SOFTWARE_API_BEARER_TOKEN", &file_config)
        .or_else(|| get_setting("SOFTWARE_API_KEY", &file_config));
    let auth_mode = get_setting("SOFTWARE_API_AUTH", &file_config).unwrap_or_else(|| "bearer".to_string());
    let dry_run = get_setting("DRY_RUN", &file_config)
        .map(|v| v.eq_ignore_ascii_case("1") || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let software = collect_software()?;
    let payload = AgentPayload { host_ip, software };

    if dry_run {
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    let client = Client::new();
    let mut request = client.post(api_url).json(&payload);
    if let Some(token_value) = token {
        if auth_mode.eq_ignore_ascii_case("x-api-key") {
            request = request.header("X-API-KEY", token_value);
        } else {
            request = request.header("Authorization", format!("Bearer {}", token_value));
        }
    }

    let response = request.send()?;
    if !response.status().is_success() {
        return Err(format!("API returned non-success status: {}", response.status()).into());
    }

    println!("Sent {} software entries.", payload.software.len());
    Ok(())
}

fn get_setting(key: &str, file_config: &HashMap<String, String>) -> Option<String> {
    env::var(key).ok().or_else(|| file_config.get(key).cloned())
}

fn get_required_setting(
    key: &str,
    file_config: &HashMap<String, String>,
) -> Result<String, Box<dyn Error>> {
    get_setting(key, file_config)
        .ok_or_else(|| format!("Missing required setting: {}", key).into())
}

fn load_env_file(path: &str) -> Result<HashMap<String, String>, Box<dyn Error>> {
    let mut map = HashMap::new();
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(map),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!(
                "Warning: cannot read config file '{}': {}. Falling back to process environment.",
                path, err
            );
            return Ok(map);
        }
        Err(err) => return Err(err.into()),
    };

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            let key = k.trim().to_string();
            let mut value = v.trim().to_string();
            if value.len() >= 2
                && ((value.starts_with('"') && value.ends_with('"'))
                    || (value.starts_with('\'') && value.ends_with('\'')))
            {
                value = value[1..value.len() - 1].to_string();
            }
            map.insert(key, value);
        }
    }

    Ok(map)
}

fn detect_host_ip() -> Result<String, Box<dyn Error>> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    let local_addr = socket.local_addr()?;
    match local_addr.ip() {
        IpAddr::V4(ip) => Ok(ip.to_string()),
        IpAddr::V6(ip) => Ok(ip.to_string()),
    }
}

fn collect_software() -> Result<Vec<SoftwareEntry>, Box<dyn Error>> {
    let mut entries = Vec::new();

    #[cfg(target_os = "windows")]
    {
        entries.extend(collect_with_windows_registry()?);
    }

    #[cfg(not(target_os = "windows"))]
    {
        entries.extend(collect_with_dpkg()?);
        entries.extend(collect_with_rpm()?);
        entries.extend(collect_with_apk()?);
        entries.extend(collect_with_pacman()?);
        entries.extend(collect_with_snap()?);
        entries.extend(collect_with_flatpak()?);
    }

    Ok(dedup(entries))
}

fn dedup(entries: Vec<SoftwareEntry>) -> Vec<SoftwareEntry> {
    let mut map: HashMap<String, String> = HashMap::new();
    for e in entries {
        map.entry(e.name).or_insert(e.version);
    }
    let mut out: Vec<SoftwareEntry> = map
        .into_iter()
        .map(|(name, version)| SoftwareEntry { name, version })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

#[cfg(target_os = "windows")]
fn has_cmd(name: &str) -> bool {
    Command::new("where")
        .arg(name)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(not(target_os = "windows"))]
fn has_cmd(name: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {} >/dev/null 2>&1", name))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn run_shell(command: &str) -> Result<String, Box<dyn Error>> {
    let output = Command::new("cmd").arg("/C").arg(command).output()?;
    if !output.status.success() {
        return Err(format!("Command failed: {}", command).into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

#[cfg(not(target_os = "windows"))]
fn run_shell(command: &str) -> Result<String, Box<dyn Error>> {
    let output = Command::new("sh").arg("-c").arg(command).output()?;
    if !output.status.success() {
        return Err(format!("Command failed: {}", command).into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn parse_tab_separated(lines: &str) -> Vec<SoftwareEntry> {
    lines
        .lines()
        .filter_map(|line| {
            let mut parts = line.split('\t');
            let name = parts.next()?.trim();
            let version = parts.next()?.trim();
            if name.is_empty() || version.is_empty() {
                return None;
            }
            Some(SoftwareEntry {
                name: name.to_string(),
                version: version.to_string(),
            })
        })
        .collect()
}

#[cfg(target_os = "windows")]
fn collect_with_windows_registry() -> Result<Vec<SoftwareEntry>, Box<dyn Error>> {
    if !has_cmd("powershell") {
        return Ok(Vec::new());
    }

    let script = r#"
$paths=@(
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
);
$items=Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -and $_.DisplayVersion } |
  Select-Object @{Name='name';Expression={$_.DisplayName}}, @{Name='version';Expression={$_.DisplayVersion}};
$items | ConvertTo-Json -Compress
"#;

    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .output()?;
    if !output.status.success() {
        return Err("Failed to enumerate Windows software via PowerShell".into());
    }

    let stdout = String::from_utf8(output.stdout)?;
    let trimmed = stdout.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Ok(Vec::new());
    }

    let value: Value = serde_json::from_str(trimmed)?;
    let mut entries = Vec::new();

    match value {
        Value::Array(items) => {
            for item in items {
                if let Some(entry) = parse_windows_entry(&item) {
                    entries.push(entry);
                }
            }
        }
        Value::Object(_) => {
            if let Some(entry) = parse_windows_entry(&value) {
                entries.push(entry);
            }
        }
        _ => {}
    }

    Ok(entries)
}

#[cfg(target_os = "windows")]
fn parse_windows_entry(value: &Value) -> Option<SoftwareEntry> {
    let name = value.get("name")?.as_str()?.trim();
    let version = value.get("version")?.as_str()?.trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some(SoftwareEntry {
        name: name.to_string(),
        version: version.to_string(),
    })
}

#[cfg(not(target_os = "windows"))]
fn collect_with_dpkg() -> Result<Vec<SoftwareEntry>, Box<dyn Error>> {
    if !has_cmd("dpkg-query") {
        return Ok(Vec::new());
    }
    let out = run_shell(r#"dpkg-query -W -f='${Package}\t${Version}\n'"#)?;
    Ok(parse_tab_separated(&out))
}

#[cfg(not(target_os = "windows"))]
fn collect_with_rpm() -> Result<Vec<SoftwareEntry>, Box<dyn Error>> {
    if !has_cmd("rpm") {
        return Ok(Vec::new());
    }
    let out = run_shell(r#"rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n'"#)?;
    Ok(parse_tab_separated(&out))
}

#[cfg(not(target_os = "windows"))]
fn collect_with_apk() -> Result<Vec<SoftwareEntry>, Box<dyn Error>> {
    if !has_cmd("apk") {
        return Ok(Vec::new());
    }
    let out = run_shell("apk info -v")?;
    let entries = out
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }
            let idx = trimmed.rfind('-')?;
            let (name, version_part) = trimmed.split_at(idx);
            let version = version_part.trim_start_matches('-');
            if name.is_empty() || version.is_empty() {
                return None;
            }
            Some(SoftwareEntry {
                name: name.to_string(),
                version: version.to_string(),
            })
        })
        .collect();
    Ok(entries)
}

#[cfg(not(target_os = "windows"))]
fn collect_with_pacman() -> Result<Vec<SoftwareEntry>, Box<dyn Error>> {
    if !has_cmd("pacman") {
        return Ok(Vec::new());
    }
    let out = run_shell("pacman -Q")?;
    let entries = out
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let name = parts.next()?;
            let version = parts.next()?;
            Some(SoftwareEntry {
                name: name.to_string(),
                version: version.to_string(),
            })
        })
        .collect();
    Ok(entries)
}

#[cfg(not(target_os = "windows"))]
fn collect_with_snap() -> Result<Vec<SoftwareEntry>, Box<dyn Error>> {
    if !has_cmd("snap") {
        return Ok(Vec::new());
    }
    let out = run_shell("snap list --unicode=never")?;
    let entries = out
        .lines()
        .skip(1)
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 2 {
                return None;
            }
            Some(SoftwareEntry {
                name: cols[0].to_string(),
                version: cols[1].to_string(),
            })
        })
        .collect();
    Ok(entries)
}

#[cfg(not(target_os = "windows"))]
fn collect_with_flatpak() -> Result<Vec<SoftwareEntry>, Box<dyn Error>> {
    if !has_cmd("flatpak") {
        return Ok(Vec::new());
    }
    let out = run_shell("flatpak list --columns=application,version --app")?;
    let entries = out
        .lines()
        .filter_map(|line| {
            let mut parts = line.split('\t');
            let name = parts.next()?.trim();
            let version = parts.next().unwrap_or("").trim();
            if name.is_empty() || version.is_empty() {
                return None;
            }
            Some(SoftwareEntry {
                name: name.to_string(),
                version: version.to_string(),
            })
        })
        .collect();
    Ok(entries)
}
