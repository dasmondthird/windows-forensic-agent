use anyhow::Result;
use log::debug;
use std::fs;
use std::path::Path;
use serde_json::Value;
use crate::types::{BrowserExtension, BrowserSetting, BrowserDownload};

/// Критически важный модуль для детекции угроз в браузерах
/// Покрывает основные векторы современных атак
pub fn collect() -> Result<(Vec<BrowserExtension>, Vec<BrowserSetting>, Vec<BrowserDownload>)> {
    debug!("Starting critical browser security analysis");
    
    let mut extensions = Vec::new();
    let mut settings = Vec::new();
    let mut downloads = Vec::new();
    
    // Собираем данные из всех популярных браузеров
    collect_chrome_based(&mut extensions, &mut settings, &mut downloads)?;
    collect_firefox_based(&mut extensions, &mut settings, &mut downloads)?;
    collect_edge_based(&mut extensions, &mut settings, &mut downloads)?;
    
    debug!("Browser analysis: {} extensions, {} settings, {} downloads", 
           extensions.len(), settings.len(), downloads.len());
    
    Ok((extensions, settings, downloads))
}

fn collect_chrome_based(
    extensions: &mut Vec<BrowserExtension>,
    settings: &mut Vec<BrowserSetting>, 
    downloads: &mut Vec<BrowserDownload>
) -> Result<()> {
    let browsers = [
        ("Chrome", r"%LOCALAPPDATA%\Google\Chrome\User Data"),
        ("Chromium", r"%LOCALAPPDATA%\Chromium\User Data"),
        ("Brave", r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data"),
        ("Opera", r"%APPDATA%\Opera Software\Opera Stable"),
        ("Vivaldi", r"%LOCALAPPDATA%\Vivaldi\User Data"),
    ];
    
    for (browser_name, profile_path) in &browsers {
        let expanded_path = expand_env_vars(profile_path);
        if Path::new(&expanded_path).exists() {
            collect_chrome_extensions(browser_name, &expanded_path, extensions)?;
            collect_chrome_settings(browser_name, &expanded_path, settings)?;
            collect_chrome_downloads(browser_name, &expanded_path, downloads)?;
        }
    }
    
    Ok(())
}

fn collect_firefox_based(
    extensions: &mut Vec<BrowserExtension>,
    settings: &mut Vec<BrowserSetting>,
    downloads: &mut Vec<BrowserDownload>
) -> Result<()> {
    let firefox_profiles = r"%APPDATA%\Mozilla\Firefox\Profiles";
    let expanded_path = expand_env_vars(firefox_profiles);
    
    if let Ok(profiles_dir) = fs::read_dir(&expanded_path) {
        for profile_entry in profiles_dir {
            if let Ok(profile) = profile_entry {
                let profile_path = profile.path();
                if profile_path.is_dir() {
                    collect_firefox_extensions("Firefox", &profile_path, extensions)?;
                    collect_firefox_settings("Firefox", &profile_path, settings)?;
                }
            }
        }
    }
    
    Ok(())
}

fn collect_edge_based(
    extensions: &mut Vec<BrowserExtension>,
    settings: &mut Vec<BrowserSetting>,
    downloads: &mut Vec<BrowserDownload>
) -> Result<()> {
    let edge_path = r"%LOCALAPPDATA%\Microsoft\Edge\User Data";
    let expanded_path = expand_env_vars(edge_path);
    
    if Path::new(&expanded_path).exists() {
        collect_chrome_extensions("Edge", &expanded_path, extensions)?;
        collect_chrome_settings("Edge", &expanded_path, settings)?;
        collect_chrome_downloads("Edge", &expanded_path, downloads)?;
    }
    
    Ok(())
}

fn collect_chrome_extensions(
    browser: &str,
    profile_path: &str, 
    extensions: &mut Vec<BrowserExtension>
) -> Result<()> {
    let extensions_path = format!("{}\\Default\\Extensions", profile_path);
    
    if let Ok(ext_dir) = fs::read_dir(&extensions_path) {
        for ext_entry in ext_dir {
            if let Ok(extension) = ext_entry {
                let ext_id = extension.file_name().to_string_lossy().to_string();
                
                // Ищем manifest.json в последней версии
                if let Ok(versions) = fs::read_dir(extension.path()) {
                    for version_entry in versions {
                        if let Ok(version) = version_entry {
                            let manifest_path = version.path().join("manifest.json");
                            if manifest_path.exists() {
                                if let Ok(manifest_content) = fs::read_to_string(&manifest_path) {
                                    if let Ok(manifest) = serde_json::from_str::<Value>(&manifest_content) {
                                        extensions.push(BrowserExtension {
                                            browser: browser.to_string(),
                                            id: ext_id.clone(),
                                            name: manifest.get("name")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("Unknown").to_string(),
                                            version: manifest.get("version")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("Unknown").to_string(),
                                            permissions: extract_permissions(&manifest),
                                            is_suspicious: check_suspicious_extension(&manifest),
                                            install_path: version.path().to_string_lossy().to_string(),
                                        });
                                    }
                                }
                                break; // Берем только одну (последнюю) версию
                            }
                        }
                    }
                }
            }
        }
    }
    
    Ok(())
}

fn collect_firefox_extensions(
    browser: &str,
    profile_path: &Path,
    extensions: &mut Vec<BrowserExtension>
) -> Result<()> {
    let extensions_json = profile_path.join("extensions.json");
    if extensions_json.exists() {
        if let Ok(content) = fs::read_to_string(&extensions_json) {
            if let Ok(data) = serde_json::from_str::<Value>(&content) {
                if let Some(addons) = data.get("addons").and_then(|v| v.as_array()) {
                    for addon in addons {
                        if let Some(id) = addon.get("id").and_then(|v| v.as_str()) {
                            extensions.push(BrowserExtension {
                                browser: browser.to_string(),
                                id: id.to_string(),
                                name: addon.get("defaultLocale")
                                    .and_then(|v| v.get("name"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("Unknown").to_string(),
                                version: addon.get("version")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("Unknown").to_string(),
                                permissions: extract_firefox_permissions(addon),
                                is_suspicious: check_suspicious_firefox_addon(addon),
                                install_path: profile_path.to_string_lossy().to_string(),
                            });
                        }
                    }
                }
            }
        }
    }
    
    Ok(())
}

fn collect_chrome_settings(
    browser: &str,
    profile_path: &str,
    settings: &mut Vec<BrowserSetting>
) -> Result<()> {
    let preferences_path = format!("{}\\Default\\Preferences", profile_path);
    
    if let Ok(prefs_content) = fs::read_to_string(&preferences_path) {
        if let Ok(prefs) = serde_json::from_str::<Value>(&prefs_content) {
            // Проверяем критические настройки безопасности
            
            // Домашняя страница
            if let Some(homepage) = prefs.get("homepage").and_then(|v| v.as_str()) {
                settings.push(BrowserSetting {
                    browser: browser.to_string(),
                    category: "Homepage".to_string(),
                    setting_name: "homepage".to_string(),
                    value: homepage.to_string(),
                    is_suspicious: is_suspicious_url(homepage),
                });
            }
            
            // Поисковая система по умолчанию
            if let Some(search_engines) = prefs.get("default_search_provider") {
                if let Some(search_url) = search_engines.get("search_url").and_then(|v| v.as_str()) {
                    settings.push(BrowserSetting {
                        browser: browser.to_string(),
                        category: "SearchEngine".to_string(),
                        setting_name: "default_search_url".to_string(),
                        value: search_url.to_string(),
                        is_suspicious: is_suspicious_search_engine(search_url),
                    });
                }
            }
            
            // Прокси настройки
            if let Some(proxy) = prefs.get("proxy") {
                if let Some(mode) = proxy.get("mode").and_then(|v| v.as_str()) {
                    if mode != "direct" {
                        settings.push(BrowserSetting {
                            browser: browser.to_string(),
                            category: "Proxy".to_string(),
                            setting_name: "proxy_mode".to_string(),
                            value: mode.to_string(),
                            is_suspicious: true, // Любой прокси подозрителен
                        });
                    }
                }
            }
            
            // Отключение безопасности
            if let Some(security) = prefs.get("safebrowsing") {
                if let Some(enabled) = security.get("enabled").and_then(|v| v.as_bool()) {
                    if !enabled {
                        settings.push(BrowserSetting {
                            browser: browser.to_string(),
                            category: "Security".to_string(),
                            setting_name: "safebrowsing_disabled".to_string(),
                            value: "true".to_string(),
                            is_suspicious: true,
                        });
                    }
                }
            }
        }
    }
    
    Ok(())
}

fn collect_firefox_settings(
    browser: &str,
    profile_path: &Path,
    settings: &mut Vec<BrowserSetting>
) -> Result<()> {
    let prefs_js = profile_path.join("prefs.js");
    
    if let Ok(content) = fs::read_to_string(&prefs_js) {
        for line in content.lines() {
            if line.starts_with("user_pref(") {
                // Парсим Firefox preferences
                if line.contains("browser.startup.homepage") {
                    if let Some(value) = extract_pref_value(line) {
                        settings.push(BrowserSetting {
                            browser: browser.to_string(),
                            category: "Homepage".to_string(),
                            setting_name: "browser.startup.homepage".to_string(),
                            value: value.clone(),
                            is_suspicious: is_suspicious_url(&value),
                        });
                    }
                }
                
                if line.contains("network.proxy.type") {
                    if let Some(value) = extract_pref_value(line) {
                        if value != "0" { // 0 = no proxy
                            settings.push(BrowserSetting {
                                browser: browser.to_string(),
                                category: "Proxy".to_string(),
                                setting_name: "network.proxy.type".to_string(),
                                value: value,
                                is_suspicious: true,
                            });
                        }
                    }
                }
            }
        }
    }
    
    Ok(())
}

fn collect_chrome_downloads(
    browser: &str,
    _profile_path: &str,
    _downloads: &mut Vec<BrowserDownload>
) -> Result<()> {
    // TODO: Implement real Chrome downloads.json parsing
    // Will parse actual downloads from: profile_path\Default\Downloads\*.json
    debug!("Chrome downloads collection placeholder for {}", browser);
    Ok(())
}

// Утилиты для анализа
fn extract_permissions(manifest: &Value) -> Vec<String> {
    let mut permissions = Vec::new();
    
    if let Some(perms) = manifest.get("permissions").and_then(|v| v.as_array()) {
        for perm in perms {
            if let Some(perm_str) = perm.as_str() {
                permissions.push(perm_str.to_string());
            }
        }
    }
    
    permissions
}

fn extract_firefox_permissions(addon: &Value) -> Vec<String> {
    // Firefox permissions logic
    Vec::new()
}

fn check_suspicious_extension(manifest: &Value) -> bool {
    let permissions = extract_permissions(manifest);
    
    // Подозрительные комбинации разрешений
    let dangerous_permissions = [
        "activeTab", "tabs", "webRequest", "webRequestBlocking",
        "cookies", "storage", "nativeMessaging", "downloads"
    ];
    
    let dangerous_count = permissions.iter()
        .filter(|p| dangerous_permissions.contains(&p.as_str()))
        .count();
    
    dangerous_count >= 3 // 3+ опасных разрешения = подозрительно
}

fn check_suspicious_firefox_addon(addon: &Value) -> bool {
    // Firefox addon suspicion logic
    false
}

fn is_suspicious_url(url: &str) -> bool {
    let suspicious_patterns = [
        "bit.ly", "tinyurl.com", "short.link", // Сокращатели ссылок
        "onion", // Tor
        "duckdns.org", "no-ip.org", // Динамический DNS
    ];
    
    suspicious_patterns.iter().any(|pattern| url.contains(pattern))
}

fn is_suspicious_search_engine(url: &str) -> bool {
    // Не Google, Bing, DuckDuckGo, Yandex
    !url.contains("google.com") && 
    !url.contains("bing.com") &&
    !url.contains("duckduckgo.com") &&
    !url.contains("yandex.ru")
}

fn extract_pref_value(line: &str) -> Option<String> {
    // Простой парсинг Firefox prefs
    if let Some(start) = line.find('"') {
        if let Some(end) = line.rfind('"') {
            if start < end {
                return Some(line[start+1..end].to_string());
            }
        }
    }
    None
}

fn expand_env_vars(path: &str) -> String {
    path.replace("%LOCALAPPDATA%", &std::env::var("LOCALAPPDATA").unwrap_or_default())
        .replace("%APPDATA%", &std::env::var("APPDATA").unwrap_or_default())
}
