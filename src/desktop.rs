//! Tout ce qui lie NetBuster au bureau : icône, lanceur, ouverture de session et réglages.

use crate::util::{data_dir, home_dir};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const APP_ID: &str = "netbuster";

/// L'icône à chaque taille, dessinée par `assets/make_icon.py`.
pub const ICONS: [(u32, &[u8]); 9] = [
    (16, include_bytes!("../assets/icons/netbuster-16.png")),
    (22, include_bytes!("../assets/icons/netbuster-22.png")),
    (24, include_bytes!("../assets/icons/netbuster-24.png")),
    (32, include_bytes!("../assets/icons/netbuster-32.png")),
    (48, include_bytes!("../assets/icons/netbuster-48.png")),
    (64, include_bytes!("../assets/icons/netbuster-64.png")),
    (128, include_bytes!("../assets/icons/netbuster-128.png")),
    (256, include_bytes!("../assets/icons/netbuster-256.png")),
    (512, include_bytes!("../assets/icons/netbuster-512.png")),
];

/// L'icône en pixels RGBA : `(largeur, hauteur, pixels)`.
pub fn icon_rgba(size: u32) -> Option<(u32, u32, Vec<u8>)> {
    let (_, png) = ICONS.iter().find(|(s, _)| *s == size)?;
    let img = image::load_from_memory_with_format(png, image::ImageFormat::Png).ok()?.into_rgba8();
    Some((img.width(), img.height(), img.into_raw()))
}

fn data_home() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).unwrap_or_else(|| home_dir().join(".local/share"))
}

fn config_home() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|| home_dir().join(".config"))
}

/// Une valeur de `Exec=` : guillemets pour les espaces, échappements demandés par la norme.
pub fn exec_quote(path: &str) -> String {
    let mut out = String::from("\"");
    for c in path.chars() {
        match c {
            // Barre oblique et guillemets sont échappés deux fois : pour la commande, puis pour le fichier.
            '\\' => out.push_str("\\\\\\\\"),
            '"' | '`' | '$' => {
                out.push_str("\\\\");
                out.push(c);
            }
            '%' => out.push_str("%%"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

fn desktop_entry(exe: &str, args: &str, autostart: bool) -> String {
    let mut exec = exec_quote(exe);
    if !args.is_empty() {
        exec.push(' ');
        exec.push_str(args);
    }
    let mut text = format!(
        "[Desktop Entry]
Type=Application
Version=1.0
Name=NetBuster
GenericName=Surveillance du réseau
Comment=Surveiller et gérer le réseau de ce PC, en temps réel
Exec={exec}
Icon={APP_ID}
Terminal=false
Categories=Network;Monitor;
Keywords=réseau;network;paquets;packets;pare-feu;firewall;ports;traceroute;ssh;
StartupWMClass={APP_ID}
StartupNotify={}
",
        !autostart
    );
    if autostart {
        // Laisse à la barre d'état le temps de démarrer avec la session.
        text.push_str("X-GNOME-Autostart-enabled=true\nX-GNOME-Autostart-Delay=3\n");
    }
    text
}

fn write_if_changed(path: &Path, content: &[u8]) -> std::io::Result<()> {
    if std::fs::read(path).is_ok_and(|old| old == content) {
        return Ok(());
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("netbuster-tmp");
    std::fs::write(&tmp, content)?;
    std::fs::rename(tmp, path)
}

fn current_exe() -> std::io::Result<String> {
    Ok(std::env::current_exe()?.to_string_lossy().into_owned())
}

/// Installe le lanceur et l'icône pour ce compte.
///
/// Sous Wayland, le bureau ignore l'icône donnée par la fenêtre : il la cherche dans le lanceur dont
/// le nom correspond à l'application. Sans ce fichier, la barre des tâches montre une icône générique.
pub fn install_launcher_in(data_home: &Path, exe: &str) -> std::io::Result<()> {
    for (size, png) in ICONS {
        let dir = data_home.join(format!("icons/hicolor/{size}x{size}/apps"));
        write_if_changed(&dir.join(format!("{APP_ID}.png")), png)?;
    }
    write_if_changed(&data_home.join(format!("applications/{APP_ID}.desktop")), desktop_entry(exe, "", false).as_bytes())
}

/// Un paquet `.deb` pose lui-même lanceur et icône dans `/usr/share`.
pub fn installed_by_package(exe: &str) -> bool {
    exe.starts_with("/usr/") && !exe.starts_with("/usr/local/")
}

/// Le lanceur du programme, là où le système en a besoin : le paquet de Windows ou de macOS s'en occupe.
pub fn install_launcher() -> std::io::Result<()> {
    if !cfg!(target_os = "linux") {
        return Ok(());
    }
    install_launcher_for(&data_home(), &current_exe()?)
}

pub fn install_launcher_for(data_home: &Path, exe: &str) -> std::io::Result<()> {
    if !installed_by_package(exe) {
        return install_launcher_in(data_home, exe);
    }
    // Un lanceur laissé par une ancienne copie du programme cacherait celui du paquet.
    match std::fs::remove_file(data_home.join(format!("applications/{APP_ID}.desktop"))) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

const WINDOWS_RUN_KEY: &str = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";

/// Le fichier qui demande à macOS de lancer NetBuster à l'ouverture de session.
pub fn launch_agent(exe: &str) -> String {
    let exe = exe.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
  <key>Label</key>
  <string>com.github.ergen35.netbuster</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exe}</string>
    <string>--minimized</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>
"
    )
}

pub fn autostart_path() -> PathBuf {
    if cfg!(target_os = "macos") {
        home_dir().join("Library/LaunchAgents/com.github.ergen35.netbuster.plist")
    } else {
        config_home().join(format!("autostart/{APP_ID}.desktop"))
    }
}

pub fn autostart_enabled() -> bool {
    if cfg!(windows) {
        crate::util::run("reg", &["query", WINDOWS_RUN_KEY, "/v", "NetBuster"]).ok
    } else {
        autostart_path().exists()
    }
}

pub fn set_autostart_at(path: &Path, exe: &str, enabled: bool) -> std::io::Result<()> {
    if enabled {
        write_if_changed(path, desktop_entry(exe, "--minimized", true).as_bytes())
    } else {
        match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

pub fn set_autostart(enabled: bool) -> std::io::Result<()> {
    let exe = current_exe()?;
    if cfg!(windows) {
        let value = format!("\"{exe}\" --minimized");
        let r = if enabled {
            crate::util::run("reg", &["add", WINDOWS_RUN_KEY, "/v", "NetBuster", "/t", "REG_SZ", "/f", "/d", &value])
        } else if autostart_enabled() {
            crate::util::run("reg", &["delete", WINDOWS_RUN_KEY, "/v", "NetBuster", "/f"])
        } else {
            return Ok(());
        };
        return if r.ok { Ok(()) } else { Err(std::io::Error::other(r.stderr.trim().to_string())) };
    }
    if cfg!(target_os = "macos") {
        let path = autostart_path();
        return if enabled {
            write_if_changed(&path, launch_agent(&exe).as_bytes())
        } else {
            match std::fs::remove_file(path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            }
        };
    }
    set_autostart_at(&autostart_path(), &exe, enabled)
}

/// Le programme a pu changer de dossier depuis l'activation : l'ouverture de session doit le retrouver.
pub fn refresh_autostart() {
    if autostart_enabled() {
        let _ = set_autostart(true);
    }
}

// ---------- Réglages enregistrés ----------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Fermer la fenêtre laisse NetBuster tourner dans la barre d'état.
    pub close_to_tray: bool,
    /// Lancer la capture dès l'ouverture de NetBuster.
    pub capture_on_open: bool,
    pub theme: ThemeChoice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ThemeChoice {
    #[default]
    Dark,
    Light,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { close_to_tray: true, capture_on_open: false, theme: ThemeChoice::Dark }
    }
}

impl Settings {
    fn path() -> PathBuf {
        data_dir().join("settings.json")
    }

    pub fn load() -> Settings {
        std::fs::read_to_string(Self::path()).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
    }

    pub fn save(&self) -> std::io::Result<()> {
        let text = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        write_if_changed(&Self::path(), &text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("netbuster-desktop-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn every_icon_decodes_at_its_announced_size() {
        for (size, _) in ICONS {
            let (w, h, px) = icon_rgba(size).unwrap();
            assert_eq!((w, h), (size, size));
            assert_eq!(px.len(), (size * size * 4) as usize);
            // Les coins sont transparents (à l'adoucissement près), le centre est plein.
            assert!(px[3] < 40, "coin de l'icône {size} : {}", px[3]);
            let c = ((size / 2 * size + size / 2) * 4 + 3) as usize;
            assert_eq!(px[c], 255, "centre de l'icône {size}");
        }
    }

    #[test]
    fn settings_saved_before_the_theme_existed_still_load() {
        let s: Settings = serde_json::from_str(r#"{"close_to_tray":false,"capture_on_open":true}"#).unwrap();
        assert_eq!(s.theme, ThemeChoice::Dark);
        assert!(!s.close_to_tray);
        assert!(s.capture_on_open);
    }

    #[test]
    fn paths_with_spaces_stay_one_argument() {
        assert_eq!(exec_quote("/home/a b/netbuster"), "\"/home/a b/netbuster\"");
        assert_eq!(exec_quote("/x/100%/n"), "\"/x/100%%/n\"");
        assert_eq!(exec_quote("/x/a$b"), "\"/x/a\\\\$b\"");
    }

    #[test]
    fn autostart_opens_reduced_and_can_be_turned_off() {
        let d = tmp("autostart");
        let p = d.join("autostart/netbuster.desktop");
        set_autostart_at(&p, "/opt/Mon Dossier/netbuster", true).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("Exec=\"/opt/Mon Dossier/netbuster\" --minimized\n"), "{text}");
        assert!(text.contains("X-GNOME-Autostart-enabled=true"));
        assert!(text.contains("Icon=netbuster"));
        set_autostart_at(&p, "/x", false).unwrap();
        assert!(!p.exists());
        // Déjà désactivé : pas une erreur.
        set_autostart_at(&p, "/x", false).unwrap();
    }

    #[test]
    fn a_packaged_copy_leaves_the_launcher_to_its_package() {
        assert!(installed_by_package("/usr/bin/netbuster"));
        assert!(!installed_by_package("/usr/local/bin/netbuster"));
        assert!(!installed_by_package("/home/a/netbuster"));
        let d = tmp("packaged");
        // Une ancienne copie avait posé son lanceur : il cacherait celui du paquet.
        install_launcher_for(&d, "/home/a/netbuster").unwrap();
        let entry = d.join("applications/netbuster.desktop");
        assert!(entry.exists());
        install_launcher_for(&d, "/usr/bin/netbuster").unwrap();
        assert!(!entry.exists());
        // Rien à retirer : pas une erreur.
        install_launcher_for(&d, "/usr/bin/netbuster").unwrap();
    }

    #[test]
    fn the_mac_login_item_opens_reduced_and_escapes_its_path() {
        let text = launch_agent("/Applications/A&B <x>/netbuster");
        assert!(text.contains("<string>/Applications/A&amp;B &lt;x&gt;/netbuster</string>"), "{text}");
        assert!(text.contains("<string>--minimized</string>"));
        assert!(text.contains("<key>RunAtLoad</key>"));
    }

    #[test]
    fn the_launcher_names_the_icon_the_window_will_look_for() {
        let d = tmp("launcher");
        install_launcher_in(&d, "/opt/netbuster").unwrap();
        let text = std::fs::read_to_string(d.join("applications/netbuster.desktop")).unwrap();
        assert!(text.contains("Icon=netbuster\n"));
        assert!(text.contains("StartupWMClass=netbuster\n"));
        assert!(!text.contains("--minimized"));
        for (size, png) in ICONS {
            assert_eq!(std::fs::read(d.join(format!("icons/hicolor/{size}x{size}/apps/netbuster.png"))).unwrap(), png);
        }
    }
}
