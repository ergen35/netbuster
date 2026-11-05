//! Pare-feu, configuration réseau et SSH : lecture de l'état et actions confirmées par la personne.

use crate::admin::Admin;
use crate::helper::SSHD_DROPIN;
use crate::util::{home_dir, run, ssh_fingerprint, which, CmdResult};
use std::collections::BTreeMap;
use std::net::IpAddr;

// ---------- Actions ----------

#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    /// Commande exécutée en administrateur.
    Root(String, Vec<String>),
    /// Commande exécutée avec les droits de la personne.
    User(String, Vec<String>),
    WriteRoot(String, String),
    WriteUser(String, String),
}

impl Step {
    pub fn root(prog: &str, args: &[&str]) -> Step {
        Step::Root(prog.into(), args.iter().map(|s| s.to_string()).collect())
    }
    pub fn user(prog: &str, args: &[&str]) -> Step {
        Step::User(prog.into(), args.iter().map(|s| s.to_string()).collect())
    }
    pub fn preview(&self) -> String {
        match self {
            Step::Root(p, a) | Step::User(p, a) => {
                let quoted: Vec<String> = a.iter().map(|x| if x.contains(' ') { format!("\"{x}\"") } else { x.clone() }).collect();
                format!("{p} {}", quoted.join(" "))
            }
            Step::WriteRoot(path, _) | Step::WriteUser(path, _) => format!("écrire {path}"),
        }
    }
    pub fn needs_root(&self) -> bool {
        matches!(self, Step::Root(..) | Step::WriteRoot(..))
    }
    pub fn run(&self, admin: &Admin) -> CmdResult {
        match self {
            Step::Root(p, a) => {
                let args: Vec<&str> = a.iter().map(String::as_str).collect();
                admin.exec_root(p, &args)
            }
            Step::User(p, a) => {
                let args: Vec<&str> = a.iter().map(String::as_str).collect();
                run(p, &args)
            }
            Step::WriteRoot(path, content) => admin.write_root(path, content),
            Step::WriteUser(path, content) => match write_private_file(path, content) {
                Ok(()) => CmdResult { ok: true, ..Default::default() },
                Err(e) => CmdResult::error(format!("{path} : {e}")),
            },
        }
    }
}

fn write_private_file(path: &str, content: &str) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = format!("{path}.netbuster-tmp");
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(content.as_bytes())?;
    }
    std::fs::rename(tmp, path)
}

#[derive(Debug, Clone)]
pub struct Action {
    pub title: String,
    pub explain: String,
    pub warning: Option<String>,
    pub steps: Vec<Step>,
    /// Exécuté si une étape échoue, pour remettre les choses en état.
    pub rollback: Vec<Step>,
}

impl Action {
    pub fn new(title: impl Into<String>, explain: impl Into<String>, steps: Vec<Step>) -> Action {
        Action { title: title.into(), explain: explain.into(), warning: None, steps, rollback: vec![] }
    }
    pub fn warn(mut self, w: impl Into<String>) -> Action {
        self.warning = Some(w.into());
        self
    }
    pub fn needs_root(&self) -> bool {
        self.steps.iter().any(Step::needs_root)
    }
}

#[derive(Debug, Clone)]
pub struct ActionResult {
    pub title: String,
    pub ok: bool,
    pub detail: String,
    pub at: String,
}

pub fn run_action(a: &Action, admin: &Admin) -> ActionResult {
    let mut detail = String::new();
    let mut ok = true;
    for s in &a.steps {
        let r = s.run(admin);
        let text = if r.stderr.trim().is_empty() { r.stdout.trim().to_string() } else { r.stderr.trim().to_string() };
        if !text.is_empty() {
            detail.push_str(&text);
            detail.push('\n');
        }
        if !r.ok {
            ok = false;
            break;
        }
    }
    if !ok {
        for s in &a.rollback {
            s.run(admin);
        }
        if !a.rollback.is_empty() {
            detail.push_str("Le réglage précédent a été remis en place.\n");
        }
    }
    ActionResult { title: a.title.clone(), ok, detail: detail.trim().to_string(), at: chrono::Local::now().format("%H:%M:%S").to_string() }
}

// ---------- Pare-feu ----------

#[derive(Debug, Clone, Default, PartialEq)]
pub struct FwRule {
    pub num: u32,
    pub packets: u64,
    pub bytes: u64,
    pub target: String,
    pub proto: String,
    pub in_if: String,
    pub out_if: String,
    pub source: String,
    pub dest: String,
    pub extra: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct FwChain {
    pub name: String,
    pub policy: Option<String>,
    pub rules: Vec<FwRule>,
}

pub fn parse_iptables_list(text: &str) -> Vec<FwChain> {
    let mut out: Vec<FwChain> = vec![];
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Chain ") {
            let name = rest.split_whitespace().next().unwrap_or("").to_string();
            let policy = rest.split_once("(policy ").and_then(|(_, p)| p.split_whitespace().next()).map(String::from);
            out.push(FwChain { name, policy, rules: vec![] });
            continue;
        }
        let toks: Vec<&str> = line.split_whitespace().collect();
        if toks.len() < 8 || toks[0] == "num" {
            continue;
        }
        let Ok(num) = toks[0].parse() else { continue };
        let Some(ch) = out.last_mut() else { continue };
        let (Ok(packets), Ok(bytes)) = (toks[1].parse(), toks[2].parse()) else { continue };
        // Colonnes : num pkts bytes [cible] proto [opt] in out source dest [compléments]
        // La cible peut être vide (règle qui ne fait que compter).
        let mut i = 3;
        let is_proto = |s: &str| matches!(s, "all" | "tcp" | "udp" | "icmp" | "ipv6-icmp" | "icmpv6" | "esp" | "ah" | "gre" | "sctp" | "igmp") || s.parse::<u16>().is_ok();
        let target = if is_proto(toks[i]) && toks.get(i + 1).is_some_and(|t| *t == "--" || *t == "*") {
            String::new()
        } else {
            i += 1;
            toks[i - 1].to_string()
        };
        let proto = toks.get(i).unwrap_or(&"").to_string();
        i += 1;
        if toks.get(i).is_some_and(|t| *t == "--" || t.chars().all(|c| c == '-' || c == 'f')) {
            i += 1;
        }
        let (Some(in_if), Some(out_if), Some(source), Some(dest)) = (toks.get(i), toks.get(i + 1), toks.get(i + 2), toks.get(i + 3)) else {
            continue;
        };
        ch.rules.push(FwRule {
            num,
            packets,
            bytes,
            target,
            proto,
            in_if: in_if.to_string(),
            out_if: out_if.to_string(),
            source: source.to_string(),
            dest: dest.to_string(),
            extra: toks.get(i + 4..).map(|t| t.join(" ")).unwrap_or_default(),
        });
    }
    out
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct UfwRule {
    pub num: u32,
    pub to: String,
    pub action: String,
    pub from: String,
}

#[derive(Debug, Clone, Default)]
pub struct UfwStatus {
    pub active: bool,
    pub defaults: String,
    pub rules: Vec<UfwRule>,
}

pub fn parse_ufw(verbose: &str, numbered: &str) -> UfwStatus {
    let mut s = UfwStatus::default();
    for l in verbose.lines() {
        if let Some(v) = l.strip_prefix("Status:") {
            s.active = v.trim() == "active";
        }
        if let Some(v) = l.strip_prefix("Default:") {
            s.defaults = v.trim().to_string();
        }
    }
    for l in numbered.lines() {
        let l = l.trim_start();
        let Some(rest) = l.strip_prefix('[') else { continue };
        let Some((num, body)) = rest.split_once(']') else { continue };
        let Ok(num) = num.trim().parse() else { continue };
        // `22/tcp                     ALLOW IN    Anywhere` : colonnes séparées par 2 espaces ou plus.
        let cols: Vec<&str> = body.split("  ").map(str::trim).filter(|c| !c.is_empty()).collect();
        if cols.len() >= 3 {
            s.rules.push(UfwRule { num, to: cols[0].into(), action: cols[1].into(), from: cols[2..].join(" ") });
        }
    }
    s
}

pub fn ufw_defaults_fr(defaults: &str) -> Vec<(String, String)> {
    defaults
        .split(',')
        .filter_map(|p| {
            let p = p.trim();
            let (action, what) = p.split_once(" (")?;
            let what = what.trim_end_matches(')');
            let a = match action {
                "deny" => "Bloqué",
                "allow" => "Autorisé",
                "reject" => "Refusé",
                "disabled" => "Désactivé",
                other => other,
            };
            let w = match what {
                "incoming" => "Entrant",
                "outgoing" => "Sortant",
                "routed" => "Routé",
                other => other,
            };
            Some((w.to_string(), a.to_string()))
        })
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct FirewallData {
    pub loaded: bool,
    pub admin_needed: bool,
    pub ufw_conf_enabled: bool,
    pub ufw: UfwStatus,
    pub tables: BTreeMap<(u8, String), Vec<FwChain>>,
    pub nft: String,
    pub error: Option<String>,
}

pub const FW_TABLES: &[&str] = &["filter", "nat", "mangle", "raw"];

pub fn ufw_conf_enabled() -> bool {
    std::fs::read_to_string("/etc/ufw/ufw.conf").is_ok_and(|t| t.lines().any(|l| l.trim().eq_ignore_ascii_case("ENABLED=yes")))
}

pub fn load_firewall(admin: &Admin) -> FirewallData {
    let mut d = FirewallData { loaded: true, ufw_conf_enabled: ufw_conf_enabled(), ..Default::default() };
    if !admin.is_on() {
        d.admin_needed = true;
        return d;
    }
    let v = admin.exec_root("ufw", &["status", "verbose"]);
    let n = admin.exec_root("ufw", &["status", "numbered"]);
    if v.ok {
        d.ufw = parse_ufw(&v.stdout, &n.stdout);
    }
    for (family, prog) in [(4u8, "iptables"), (6u8, "ip6tables")] {
        for table in FW_TABLES {
            let r = admin.exec_root(prog, &["-t", table, "-L", "-n", "-v", "-x", "--line-numbers"]);
            if r.ok {
                d.tables.insert((family, table.to_string()), parse_iptables_list(&r.stdout));
            } else if !r.stderr.contains("does not exist") && !r.stderr.contains("Table does not") {
                d.error = Some(r.stderr.trim().to_string());
            }
        }
    }
    let r = admin.exec_root("nft", &["list", "ruleset"]);
    d.nft = if r.ok { r.stdout } else { r.stderr };
    d
}

/// Bloque ou ouvre un port. Passe par UFW s'il gère le pare-feu de la machine.
pub fn port_rule_action(port: u16, proto: &str, iface: Option<&str>, allow: bool, ufw_active: bool) -> Action {
    let verb = if allow { "Ouvrir" } else { "Fermer" };
    let scope = iface.map(|i| format!(" sur {i}")).unwrap_or_default();
    let title = format!("{verb} le port {port}/{}{scope}", proto.to_uppercase());
    let explain = if allow {
        format!("Le pare-feu laissera entrer les connexions vers le port {port}{scope}.")
    } else {
        format!("Le pare-feu bloquera les connexions qui arrivent de l'extérieur sur le port {port}{scope}. Le programme continue de tourner.")
    };
    let spec = format!("{port}/{proto}");
    let port_s = port.to_string();
    let steps = if ufw_active {
        let verb = if allow { "allow" } else { "deny" };
        match iface {
            Some(i) => vec![Step::root("ufw", &[verb, "in", "on", i, "to", "any", "port", &port_s, "proto", proto])],
            None => vec![Step::root("ufw", &[verb, &spec])],
        }
    } else {
        let target = if allow { "ACCEPT" } else { "DROP" };
        ["iptables", "ip6tables"]
            .iter()
            .map(|prog| {
                let mut a = vec!["-I", "INPUT", "1"];
                if let Some(i) = iface {
                    a.extend_from_slice(&["-i", i]);
                }
                a.extend_from_slice(&["-p", proto, "--dport", &port_s, "-j", target]);
                Step::root(prog, &a)
            })
            .collect()
    };
    Action::new(title, explain, steps)
}

#[derive(Debug, Clone, Default)]
pub struct NewRule {
    pub chain: String,
    pub action: String,
    pub proto: String,
    pub port: String,
    pub source: String,
    pub iface: String,
}

/// Prépare une règle saisie dans le formulaire. Une erreur explique ce qu'il faut corriger.
pub fn iptables_rule_action(family: u8, r: &NewRule) -> Result<Action, String> {
    let prog = if family == 6 { "ip6tables" } else { "iptables" };
    let mut args: Vec<String> = vec!["-I".into(), r.chain.clone(), "1".into()];
    if !r.iface.is_empty() {
        args.push(if r.chain == "OUTPUT" { "-o".into() } else { "-i".into() });
        args.push(r.iface.clone());
    }
    if r.proto != "tous" {
        args.push("-p".into());
        args.push(r.proto.clone());
    }
    let port = r.port.trim();
    if !port.is_empty() {
        if r.proto != "tcp" && r.proto != "udp" {
            return Err("Un port ne s'utilise qu'avec TCP ou UDP.".into());
        }
        let n: u16 = port.parse().map_err(|_| "Le port doit être un nombre entre 1 et 65535.".to_string())?;
        if n == 0 {
            return Err("Le port doit être un nombre entre 1 et 65535.".into());
        }
        args.push("--dport".into());
        args.push(n.to_string());
    }
    let source = r.source.trim();
    if !source.is_empty() {
        validate_cidr(source)?;
        args.push("-s".into());
        args.push(source.to_string());
    }
    args.push("-j".into());
    args.push(r.action.clone());
    let arefs: Vec<&str> = args.iter().map(String::as_str).collect();
    let action_fr = match r.action.as_str() {
        "ACCEPT" => "Autoriser",
        "DROP" => "Bloquer sans répondre",
        _ => "Refuser",
    };
    Ok(Action::new(
        format!("Ajouter une règle : {action_fr} sur {}", r.chain),
        "La règle passe en tête de la chaîne. Elle disparaît au redémarrage, sauf si UFW ou un autre outil la sauvegarde.",
        vec![Step::root(prog, &arefs)],
    ))
}

pub fn validate_cidr(s: &str) -> Result<(), String> {
    let (ip, prefix) = s.split_once('/').unwrap_or((s, ""));
    let parsed: IpAddr = ip.parse().map_err(|_| format!("« {ip} » n'est pas une adresse IP."))?;
    if !prefix.is_empty() {
        let max = if parsed.is_ipv4() { 32 } else { 128 };
        let p: u8 = prefix.parse().map_err(|_| "La longueur de préfixe doit être un nombre.".to_string())?;
        if p > max {
            return Err(format!("Le préfixe doit être au maximum {max}."));
        }
    }
    Ok(())
}

// ---------- Configuration réseau ----------

#[derive(Debug, Clone, Default, PartialEq)]
pub struct RouteRow {
    pub dst: String,
    pub via: String,
    pub dev: String,
    pub metric: String,
    pub proto: String,
    pub v6: bool,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct NeighRow {
    pub ip: String,
    pub dev: String,
    pub mac: String,
    pub state: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct NmConn {
    pub name: String,
    pub uuid: String,
    pub kind: String,
    pub device: String,
    pub active: bool,
}

#[derive(Debug, Clone, Default)]
pub struct NetConfigData {
    pub loaded: bool,
    pub routes: Vec<RouteRow>,
    pub neighbors: Vec<NeighRow>,
    pub connections: Vec<NmConn>,
    pub dns: Vec<(String, String)>,
    pub hostname: String,
    pub nm_available: bool,
}

pub fn parse_routes(json: &str, v6: bool) -> Vec<RouteRow> {
    let v: serde_json::Value = serde_json::from_str(json).unwrap_or_default();
    let s = |e: &serde_json::Value, k: &str| e.get(k).map(|x| x.as_str().map(String::from).unwrap_or_else(|| x.to_string())).unwrap_or_default();
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|e| RouteRow { dst: s(e, "dst"), via: s(e, "gateway"), dev: s(e, "dev"), metric: s(e, "metric"), proto: s(e, "protocol"), v6 })
                .collect()
        })
        .unwrap_or_default()
}

pub fn parse_neighbors(json: &str) -> Vec<NeighRow> {
    let v: serde_json::Value = serde_json::from_str(json).unwrap_or_default();
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|e| NeighRow {
                    ip: e.get("dst").and_then(|x| x.as_str()).unwrap_or("").into(),
                    dev: e.get("dev").and_then(|x| x.as_str()).unwrap_or("").into(),
                    mac: e.get("lladdr").and_then(|x| x.as_str()).unwrap_or("").into(),
                    state: e.get("state").and_then(|x| x.as_array()).and_then(|x| x.first()).and_then(|x| x.as_str()).unwrap_or("").into(),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Sépare une ligne de `nmcli -t` : `:` sépare, `\:` est un deux-points dans une valeur.
fn nmcli_split(line: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(n) = chars.next() {
                    out.last_mut().unwrap().push(n);
                }
            }
            ':' => out.push(String::new()),
            c => out.last_mut().unwrap().push(c),
        }
    }
    out
}

pub fn parse_nmcli(text: &str) -> Vec<NmConn> {
    text.lines()
        .filter_map(|l| {
            let c = nmcli_split(l);
            if c.len() < 5 {
                return None;
            }
            Some(NmConn { name: c[0].clone(), uuid: c[1].clone(), kind: c[2].clone(), device: c[3].clone(), active: c[4] == "activated" })
        })
        .collect()
}

pub fn parse_resolvectl(text: &str) -> Vec<(String, String)> {
    let mut out = vec![];
    for l in text.lines() {
        // `Link 2 (wlo1): 192.168.43.1` ou `Global: 1.1.1.1`
        let Some((who, vals)) = l.split_once(':') else { continue };
        let who = who.trim();
        let name = if who == "Global" {
            "Global".to_string()
        } else if let Some(n) = who.split_once('(').and_then(|(_, r)| r.strip_suffix(')')) {
            n.to_string()
        } else {
            continue;
        };
        if !vals.trim().is_empty() {
            out.push((name, vals.trim().to_string()));
        }
    }
    out
}

pub fn load_netconfig() -> NetConfigData {
    let mut d = NetConfigData { loaded: true, ..Default::default() };
    d.routes = parse_routes(&run("ip", &["-j", "route"]).stdout, false);
    d.routes.extend(parse_routes(&run("ip", &["-j", "-6", "route"]).stdout, true));
    d.neighbors = parse_neighbors(&run("ip", &["-j", "neigh"]).stdout);
    d.nm_available = which("nmcli").is_some();
    if d.nm_available {
        d.connections = parse_nmcli(&run("nmcli", &["-t", "-f", "NAME,UUID,TYPE,DEVICE,STATE", "con", "show"]).stdout);
    }
    d.dns = parse_resolvectl(&run("resolvectl", &["dns"]).stdout);
    if d.dns.is_empty() {
        let text = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
        let servers: Vec<&str> = text.lines().filter_map(|l| l.trim().strip_prefix("nameserver")).map(str::trim).collect();
        if !servers.is_empty() {
            d.dns.push(("Système".into(), servers.join(" ")));
        }
    }
    d.hostname = std::fs::read_to_string("/etc/hostname").unwrap_or_default().trim().to_string();
    d
}

pub fn link_action(iface: &str, up: bool) -> Action {
    let a = Action::new(
        format!("{} l'interface {iface}", if up { "Activer" } else { "Désactiver" }),
        if up { "L'interface se remet à échanger du trafic." } else { "Tout le trafic de cette interface s'arrête immédiatement." },
        vec![Step::root("ip", &["link", "set", "dev", iface, if up { "up" } else { "down" }])],
    );
    if up {
        a
    } else {
        a.warn("Si vous êtes connecté à distance par cette interface, vous perdrez l'accès au PC.")
    }
}

pub fn mtu_action(iface: &str, mtu: &str) -> Result<Action, String> {
    let n: u32 = mtu.trim().parse().map_err(|_| "La MTU doit être un nombre.".to_string())?;
    if !(68..=65536).contains(&n) {
        return Err("La MTU doit être entre 68 et 65536.".into());
    }
    let n = n.to_string();
    Ok(Action::new(
        format!("Régler la MTU de {iface} à {n}"),
        "Taille maximale des paquets sur cette interface.",
        vec![Step::root("ip", &["link", "set", "dev", iface, "mtu", &n])],
    ))
}

pub fn addr_action(iface: &str, cidr: &str, add: bool) -> Result<Action, String> {
    let cidr = cidr.trim();
    if !cidr.contains('/') {
        return Err("Indiquez l'adresse avec son préfixe, par exemple 192.168.1.50/24.".into());
    }
    validate_cidr(cidr)?;
    Ok(Action::new(
        format!("{} l'adresse {cidr} {} {iface}", if add { "Ajouter" } else { "Retirer" }, if add { "à" } else { "de" }),
        "Changement immédiat, perdu au redémarrage sauf s'il est enregistré dans une connexion.",
        vec![Step::root("ip", &["addr", if add { "add" } else { "del" }, cidr, "dev", iface])],
    ))
}

pub fn route_add_action(dst: &str, via: &str, iface: &str) -> Result<Action, String> {
    let dst = dst.trim();
    let via = via.trim();
    if dst != "default" {
        validate_cidr(dst)?;
    }
    let mut args = vec!["route", "add", dst];
    if !via.is_empty() {
        via.parse::<IpAddr>().map_err(|_| format!("« {via} » n'est pas une adresse IP."))?;
        args.extend_from_slice(&["via", via]);
    }
    if !iface.is_empty() {
        args.extend_from_slice(&["dev", iface]);
    }
    if via.is_empty() && iface.is_empty() {
        return Err("Indiquez une passerelle ou une interface.".into());
    }
    Ok(Action::new(format!("Ajouter la route vers {dst}"), "Le trafic vers cette destination passera par ce chemin.", vec![Step::root("ip", &args)]))
}

pub fn route_del_action(r: &RouteRow) -> Action {
    let mut args = vec![];
    if r.v6 {
        args.push("-6");
    }
    args.extend_from_slice(&["route", "del", r.dst.as_str()]);
    if !r.via.is_empty() {
        args.extend_from_slice(&["via", r.via.as_str()]);
    }
    if !r.dev.is_empty() {
        args.extend_from_slice(&["dev", r.dev.as_str()]);
    }
    let a = Action::new(format!("Retirer la route vers {}", r.dst), "Le trafic vers cette destination n'empruntera plus ce chemin.", vec![Step::root("ip", &args)]);
    if r.dst == "default" {
        a.warn("C'est la route par défaut : sans elle, ce PC perd l'accès à Internet.")
    } else {
        a
    }
}

pub fn nm_toggle_action(c: &NmConn) -> Action {
    let verb = if c.active { "down" } else { "up" };
    let a = Action::new(
        format!("{} la connexion « {} »", if c.active { "Couper" } else { "Activer" }, c.name),
        if c.active { "Le PC se déconnecte de ce réseau." } else { "Le PC se connecte à ce réseau." },
        vec![Step::user("nmcli", &["con", verb, "uuid", &c.uuid])],
    );
    if c.active {
        a.warn("Si c'est votre connexion à Internet, elle sera coupée.")
    } else {
        a
    }
}

pub fn dns_action(c: &NmConn, servers: &str) -> Result<Action, String> {
    let list: Vec<&str> = servers.split([' ', ',']).filter(|s| !s.is_empty()).collect();
    if list.is_empty() {
        return Err("Indiquez au moins un serveur DNS.".into());
    }
    for s in &list {
        s.parse::<IpAddr>().map_err(|_| format!("« {s} » n'est pas une adresse IP."))?;
    }
    let joined = list.join(" ");
    Ok(Action::new(
        format!("Utiliser le DNS {joined} sur « {} »", c.name),
        "Enregistré dans la connexion, puis appliqué en la relançant : une brève coupure est possible.",
        vec![
            Step::user("nmcli", &["con", "mod", "uuid", &c.uuid, "ipv4.dns", &joined, "ipv4.ignore-auto-dns", "yes"]),
            Step::user("nmcli", &["con", "up", "uuid", &c.uuid]),
        ],
    ))
}

// ---------- SSH ----------

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SshKey {
    pub kind: String,
    pub comment: String,
    pub fingerprint: String,
    pub line: String,
}

pub fn parse_key_line(line: &str) -> Option<SshKey> {
    let l = line.trim();
    if l.is_empty() || l.starts_with('#') {
        return None;
    }
    let toks: Vec<&str> = l.split_whitespace().collect();
    // Des options peuvent précéder le type de clé.
    let at = toks.iter().position(|t| t.starts_with("ssh-") || t.starts_with("ecdsa-") || t.starts_with("sk-"))?;
    let b64 = toks.get(at + 1)?;
    Some(SshKey {
        kind: toks[at].to_string(),
        comment: toks.get(at + 2..).map(|t| t.join(" ")).unwrap_or_default(),
        fingerprint: ssh_fingerprint(b64).unwrap_or_default(),
        line: l.to_string(),
    })
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct KnownHost {
    pub host: String,
    pub hashed: bool,
    pub kind: String,
}

pub fn parse_known_hosts(text: &str) -> Vec<KnownHost> {
    text.lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.is_empty() || l.starts_with('#') {
                return None;
            }
            let mut it = l.split_whitespace();
            let host = it.next()?;
            Some(KnownHost { host: host.to_string(), hashed: host.starts_with("|1|"), kind: it.next().unwrap_or("").to_string() })
        })
        .collect()
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SshHost {
    pub alias: String,
    pub hostname: String,
    pub user: String,
    pub port: String,
}

pub fn parse_ssh_config(text: &str) -> Vec<SshHost> {
    let mut out: Vec<SshHost> = vec![];
    for l in text.lines() {
        let l = l.trim();
        let Some((k, v)) = l.split_once(|c: char| c.is_whitespace() || c == '=') else { continue };
        let v = v.trim();
        match k.to_ascii_lowercase().as_str() {
            "host" => out.push(SshHost { alias: v.to_string(), ..Default::default() }),
            "hostname" => {
                if let Some(h) = out.last_mut() {
                    h.hostname = v.to_string();
                }
            }
            "user" => {
                if let Some(h) = out.last_mut() {
                    h.user = v.to_string();
                }
            }
            "port" => {
                if let Some(h) = out.last_mut() {
                    h.port = v.to_string();
                }
            }
            _ => {}
        }
    }
    out.retain(|h| h.alias != "*");
    out
}

#[derive(Debug, Clone, PartialEq)]
pub struct LoginEvent {
    pub when: String,
    pub ok: bool,
    pub user: String,
    pub from: String,
    pub method: String,
}

pub fn parse_ssh_journal(text: &str) -> Vec<LoginEvent> {
    let mut out = vec![];
    for l in text.lines() {
        let (ok, rest) = if let Some(p) = l.find("Accepted ") {
            (true, &l[p + 9..])
        } else if let Some(p) = l.find("Failed ") {
            (false, &l[p + 7..])
        } else {
            continue;
        };
        // `password for bob from 1.2.3.4 port 22 ssh2` / `password for invalid user bob from …`
        let toks: Vec<&str> = rest.split_whitespace().collect();
        let Some(from_at) = toks.iter().position(|t| *t == "from") else { continue };
        let Some(for_at) = toks.iter().position(|t| *t == "for") else { continue };
        let user = toks.get(from_at.wrapping_sub(1)).unwrap_or(&"").to_string();
        if for_at >= from_at {
            continue;
        }
        out.push(LoginEvent {
            when: l.split_whitespace().next().unwrap_or("").chars().take(19).collect::<String>().replace('T', " "),
            ok,
            user,
            from: toks.get(from_at + 1).unwrap_or(&"").to_string(),
            method: toks.first().unwrap_or(&"").to_string(),
        });
    }
    out.reverse();
    out
}

#[derive(Debug, Clone, Default)]
pub struct SshData {
    pub loaded: bool,
    pub server_installed: bool,
    pub unit: String,
    pub active: bool,
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub settings: BTreeMap<String, String>,
    pub settings_effective: bool,
    pub dropin_content: String,
    pub dropin_supported: bool,
    pub authorized: Vec<SshKey>,
    pub own_keys: Vec<(String, SshKey)>,
    pub agent_keys: Vec<String>,
    pub known_hosts: Vec<KnownHost>,
    pub hosts: Vec<SshHost>,
    pub logins: Vec<LoginEvent>,
    pub logins_need_admin: bool,
    pub can_install: bool,
}

/// Réglages proposés dans l'écran SSH (en minuscules, comme `sshd -T`).
pub const SSH_SETTINGS: &[&str] = &["port", "permitrootlogin", "passwordauthentication", "pubkeyauthentication", "x11forwarding", "maxauthtries"];

pub fn parse_sshd_files(main: &str, dropins: &[String]) -> BTreeMap<String, String> {
    // Pour OpenSSH, la première valeur rencontrée l'emporte ; les fichiers inclus sont lus en tête.
    let mut out = BTreeMap::new();
    let mut read = |text: &str| {
        for l in text.lines() {
            let l = l.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            let lower = l.to_ascii_lowercase();
            if lower.starts_with("match ") {
                break;
            }
            let mut it = l.split_whitespace();
            let (Some(k), Some(v)) = (it.next(), it.next()) else { continue };
            out.entry(k.to_ascii_lowercase()).or_insert_with(|| v.to_string());
        }
    };
    for d in dropins {
        read(d);
    }
    read(main);
    out
}

pub fn parse_sshd_t(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for l in text.lines() {
        if let Some((k, v)) = l.split_once(' ') {
            out.entry(k.to_string()).or_insert_with(|| v.to_string());
        }
    }
    out
}

pub fn load_ssh(admin: &Admin) -> SshData {
    let mut d = SshData { loaded: true, ..Default::default() };
    d.server_installed = which("sshd").is_some() || std::path::Path::new("/usr/sbin/sshd").exists();
    d.can_install = which("apt-get").is_some();
    if d.server_installed {
        let list = run("systemctl", &["list-unit-files", "--no-legend", "ssh.service", "sshd.service"]).stdout;
        d.unit = if list.contains("sshd.service") { "sshd".into() } else { "ssh".into() };
        d.active = run("systemctl", &["is-active", &d.unit]).stdout.trim() == "active";
        // ssh.socket peut démarrer le service à la demande.
        let socket_active = run("systemctl", &["is-active", "ssh.socket"]).stdout.trim() == "active";
        d.active = d.active || socket_active;
        d.enabled = run("systemctl", &["is-enabled", &d.unit]).stdout.trim() == "enabled"
            || run("systemctl", &["is-enabled", "ssh.socket"]).stdout.trim() == "enabled";

        let main = std::fs::read_to_string("/etc/ssh/sshd_config").unwrap_or_default();
        d.dropin_supported = main.lines().any(|l| l.trim_start().to_ascii_lowercase().starts_with("include") && l.contains("sshd_config.d"));
        let mut dropins = vec![];
        if let Ok(rd) = std::fs::read_dir("/etc/ssh/sshd_config.d") {
            let mut names: Vec<_> = rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "conf")).collect();
            names.sort();
            for p in names {
                if let Ok(t) = std::fs::read_to_string(&p) {
                    dropins.push(t);
                }
            }
        }
        d.dropin_content = std::fs::read_to_string(SSHD_DROPIN).unwrap_or_default();
        d.settings = parse_sshd_files(&main, &dropins);
        if admin.is_on() {
            let r = admin.exec_root("sshd", &["-T"]);
            if r.ok {
                d.settings = parse_sshd_t(&r.stdout);
                d.settings_effective = true;
            }
        }
        d.ports = d.settings.get("port").and_then(|p| p.parse().ok()).map(|p| vec![p]).unwrap_or_else(|| vec![22]);

        let j = admin.exec_best("journalctl", &["-u", &d.unit, "-n", "400", "--no-pager", "-o", "short-iso"]);
        d.logins = parse_ssh_journal(&j.stdout);
        d.logins_need_admin = !admin.is_on();
    }

    let ssh_dir = home_dir().join(".ssh");
    if let Ok(t) = std::fs::read_to_string(ssh_dir.join("authorized_keys")) {
        d.authorized = t.lines().filter_map(parse_key_line).collect();
    }
    if let Ok(rd) = std::fs::read_dir(&ssh_dir) {
        let mut files: Vec<_> = rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "pub")).collect();
        files.sort();
        for p in files {
            if let Some(k) = std::fs::read_to_string(&p).ok().and_then(|t| t.lines().find_map(parse_key_line)) {
                d.own_keys.push((p.file_stem().unwrap_or_default().to_string_lossy().into_owned(), k));
            }
        }
    }
    if let Ok(t) = std::fs::read_to_string(ssh_dir.join("known_hosts")) {
        d.known_hosts = parse_known_hosts(&t);
    }
    if let Ok(t) = std::fs::read_to_string(ssh_dir.join("config")) {
        d.hosts = parse_ssh_config(&t);
    }
    let agent = run("ssh-add", &["-l"]);
    if agent.ok {
        d.agent_keys = agent.stdout.lines().map(String::from).collect();
    }
    d
}

pub fn ssh_service_action(unit: &str, verb: &str) -> Action {
    let (title, explain) = match verb {
        "start" => ("Démarrer le serveur SSH", "Ce PC acceptera les connexions SSH."),
        "stop" => ("Arrêter le serveur SSH", "Ce PC n'acceptera plus de nouvelles connexions SSH."),
        "restart" => ("Redémarrer le serveur SSH", "Le service repart avec sa configuration actuelle."),
        "enable" => ("Lancer SSH au démarrage", "Le serveur SSH démarrera avec le PC."),
        _ => ("Ne plus lancer SSH au démarrage", "Le serveur SSH ne démarrera plus avec le PC."),
    };
    let a = Action::new(title, explain, vec![Step::root("systemctl", &[verb, unit])]);
    if verb == "stop" {
        a.warn("Si vous êtes connecté à ce PC par SSH, vous risquez de perdre l'accès.")
    } else {
        a
    }
}

/// Enregistre les réglages dans un fichier dédié, vérifie la configuration, puis recharge le service.
pub fn ssh_settings_action(unit: &str, previous: &str, values: &[(String, String)]) -> Result<Action, String> {
    let mut content = String::from("# Réglages écrits par NetBuster\n");
    for (k, v) in values {
        if v.is_empty() || v.contains(char::is_whitespace) {
            return Err(format!("Valeur non valide pour {k}."));
        }
        if k == "port" {
            let p: u16 = v.parse().map_err(|_| "Le port doit être un nombre entre 1 et 65535.".to_string())?;
            if p == 0 {
                return Err("Le port doit être un nombre entre 1 et 65535.".into());
            }
        }
        if k == "maxauthtries" {
            v.parse::<u16>().map_err(|_| "Le nombre d'essais doit être un nombre.".to_string())?;
        }
        content.push_str(&format!("{k} {v}\n"));
    }
    let mut a = Action::new(
        "Appliquer les réglages du serveur SSH",
        "Les réglages sont écrits, vérifiés par le serveur, puis pris en compte. En cas d'erreur, l'ancien réglage revient tout seul.",
        vec![
            Step::WriteRoot(SSHD_DROPIN.into(), content),
            Step::root("sshd", &["-t"]),
            Step::root("systemctl", &["reload-or-restart", unit]),
        ],
    );
    a.rollback = vec![Step::WriteRoot(SSHD_DROPIN.into(), previous.to_string())];
    Ok(a)
}

pub fn authorized_keys_path() -> String {
    home_dir().join(".ssh/authorized_keys").to_string_lossy().into_owned()
}

pub fn remove_authorized_action(keys: &[SshKey], remove: &SshKey) -> Action {
    let text: String = keys.iter().filter(|k| k.line != remove.line).map(|k| format!("{}\n", k.line)).collect();
    Action::new(
        format!("Retirer la clé {}", if remove.comment.is_empty() { remove.fingerprint.as_str() } else { remove.comment.as_str() }),
        "Le détenteur de cette clé ne pourra plus se connecter à votre compte sur ce PC.",
        vec![Step::WriteUser(authorized_keys_path(), text)],
    )
}

pub fn add_authorized_action(keys: &[SshKey], new_line: &str) -> Result<Action, String> {
    let key = parse_key_line(new_line).ok_or("Ce texte ne ressemble pas à une clé publique SSH.".to_string())?;
    if key.fingerprint.is_empty() {
        return Err("Cette clé publique est illisible.".into());
    }
    if keys.iter().any(|k| k.fingerprint == key.fingerprint) {
        return Err("Cette clé est déjà autorisée.".into());
    }
    let mut text: String = keys.iter().map(|k| format!("{}\n", k.line)).collect();
    text.push_str(new_line.trim());
    text.push('\n');
    Ok(Action::new(
        format!("Autoriser la clé {}", if key.comment.is_empty() { key.fingerprint.as_str() } else { key.comment.as_str() }),
        "Le détenteur de cette clé pourra se connecter à votre compte sur ce PC.",
        vec![Step::WriteUser(authorized_keys_path(), text)],
    )
    .warn(format!("Vérifiez que l'empreinte {} est bien celle attendue.", key.fingerprint)))
}

pub fn kill_process_action(pid: u32, name: &str, root: bool) -> Action {
    let p = pid.to_string();
    let step = if root { Step::root("kill", &["-TERM", &p]) } else { Step::user("kill", &["-TERM", &p]) };
    Action::new(format!("Arrêter {name} (processus {pid})"), "Le programme reçoit l'ordre de se fermer, et toutes ses connexions s'arrêtent.", vec![step])
}

/// Coupe une connexion TCP sans arrêter le programme (fonction du noyau, droits requis).
pub fn kill_socket_action(local: &str, remote: &str, app: &str) -> Action {
    Action::new(
        format!("Couper la connexion de {app} vers {remote}"),
        "Seule cette connexion est coupée, le programme continue de tourner.",
        vec![Step::root("ss", &["-K", "src", local, "dst", remote])],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const IPT: &str = "Chain INPUT (policy DROP 12 packets, 3456 bytes)
num      pkts      bytes target     prot opt in     out     source               destination
1          10      2000 ufw-before-input  all  --  *      *       0.0.0.0/0            0.0.0.0/0
2           5       300 ACCEPT     tcp  --  wlo1   *       192.168.1.0/24       0.0.0.0/0            tcp dpt:22
3           0         0            all  --  *      *       0.0.0.0/0            0.0.0.0/0

Chain DOCKER (1 references)
num      pkts      bytes target     prot opt in     out     source               destination
1           0         0 DROP       all  --  !docker0 docker0  0.0.0.0/0            0.0.0.0/0
";

    #[test]
    fn iptables_listing() {
        let c = parse_iptables_list(IPT);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].name, "INPUT");
        assert_eq!(c[0].policy.as_deref(), Some("DROP"));
        assert_eq!(c[0].rules.len(), 3);
        let r = &c[0].rules[1];
        assert_eq!((r.num, r.packets, r.bytes), (2, 5, 300));
        assert_eq!(r.target, "ACCEPT");
        assert_eq!(r.proto, "tcp");
        assert_eq!(r.in_if, "wlo1");
        assert_eq!(r.source, "192.168.1.0/24");
        assert_eq!(r.extra, "tcp dpt:22");
        assert_eq!(c[0].rules[2].target, "");
        assert_eq!(c[0].rules[2].proto, "all");
        assert_eq!(c[1].policy, None);
        assert_eq!(c[1].rules[0].in_if, "!docker0");
    }

    #[test]
    fn ip6tables_without_opt_column() {
        let t = "Chain INPUT (policy ACCEPT 0 packets, 0 bytes)\nnum pkts bytes target prot opt in out source destination\n1 1 60 ACCEPT tcp * * ::/0 ::/0 tcp dpt:22\n";
        let c = parse_iptables_list(t);
        assert_eq!(c[0].rules[0].in_if, "*");
        assert_eq!(c[0].rules[0].source, "::/0");
        assert_eq!(c[0].rules[0].extra, "tcp dpt:22");
    }

    #[test]
    fn ufw_output() {
        let v = "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\nNew profiles: skip\n";
        let n = "Status: active\n\n     To                         Action      From\n     --                         ------      ----\n[ 1] 22/tcp                     ALLOW IN    Anywhere\n[ 2] 80/tcp on wlo1             DENY IN     192.168.1.0/24\n[ 3] 22/tcp (v6)                ALLOW IN    Anywhere (v6)\n";
        let u = parse_ufw(v, n);
        assert!(u.active);
        assert_eq!(u.rules.len(), 3);
        assert_eq!(u.rules[0], UfwRule { num: 1, to: "22/tcp".into(), action: "ALLOW IN".into(), from: "Anywhere".into() });
        assert_eq!(u.rules[1].to, "80/tcp on wlo1");
        let d = ufw_defaults_fr(&u.defaults);
        assert_eq!(d[0], ("Entrant".to_string(), "Bloqué".to_string()));
        assert_eq!(d[1], ("Sortant".to_string(), "Autorisé".to_string()));
    }

    fn args(s: &Step) -> String {
        s.preview()
    }

    #[test]
    fn port_actions_use_the_active_firewall() {
        let a = port_rule_action(22, "tcp", None, false, true);
        assert_eq!(args(&a.steps[0]), "ufw deny 22/tcp");
        let a = port_rule_action(8080, "tcp", Some("wlo1"), true, true);
        assert_eq!(args(&a.steps[0]), "ufw allow in on wlo1 to any port 8080 proto tcp");
        let a = port_rule_action(53, "udp", Some("wlo1"), false, false);
        assert_eq!(a.steps.len(), 2);
        assert_eq!(args(&a.steps[0]), "iptables -I INPUT 1 -i wlo1 -p udp --dport 53 -j DROP");
        assert_eq!(args(&a.steps[1]), "ip6tables -I INPUT 1 -i wlo1 -p udp --dport 53 -j DROP");
    }

    #[test]
    fn rule_form_validates_input() {
        let mut r = NewRule { chain: "INPUT".into(), action: "ACCEPT".into(), proto: "tcp".into(), port: "443".into(), source: "10.0.0.0/8".into(), iface: "wlo1".into() };
        let a = iptables_rule_action(4, &r).unwrap();
        assert_eq!(args(&a.steps[0]), "iptables -I INPUT 1 -i wlo1 -p tcp --dport 443 -s 10.0.0.0/8 -j ACCEPT");
        r.port = "70000".into();
        assert!(iptables_rule_action(4, &r).is_err());
        r.port = "; rm -rf /".into();
        assert!(iptables_rule_action(4, &r).is_err());
        r.port = "443".into();
        r.source = "pas-une-ip".into();
        assert!(iptables_rule_action(4, &r).is_err());
        r.source = "".into();
        r.proto = "icmp".into();
        assert!(iptables_rule_action(4, &r).is_err());
    }

    #[test]
    fn netconfig_real_shapes() {
        let routes = parse_routes(r#"[{"dst":"default","gateway":"192.168.43.1","dev":"wlo1","protocol":"dhcp","prefsrc":"192.168.43.242","metric":600,"flags":[]}]"#, false);
        assert_eq!(routes[0].via, "192.168.43.1");
        assert_eq!(routes[0].metric, "600");
        let n = parse_neighbors(r#"[{"dst":"172.17.0.4","dev":"docker0","lladdr":"42:94:d0:12:30:31","state":["REACHABLE"]}]"#);
        assert_eq!(n[0].state, "REACHABLE");
        let c = parse_nmcli("HUAWEI P smart:abc-1:802-11-wireless:wlo1:activated\nCANALBOX\\:2G:def-2:802-11-wireless::\n");
        assert_eq!(c[0].name, "HUAWEI P smart");
        assert!(c[0].active);
        assert_eq!(c[1].name, "CANALBOX:2G");
        assert!(!c[1].active);
        let d = parse_resolvectl("Global:\nLink 2 (wlo1): 192.168.43.1\nLink 3 (docker0):\n");
        assert_eq!(d, vec![("wlo1".to_string(), "192.168.43.1".to_string())]);
    }

    #[test]
    fn netconfig_actions_validate() {
        assert!(addr_action("wlo1", "192.168.1.5", true).is_err());
        assert!(addr_action("wlo1", "192.168.1.5/33", true).is_err());
        assert_eq!(args(&addr_action("wlo1", "192.168.1.5/24", true).unwrap().steps[0]), "ip addr add 192.168.1.5/24 dev wlo1");
        assert!(mtu_action("wlo1", "abc").is_err());
        assert!(mtu_action("wlo1", "10").is_err());
        assert!(route_add_action("10.0.0.0/8", "", "").is_err());
        assert_eq!(args(&route_add_action("default", "192.168.1.1", "wlo1").unwrap().steps[0]), "ip route add default via 192.168.1.1 dev wlo1");
        assert!(dns_action(&NmConn::default(), "1.1.1.1 bad").is_err());
        assert!(route_del_action(&RouteRow { dst: "default".into(), ..Default::default() }).warning.is_some());
    }

    #[test]
    fn ssh_parsers() {
        let k = parse_key_line("from=\"10.0.0.1\" ssh-ed25519 QUJD alice@pc").unwrap();
        assert_eq!(k.kind, "ssh-ed25519");
        assert_eq!(k.comment, "alice@pc");
        assert!(parse_key_line("# commentaire").is_none());
        assert!(parse_key_line("n'importe quoi").is_none());

        let hosts = parse_known_hosts("github.com ssh-ed25519 AAA\n|1|abc|def ssh-rsa BBB\n");
        assert!(!hosts[0].hashed);
        assert!(hosts[1].hashed);

        let cfg = parse_ssh_config("Host *\n  ServerAliveInterval 30\nHost prod\n  HostName 1.2.3.4\n  User root\n  Port 2222\n");
        assert_eq!(cfg, vec![SshHost { alias: "prod".into(), hostname: "1.2.3.4".into(), user: "root".into(), port: "2222".into() }]);

        let j = "2026-11-04T10:00:00+0100 pc sshd[12]: Failed password for invalid user admin from 5.6.7.8 port 2222 ssh2\n2026-11-04T10:01:00+0100 pc sshd[13]: Accepted publickey for alice from 1.2.3.4 port 50000 ssh2: ED25519 SHA256:abc\n2026-11-04T10:02:00+0100 pc sshd[14]: Server listening on 0.0.0.0 port 22.\n";
        let e = parse_ssh_journal(j);
        assert_eq!(e.len(), 2);
        assert!(e[0].ok);
        assert_eq!(e[0].user, "alice");
        assert_eq!(e[0].method, "publickey");
        assert!(!e[1].ok);
        assert_eq!(e[1].user, "admin");
        assert_eq!(e[1].from, "5.6.7.8");
    }

    #[test]
    fn sshd_first_value_wins_and_dropins_come_first() {
        let m = parse_sshd_files("Port 22\nPasswordAuthentication yes\nMatch User x\n  Port 99\n", &["PasswordAuthentication no\n".to_string()]);
        assert_eq!(m["port"], "22");
        assert_eq!(m["passwordauthentication"], "no");
    }

    #[test]
    fn ssh_settings_rollback_and_validation() {
        let a = ssh_settings_action("ssh", "old", &[("port".into(), "2222".into()), ("permitrootlogin".into(), "no".into())]).unwrap();
        assert_eq!(a.rollback, vec![Step::WriteRoot(SSHD_DROPIN.into(), "old".into())]);
        match &a.steps[0] {
            Step::WriteRoot(_, c) => assert!(c.contains("port 2222\n") && c.contains("permitrootlogin no\n")),
            _ => panic!(),
        }
        assert!(ssh_settings_action("ssh", "", &[("port".into(), "abc".into())]).is_err());
        assert!(ssh_settings_action("ssh", "", &[("permitrootlogin".into(), "yes\nmatch all".into())]).is_err());
    }

    #[test]
    fn authorized_keys_edit() {
        let a = parse_key_line("ssh-ed25519 QUJD a").unwrap();
        let b = parse_key_line("ssh-ed25519 QUJE b").unwrap();
        let act = remove_authorized_action(&[a.clone(), b.clone()], &a);
        match &act.steps[0] {
            Step::WriteUser(_, c) => assert_eq!(c, "ssh-ed25519 QUJE b\n"),
            _ => panic!(),
        }
        assert!(add_authorized_action(&[a.clone()], "ssh-ed25519 QUJD autre").is_err());
        assert!(add_authorized_action(&[a], "pas une clé").is_err());
    }
}
