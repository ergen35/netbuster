//! Prépare un dossier pour le mode test de l'assistant. Rien ne touche au système.
//! Usage : cargo run --example make_mock -- <dossier> <ip locale> <numéro d'interface>

#[cfg(not(unix))]
fn main() {}

#[cfg(unix)]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let me: Vec<u8> = args[2].split('.').map(|x| x.parse().unwrap()).collect();
    let ifindex = args.get(3).and_then(|x| x.parse().ok()).unwrap_or(2);
    netbuster::mockkit::write_mock(std::path::Path::new(&args[1]), me.try_into().unwrap(), ifindex);
}
