//! Sous Windows, l'icône du programme et sa description sont gravées dans le fichier `.exe`.
//!
//! `assets/windows/netbuster.res` est déjà compilé (voir `assets/make_platform_icons.py`) :
//! ainsi, construire NetBuster ne demande aucun outil de plus.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/windows/netbuster.res");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let root = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        println!("cargo:rustc-link-arg-bins={root}/assets/windows/netbuster.res");
    }
}
