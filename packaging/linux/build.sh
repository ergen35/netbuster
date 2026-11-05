#!/usr/bin/env bash
# Fabrique les paquets Linux dans dist/ : l'archive du binaire (.tar.gz) et le paquet .deb.
#   packaging/linux/build.sh              compile puis empaquette
#   packaging/linux/build.sh --no-build   empaquette le binaire déjà compilé
set -euo pipefail
umask 022

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"

if [ "${1:-}" != "--no-build" ]; then
    cargo build --release --locked
fi
BIN="$TARGET_DIR/release/netbuster"
[ -x "$BIN" ] || { echo "binaire absent : $BIN" >&2; exit 1; }

DEB_ARCH="$(dpkg --print-architecture)"
DIST="$ROOT/dist"
WORK="$DIST/.travail"
rm -rf "$WORK"
mkdir -p "$WORK"

# ---------- Archive du binaire ----------
ARCHIVE_NAME="netbuster-$VERSION-linux-$(uname -m)"
ARCHIVE="$WORK/$ARCHIVE_NAME"
mkdir -p "$ARCHIVE"
install -m 0755 "$BIN" "$ARCHIVE/netbuster"
cat > "$ARCHIVE/LISEZMOI.txt" <<TXT
NetBuster $VERSION pour Linux

Pour le lancer : double-cliquez sur « netbuster » ou tapez ./netbuster dans ce dossier.
Il n'y a rien à installer : au premier lancement, NetBuster ajoute son lanceur et son icône à votre menu
d'applications. Si vous déplacez le fichier, relancez-le une fois pour mettre le lanceur à jour.

Il a besoin des commandes « ip » et « ss » (paquet iproute2) et de « pkexec » pour les fonctions
administrateur. Sur Debian ou Ubuntu, préférez le paquet .deb, qui installe ce qu'il faut.

Projet : https://github.com/ergen35/netbuster
TXT
tar -C "$WORK" --owner=0 --group=0 -czf "$DIST/$ARCHIVE_NAME.tar.gz" "$ARCHIVE_NAME"

# ---------- Paquet .deb ----------
PKG="$WORK/deb"
mkdir -p "$PKG/DEBIAN" "$PKG/usr/bin" "$PKG/usr/share/applications" "$PKG/usr/share/doc/netbuster"
install -m 0755 "$BIN" "$PKG/usr/bin/netbuster"
install -m 0644 packaging/linux/netbuster.desktop "$PKG/usr/share/applications/netbuster.desktop"
for s in 16 22 24 32 48 64 128 256 512; do
    d="$PKG/usr/share/icons/hicolor/${s}x${s}/apps"
    mkdir -p "$d"
    install -m 0644 "assets/icons/netbuster-$s.png" "$d/netbuster.png"
done
cat > "$PKG/usr/share/doc/netbuster/copyright" <<TXT
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: NetBuster
Source: https://github.com/ergen35/netbuster

Files: *
Copyright: Serge Eric Hotegni
License: Tous-droits-reserves
 Aucune licence libre n'a encore été choisie pour ce projet.
TXT

# La version de la bibliothèque C vient de ce que le binaire demande réellement.
SHLIB_DIR="$WORK/shlibs"
mkdir -p "$SHLIB_DIR/debian"
printf 'Source: netbuster\n' > "$SHLIB_DIR/debian/control"
LIBS="$(cd "$SHLIB_DIR" && dpkg-shlibdeps -O --ignore-missing-info "$PKG/usr/bin/netbuster" 2>/dev/null | sed -n 's/^shlibs:Depends=//p')"
[ -n "$LIBS" ] || { echo "dépendances du binaire introuvables" >&2; exit 1; }

SIZE_KB="$(du -sk "$PKG" | cut -f1)"
# OpenGL, le clavier et l'affichage sont chargés à l'exécution : l'analyse du binaire ne les voit pas.
cat > "$PKG/DEBIAN/control" <<TXT
Package: netbuster
Version: $VERSION
Architecture: $DEB_ARCH
Maintainer: Serge Eric Hotegni <ergen35@users.noreply.github.com>
Installed-Size: $SIZE_KB
Depends: $LIBS, iproute2, libegl1 | libgl1, libxkbcommon0, libwayland-client0 | libx11-6
Recommends: pkexec | policykit-1, libxkbcommon-x11-0, libxcursor1, libxi6, libxrandr2, libx11-xcb1, mtr-tiny | traceroute, fonts-noto-core | fonts-dejavu-core
Suggests: ufw, network-manager, openssh-server, tcpdump
Section: net
Priority: optional
Homepage: https://github.com/ergen35/netbuster
Description: surveillance et gestion du réseau du PC, en temps réel
 NetBuster montre ce qui entre et sort de ce PC : débits, applications,
 connexions, ports ouverts, paquets, traceroute et fournisseurs des adresses IP.
 Il gère aussi le pare-feu, la configuration réseau et SSH, et peut capturer
 le trafic en arrière-plan dès le démarrage du PC.
TXT
for s in postinst prerm postrm; do
    install -m 0755 "packaging/linux/deb/$s" "$PKG/DEBIAN/$s"
done
(cd "$PKG" && find usr -type f -print0 | sort -z | xargs -0 md5sum > DEBIAN/md5sums)
chmod 0644 "$PKG/DEBIAN/md5sums" "$PKG/DEBIAN/control"
find "$PKG" -type d -exec chmod 0755 {} +

DEB="$DIST/netbuster_${VERSION}_$DEB_ARCH.deb"
dpkg-deb --root-owner-group -Zxz --build "$PKG" "$DEB" >/dev/null
rm -rf "$WORK"
echo "Prêt :"
ls -lh "$DEB" "$DIST/$ARCHIVE_NAME.tar.gz"
