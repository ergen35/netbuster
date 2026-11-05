# NetBuster

Surveillance et gestion du réseau du PC, en temps réel.

## Installer

| Système | Fichier | Comment |
| --- | --- | --- |
| Debian, Ubuntu | `netbuster_<version>_amd64.deb` | `sudo apt install ./netbuster_<version>_amd64.deb` |
| Autre Linux | `netbuster-<version>-linux-x86_64.tar.gz` | Décompresser, puis lancer `netbuster`. Il n'y a rien à installer. |
| Windows 10 et 11 | `netbuster-<version>-windows-x64-setup.exe` | Lancer l'installateur. Sans droits administrateur. Une version `.zip` portable existe aussi. |
| macOS 11 et plus | `netbuster-<version>-macos-universal.dmg` | Glisser NetBuster dans Applications. |

Les fichiers ne sont pas signés par un éditeur reconnu. Windows peut afficher « Windows a protégé votre
ordinateur » (Informations complémentaires, puis Exécuter quand même). macOS demande un clic droit sur
l'application, puis Ouvrir, au premier lancement.

## Ce qui fonctionne selon le système

| Fonction | Linux | Windows, macOS |
| --- | --- | --- |
| Débits des interfaces, consommation | oui | oui |
| Connexions et ports ouverts, avec leur programme | oui | oui (sous macOS, seulement ceux de votre compte) |
| Traceroute, identification des adresses IP | oui | oui |
| Thème, copie des adresses, listes figées | oui | oui |
| Lancement à l'ouverture de session | oui | oui (réduit dans la barre des tâches) |
| Volume de trafic par programme | oui | pas encore |
| Capture et analyse des paquets | oui | pas encore |
| Pare-feu, configuration réseau, SSH | oui | pas encore |
| Icône de la barre d'état, service en arrière-plan | oui | pas encore |

## Fabriquer les paquets

Il faut Rust 1.95 ou plus récent. Les fichiers arrivent dans `dist/`.

- Linux : `packaging/linux/build.sh`, avec `dpkg-deb`.
- Windows : `packaging\windows\build.ps1`, avec [Inno Setup](https://jrsoftware.org/isinfo.php) pour l'installateur.
- macOS : `packaging/macos/build.sh`, sur un Mac avec les outils de Xcode.

Chaque système se fabrique sur lui-même. Une fois ce dossier envoyé sur GitHub, le fichier
`.github/workflows/paquets.yml` fabrique les trois à chaque envoi sur `main` : ils se téléchargent dans
l'onglet Actions. Une étiquette commençant par `v` (par exemple `v0.1.0`) les publie aussi dans une version GitHub.

Pour changer de version, modifiez `version` dans `Cargo.toml`, puis celle de `assets/make_platform_icons.py`,
et refaites `assets/windows/netbuster.res` comme indiqué en tête de ce script.

## Crédits

Créé par Serge Eric Hotegni : https://github.com/ergen35. Projet : https://github.com/ergen35/netbuster
