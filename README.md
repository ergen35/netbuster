# NetBuster

Surveillance et gestion du réseau du PC, en temps réel.

## Installer

| Système | Fichier | Comment |
| --- | --- | --- |
| Debian, Ubuntu | `netbuster_<version>_amd64.deb` | `sudo apt install ./netbuster_<version>_amd64.deb` |
| Autre Linux | `netbuster-<version>-linux-x86_64.tar.gz` | Décompresser, puis lancer `netbuster`. Il n'y a rien à installer. |
| Windows 10 et 11 | `netbuster-<version>-windows-x64-setup.exe` | Lancer l'installateur. Sans droits administrateur. Une version `.zip` portable existe aussi. |
| macOS 11 et plus | `netbuster-<version>-macos-universal.dmg` | Glisser NetBuster dans Applications. |

### Avertissement au premier lancement

Les fichiers ne sont pas (encore) signés par un éditeur reconnu : le système l'affiche, ce n'est pas un défaut
du programme.

- **Windows** affiche « Windows a protégé votre ordinateur » : cliquez sur *Informations complémentaires*, puis
  *Exécuter quand même*.
- **macOS** refuse d'abord d'ouvrir l'application. Deux façons de continuer :
  - Faites un clic droit sur NetBuster, puis *Ouvrir*. Sur les versions récentes de macOS, ce clic droit ne
    suffit pas toujours : ouvrez alors *Réglages Système > Confidentialité et sécurité*, descendez jusqu'à
    la section *Sécurité* et cliquez sur *Ouvrir quand même*.
  - Ou, dans le Terminal, retirez la quarantaine une fois pour toutes :
    `xattr -dr com.apple.quarantine /Applications/NetBuster.app`

### Vérifier le téléchargement

Chaque version publie un fichier `SHA256SUMS`. Calculez l'empreinte du paquet téléchargé et comparez-la à la
ligne correspondante de ce fichier :

- Linux : `sha256sum -c --ignore-missing SHA256SUMS` (dans le dossier des téléchargements) doit répondre `OK`.
- macOS : `shasum -a 256 <fichier>`
- Windows (PowerShell) : `Get-FileHash <fichier>`

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

## Licence

[MIT](LICENSE) : vous pouvez utiliser, copier, modifier et redistribuer NetBuster librement, à condition de
conserver la mention de copyright et le texte de la licence.

## Crédits

Créé par Serge Eric Hotegni : https://github.com/ergen35. Projet : https://github.com/ergen35/netbuster
