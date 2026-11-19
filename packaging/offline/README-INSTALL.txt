WIFI Center - offline installation
=================================

Contents
  wifi-center_*_all.deb   the application and its privileged helper
  install-offline.sh      verifies SHA256SUMS and installs with apt (works without a network if dependencies are present)
  fetch-deps.sh           run once on an ONLINE machine (same Parrot release) to fill ./debs with dependency packages
  SHA256SUMS              checksums of the files above

Install
  1. (Only if the target machine lacks the Python/Qt packages and has no network)
     On an online machine of the same Parrot OS release:  sudo ./fetch-deps.sh
     then copy this whole folder to the target.
  2. On the target:  sudo ./install-offline.sh        (add --dry-run first to see what would happen)

Parrot OS 7 already ships the dependencies (python3-pyside6, pyqtgraph, psutil, dbus, gi), so step 1 is usually unnecessary.

After installing
  * Start "WIFI Center" from the application menu, or run: wifi-center
  * The privileged helper is installed with the package. Privileged actions ask for your administrator password through Polkit.
    See /usr/share/doc/wifi-center/ROOT_ACCESS.md.

Remove
  sudo apt remove wifi-center        (keeps the helper's audit log in /var/log/wifi-center and your data in your home folder)

Integrity note
  SHA256SUMS protects against a damaged copy. It does not prove who built the package: only install files you obtained from a
  source you trust.
