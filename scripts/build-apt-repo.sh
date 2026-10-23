#!/bin/bash
# Builds a signed apt repository from the .deb files in DEBS into OUT: suite and codename
# "stable", component "main", amd64. Signs with KEY, which must be in gpg's keyring.
# Usage: scripts/build-apt-repo.sh DEBS OUT KEY
set -euo pipefail

debs=$(realpath "$1")
out=$2
key=$3

rm -rf "$out"
mkdir -p "$out/pool/main" "$out/dists/stable/main/binary-amd64"
cp "$debs"/*.deb "$out/pool/main/"
cd "$out"

apt-ftparchive packages pool > dists/stable/main/binary-amd64/Packages
gzip -9 -k -n dists/stable/main/binary-amd64/Packages
apt-ftparchive \
    -o APT::FTPArchive::Release::Origin=sshvault \
    -o APT::FTPArchive::Release::Label=sshvault \
    -o APT::FTPArchive::Release::Suite=stable \
    -o APT::FTPArchive::Release::Codename=stable \
    -o APT::FTPArchive::Release::Architectures=amd64 \
    -o APT::FTPArchive::Release::Components=main \
    release dists/stable > dists/stable/Release

gpg --batch --yes --local-user "$key" --clearsign --output dists/stable/InRelease dists/stable/Release
gpg --batch --yes --local-user "$key" --armor --detach-sign --output dists/stable/Release.gpg dists/stable/Release
gpg --armor --export "$key" > sshvault.asc
fingerprint=$(gpg --with-colons --fingerprint "$key" | awk -F: '$1 == "fpr" { print $10; exit }')

cat > index.html <<HTML
<!doctype html>
<meta charset="utf-8">
<title>sshvault apt repository</title>
<h1>sshvault apt repository</h1>
<p>For Ubuntu 24.04 or later, amd64. See <a href="https://github.com/torstei/sshvault">the project</a>.</p>
<pre>
sudo curl -fsSLo /etc/apt/keyrings/sshvault.asc https://torstei.github.io/sshvault/sshvault.asc
echo "deb [signed-by=/etc/apt/keyrings/sshvault.asc] https://torstei.github.io/sshvault stable main" \\
  | sudo tee /etc/apt/sources.list.d/sshvault.list
sudo apt update &amp;&amp; sudo apt install sshvault
</pre>
<p>Signing key fingerprint: <code>$fingerprint</code></p>
HTML
