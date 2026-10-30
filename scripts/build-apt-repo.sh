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
    -o APT::FTPArchive::Release::Origin=pidvault \
    -o APT::FTPArchive::Release::Label=pidvault \
    -o APT::FTPArchive::Release::Suite=stable \
    -o APT::FTPArchive::Release::Codename=stable \
    -o APT::FTPArchive::Release::Architectures=amd64 \
    -o APT::FTPArchive::Release::Components=main \
    release dists/stable > dists/stable/Release

gpg --batch --yes --local-user "$key" --clearsign --output dists/stable/InRelease dists/stable/Release
gpg --batch --yes --local-user "$key" --armor --detach-sign --output dists/stable/Release.gpg dists/stable/Release
gpg --armor --export "$key" > pidvault.asc
fingerprint=$(gpg --with-colons --fingerprint "$key" | awk -F: '$1 == "fpr" { print $10; exit }')

cat > index.html <<HTML
<!doctype html>
<meta charset="utf-8">
<title>pidvault apt repository</title>
<h1>pidvault apt repository</h1>
<p>For Ubuntu 24.04 or later, amd64. See <a href="https://github.com/torstei/pidvault">the project</a>.</p>
<pre>
sudo curl -fsSLo /etc/apt/keyrings/pidvault.asc https://torstei.github.io/pidvault/pidvault.asc
echo "deb [signed-by=/etc/apt/keyrings/pidvault.asc] https://torstei.github.io/pidvault stable main" \\
  | sudo tee /etc/apt/sources.list.d/pidvault.list
sudo apt update &amp;&amp; sudo apt install pidvault
</pre>
<p>Signing key fingerprint: <code>$fingerprint</code></p>
HTML
