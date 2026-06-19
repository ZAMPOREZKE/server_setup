install -d -o root -g root -m 0755 /run/sshd
apt update
DEBIAN_FRONTEND=noninteractive apt full-upgrade -y
apt autoremove -y
