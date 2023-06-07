#!/bin/bash

# Set some curl options so that temporary failures get retried
# More info: https://ec.haxx.se/usingcurl-timeouts.html
CURL_OPTS=(-L --retry 100 --retry-delay 0 --connect-timeout 10 --max-time 300)

# Update packages
dnf -y update

# Install 
#  - uuid used for random token generation,
#  - python for certbot
dnf install -y uuid python3

# Install certbot 
python3 -m venv /opt/certbot
/opt/certbot/bin/pip install --upgrade pip
/opt/certbot/bin/pip install certbot certbot-dns-route53
ln -s /opt/certbot/bin/certbot /usr/bin/certbot

# Create teleport user. It is helpful to share the same UID
# to have the same permissions on shared NFS volumes across auth servers and for consistency.
useradd -r teleport -u "${TELEPORT_UID}" -d /var/lib/teleport
# Add teleport to adm group to read and write logs
usermod -a -G adm teleport

# Setup teleport run dir for pid files
install -d -m 0700 -o teleport -g adm /var/lib/teleport
install -d -m 0755 -o teleport -g adm /run/teleport /etc/teleport.d


# Pick the teleport tarball filename matching the requested teleport
# edition.
case "${TELEPORT_TYPE}-${TELEPORT_FIPS}" in
    oss-0) TARBALL="teleport-v${TELEPORT_VERSION}-linux-amd64-bin.tar.gz" ;;
    ent-0) TARBALL="teleport-ent-v${TELEPORT_VERSION}-linux-amd64-bin.tar.gz" ;;
    ent-1) TARBALL="teleport-ent-v${TELEPORT_VERSION}-linux-amd64-fips-bin.tar.gz" ;;
    oss-1)
        echo "OSS FIPS not supported" >&2
        exit 1
        ;;
    *)
        echo "Invalid environment" >&2
        exit 1
        ;;
esac
TARBALL_FILENAME="/tmp/files/${TARBALL}"

if [[ -f "${TARBALL_FILENAME}" ]]; then    
    echo "Found locally uploaded tarball: ${TARBALL_FILENAME}, moving to /tmp/teleport.tar.gz"
    mv "${TARBALL_FILENAME}" /tmp/teleport.tar.gz
else
    echo "Downloading teleport tarball ${TARBALL}"
    curl "${CURL_OPTS[@]}" -o /tmp/teleport.tar.gz "https://get.gravitational.com/teleport/${TELEPORT_VERSION}/${TARBALL}"
fi

# Extract tarball to /tmp/teleport to get the binaries out
mkdir /tmp/teleport
tar -C /tmp/teleport -x -z -f /tmp/teleport.tar.gz --strip-components=1
install -m 755 /tmp/teleport/{tctl,tsh,teleport,tbot} /usr/local/bin
rm -rf /tmp/teleport /tmp/teleport.tar.gz

if [[ "${TELEPORT_FIPS}" == 1 ]]; then
    # add --fips to 'teleport start' commands in FIPS mode
    sed -i -E 's_^(ExecStart=/usr/local/bin/teleport start)_\1 --fips_' /etc/systemd/system/teleport*.service
fi

# Add /usr/local/bin to path used by sudo (so 'sudo tctl users add' will work as per the docs)
echo "Defaults    secure_path = /sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin" > /etc/sudoers.d/secure_path

# Clean up the authorized keys not used
rm -f /root/.ssh/authorized_keys
rm -f /home/ec2-user/.ssh/authorized_keys

# Clean up copied temp files
rm -rf /tmp/files

# Clean up all packages
dnf -y clean all
rm -rf /var/cache/dnf /var/cache/yum

# Enable Teleport services to start on boot
systemctl enable teleport-generate-config.service
systemctl enable teleport.service
