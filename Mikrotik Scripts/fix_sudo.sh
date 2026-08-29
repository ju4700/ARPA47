#!/bin/bash
echo '4700' | sudo -S bash -c 'echo "ju4700 ALL=(root) NOPASSWD: /usr/bin/truncate" > /etc/sudoers.d/arpa-truncate && chmod 440 /etc/sudoers.d/arpa-truncate'
echo "Sudoers rule:"
cat /etc/sudoers.d/arpa-truncate
sed -i 's/truncate -s 0 "$f"/sudo truncate -s 0 "$f"/' /home/ju4700/arpa_rotate_zeek.sh
echo "Rotation script updated:"
grep truncate /home/ju4700/arpa_rotate_zeek.sh
