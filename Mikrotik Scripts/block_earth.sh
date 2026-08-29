#!/bin/bash
sudo firewall-cmd --add-rich-rule="rule family='ipv4' source address='192.168.1.1' port port='37008' protocol='udp' drop" --permanent
sudo firewall-cmd --add-rich-rule="rule family='ipv4' source address='192.168.1.1' port port='2055' protocol='udp' drop" --permanent
sudo firewall-cmd --add-rich-rule="rule family='ipv4' source address='103.148.176.33' port port='37008' protocol='udp' drop" --permanent
sudo firewall-cmd --add-rich-rule="rule family='ipv4' source address='103.148.176.33' port port='2055' protocol='udp' drop" --permanent
sudo firewall-cmd --reload
echo "Firewall rules applied."
