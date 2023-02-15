nmcli connection modify crc ip4 10.1.0.2/24
ip route add 10.1.0.0/16 dev crc src 10.1.0.2 metric 300

sleep 60
VICTIM_IFACE=`virsh domiflist victim | grep management | cut -d " " -f 2`
ATTACKER_IFACE=`virsh domiflist attacker | grep management | cut -d " " -f 2`

VICTIM_IP=`virsh net-dhcp-leases default | grep victim | cut -d " " -f 16`
echo GNS3:
echo victim: $VICTIM_IFACE
echo attacker: $ATTACKER_IFACE
echo \n
echo SSH:
echo victim: $VICTIM_IP
echo attacker: 192.168.122.2
