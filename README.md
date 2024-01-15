# Test if SSID is checked after connecting

Create the following example `hostapd_test.conf` configuration:

	interface=wlan0
	ctrl_interface=wpaspy_ctrl
	channel=1
	ssid=connectssid

Now start hostapd:

	./hostapd hostapd_test.conf

To give the client an IP address create the following `dnsmasq.conf` file:

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

Now connect to the created network. Once connected, you can make hostapd
advertise a different SSID using the following command:

	./hostapd_cli -p wpaspy_ctrl raw "CHANGESSID changedssid"

If the client stays connected then the client does not verify the SSID in
beacon frames one connected. Note that you can try to ping the client to
check whether it's still connected (see the client IP address in dnsmasq).


# Test whether SSID is checked during authentication

Start hostapd like above and then execute:

	./hostapd_cli -p wpaspy_ctrl raw "FAKESSID changedssid"

This will simulate a MC-MITM attacker that modifies probe responses, beacons,
and association requests to advertise a different (fake) SSID. This will also
turn off beacon protection to simulate that the attacker changes the SSID in
the beacon but cannot recalculate the beacon MMIC.

After starting hostapd try to connect with a client to "changessid". If clients
can successfully connect to the "changedssid" then the SSID is not verifed
during connection/authentication.

