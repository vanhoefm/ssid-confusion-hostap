#!/usr/bin/env python3
# Copyright (c) 2022, Mathy Vanhoef <mathy.vanhoef@kuleuven.be>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.

from libwifi import *
import abc, sys, os, socket, struct, time, argparse, heapq, subprocess, atexit, select
from datetime import datetime
from wpaspy import Ctrl

#### Debug output functions ####

class Daemon(metaclass=abc.ABCMeta):
	def __init__(self, options):
		self.options = options
		self.nic_iface = options.iface
		self.process = None

		self.wpaspy_pending = []


	def wpaspy_command(self, cmd, can_fail=False):
		# Include console prefix so we can ignore other messages sent over the control interface
		response = self.wpaspy_ctrl.request("> " + cmd)
		while not response.startswith("> "):
			self.wpaspy_pending.append(response)
			response = self.wpaspy_ctrl.recv()

		if "UNKNOWN COMMAND" in response:
			log(ERROR, "wpa_supplicant did not recognize the command %s. Did you (re)compile wpa_supplicant/hostapd?" % cmd.split()[0])
			quit(1)
		elif "FAIL" in response:
			if not can_fail:
				log(ERROR, f"Failed to execute command {cmd}")
				quit(1)
			else:
				return None

		return response[2:]


	def wait_event(self, event, timeout=60*60*24*365):
		while len(self.wpaspy_pending) > 0:
			line = self.wpaspy_pending.pop()
			if event in line:
				return True

		time_end = time.time() + timeout
		time_curr = time.time()
		while time_curr < time_end:
			remaining_time = time_end - time_curr
			sel = select.select([self.wpaspy_ctrl.s], [], [], remaining_time)
			if self.wpaspy_ctrl.s in sel[0]:
				line = self.wpaspy_ctrl.recv()
				if event in line:
					return True
			time_curr = time.time()

		return False


	def connect_wpaspy(self):
		# Wait until daemon started
		time_abort = time.time() + 10
		while not os.path.exists("wpaspy_ctrl/" + self.nic_iface) and time.time() < time_abort:
			time.sleep(0.1)

		# Abort if daemon didn't start properly
		if not os.path.exists("wpaspy_ctrl/" + self.nic_iface):
			log(ERROR, "Unable to connect to control interface. Did hostap/wpa_supplicant start properly?")
			log(ERROR, "Try recompiling them using ./build.sh and double-check client.conf and hostapd.conf.")
			quit(1)

		# Open the wpa_supplicant or hostapd control interface
		try:
			self.wpaspy_ctrl = Ctrl("wpaspy_ctrl/" + self.nic_iface)
			self.wpaspy_ctrl.attach()
		except:
			log(ERROR, "It seems wpa_supplicant/hostapd did not start properly.")
			log(ERROR, "Please restart it manually and inspect its output.")
			log(ERROR, "Did you disable Wi-Fi in the network manager? Otherwise it won't start properly.")
			raise


	def stop(self):
		log(STATUS, "Closing daemon and cleaning up ...")
		if self.process:
			self.process.terminate()
			self.process.wait()


class Station():
	def __init__(self, clientmac):
		self.mac = clientmac


class Authenticator(Daemon):
	def __init__(self, options):
		super().__init__(options)

		self.apmac = None
		self.sock_eth = None
		self.dhcp = None
		self.arp_sender_ip = None
		self.arp_sock = None

		# We can only test one client at a time. Because we change the beacon and that
		# will affect all connected clients.
		self.station = None

	def time_tick(self):
		station.time_tick()

	def advertise_fakessid(self, fakessid):
		self.wpaspy_command(f"FAKESSID {fakessid}")

	def handle_eth_dhcp(self, p, station):
		if not DHCP in p or not station.get_peermac() in self.dhcp.leases: return

		# This assures we only mark it as connected after receiving a DHCP Request
		req_type = next(opt[1] for opt in p[DHCP].options if isinstance(opt, tuple) and opt[0] == 'message-type')
		if req_type != 3: return

		peerip = self.dhcp.leases[station.get_peermac()]
		log(STATUS, "Client {} with IP {} has connected".format(station.get_peermac(), peerip))
		station.set_ip_addresses(self.arp_sender_ip, peerip)

	def handle_eth(self, p):
		# TODO: Properly handle IPv6 vs DHCP. Why can't we always call station.handle_eth(p)?
		# TODO: Shouldn't we handle ARP in the Station() code instead?

		# Ignore clients not connected to the AP
		clientmac = p[Ether].src
		if self.station == None or clientmac != self.station.mac:
			return

		# Let clients get IP addresses
		if not self.options.no_dhcp:
			self.dhcp.reply(p)
		self.arp_sock.reply(p)

		# Monitor DHCP messages to know when a client received an IP address
		if not self.options.no_dhcp and not self.station.obtained_ip:
			self.handle_eth_dhcp(p, self.station)
		else:
			station.handle_eth(p)

	def handle_wpaspy(self, msg):
		log(DEBUG, "daemon: " + msg)

		if "AP-STA-ASSOCIATING" in msg:
			cmd, clientmac, source = msg.split()
			self.station = Station(clientmac)

			log(STATUS, "Client {} is connecting".format(clientmac))
			self.station.handle_connecting(self.apmac)
			self.station.set_peermac(clientmac)

			# When in client mode, the scanning operation might interferes with this test.
			# So it must be executed once we are connecting so the channel is stable.
			self.injection_test(clientmac, self.apmac, False)

		elif "AP-STA-CONNECTED" in msg:
			cmd, clientmac = msg.split()
			if clientmac != self.station.mac:
				log(WARNING, "Unknown client {} finished authenticating.".format(clientmac))
				return
			self.station.handle_authenticated()

			# Test 1: we shouldn't get here with beacon protection. But without 'post-beacon verification'
			#	  that my still happen. We can try to let the client get an IP and then do a ping test.
			#	  Then even normal beacon verification doesn't detect the bad beacons?

			# Test 2: at this point we can instruct the kernel/hostap to use the real SSID everywhere.
			#	  And we would enable beacon protection against. This simulates switching to the real
			#	  channel and let the client directly interact with the real network.

			self.injection_test(clientmac, self.apmac, True)

	def run(self):
		cmd = ["../hostapd/hostapd", "-i", self.nic_iface, self.options.config]
		if self.options.debug == 1:
			cmd += ["-d", "-K"]
		elif self.options.debug >= 2:
			cmd += ["-dd", "-K"]

		log(STATUS, "Starting hostapd using: " + " ".join(cmd))
		try:
			self.process = subprocess.Popen(cmd)
		except:
			if not os.path.exists("../hostapd/hostapd"):
				log(ERROR, "hostapd executable not found. Did you compile hostapd using ./build.sh?")
			raise

		self.connect_wpaspy()
		self.apmac = get_macaddress(self.nic_iface)

		# Let scapy handle DHCP requests
		self.dhcp = DHCP_sock(sock=self.sock_eth,
						domain='mathyvanhoef.com',
						pool=Net('192.168.100.0/24'),
						network='192.168.100.0/24',
						gw='192.168.100.254',
						renewal_time=600, lease_time=3600)
		# Configure gateway IP: reply to ARP and ping requests
		# XXX Should we still do this? What about --ip and --peerip?
		subprocess.check_output(["ifconfig", self.nic_iface, "192.168.100.254"])

		# Use a dedicated IP address for our ARP ping and replies
		self.arp_sender_ip = self.dhcp.pool.pop()
		self.arp_sock = ARP_sock(sock=self.sock_eth, IP_addr=self.arp_sender_ip, ARP_addr=self.apmac)


		# Testing: simulate the attacker by making hostapd use fakessid in beacons, probe response,
		# and association responses. This simulates a multi-channel attacker that modifies these
		# frames. To simulate a real attacker, this will also instruct the kernel to disable beacon
		# protection, since a real attacker cannot modify beacons and recreate the authenticity tag.
		self.advertise_fakessid(self.options.fakessid)

		while True:
			time.sleep(1)

def cleanup():
	test.stop()


def main():
	global test

	parser = argparse.ArgumentParser(description="SSID Confusion Tester")
	parser.add_argument("iface", help="Wireless interface to use.")
	parser.add_argument("fakessid", help="The SSID to impersonate. This SSID will be used in beacons/probes/etc.")
	parser.add_argument("-d", "--debug", action="count", default=0, help="Increase output verbosity.")
	parser.add_argument("--config", default="hostapd.conf", help="Config file to use for hostapd.")
	options = parser.parse_args()

	change_log_level(-options.debug)

	test = Authenticator(options)
	atexit.register(cleanup)
	test.run()


if __name__ == "__main__":
	main()

