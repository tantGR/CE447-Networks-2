#Theodoros Antoniou 2208 - NAT 
#17/5/2019

# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Two OpenFlow 1.0 L3 Static Routers and two OpenFlow 1.0 L2 learning switches.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import ether_types
import time

BCAST = "FF:FF:FF:FF:FF:FF"
LAN1 = "192.168.1.0"
LAN2 = "192.168.2.0"
PUBLIC_IP = "200.0.0.0"
PUBLIC_MAC = "00:00:00:00:04:02" 
R1_IP_LEFT = "192.168.1.1"
R1_MAC_LEFT = "00:00:00:00:01:01"
R1_MAC_RIGHT = "00:00:00:00:03:01"
R1_MAC_PUBLIC = "00:00:00:00:04:01"
R1_IP_PUBLIC = "200.0.0.1"
R2_IP_RIGHT = "192.168.2.1"
R2_MAC_LEFT = "00:00:00:00:03:02"
R2_MAC_RIGHT = "00:00:00:00:02:01"
UDP = 17
TCP = 6
nat_table = {}
nat_ports = 49160



class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    def add_flow(self, datapath, match, actions):
        ofproto = datapath.ofproto

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
	
        datapath.send_msg(mod)

    def out_port(self,ip,port):
	global nat_ports, nat_table	
	for p in nat_table:
		if nat_table[p][0] == ip and nat_table[p][1] == port:
			return p

	nat_ports = nat_ports + 1
	nat_table[nat_ports] = [ip,port]
	#print(nat_table)
	return nat_ports
	
    def find_host(self,port):
	global nat_table,nat_ports

	if port in nat_table:
		return nat_table[port]
	else:
		return -1,-1
	
		
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
	global nat_table
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src

        self.mac_to_port.setdefault(dpid, {})

	self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dpid == 0x1A:	
            if eth.ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                arpPkt = pkt.get_protocol(arp.arp)
		if arpPkt.opcode == 1 and arpPkt.dst_ip == R1_IP_LEFT:
			self.send_arp_reply(datapath,R1_MAC_LEFT,R1_IP_LEFT,src,arpPkt.src_ip,msg.in_port)
		elif arpPkt.opcode == 1 and arpPkt.dst_ip == R1_IP_PUBLIC:
			self.send_arp_reply(datapath,R1_MAC_PUBLIC,R1_IP_PUBLIC,src,arpPkt.src_ip,msg.in_port)
                return
            elif eth.ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
		ipPkt = pkt.get_protocol(ipv4.ipv4)
		src_ip = ipPkt.src
		dst_ip = ipPkt.dst
		if ipPkt.proto == TCP:   
			tpkt = pkt.get_protocol(tcp.tcp)
			src_port = tpkt.src_port
            dst_port = tpkt.dst_port			
		elif ipPkt.proto == UDP:
			tpkt = pkt.get_protocol(udp.udp)
			src_port = tpkt.src_port
			dst_port = tpkt.dst_port
		if dst_ip[:8] == PUBLIC_IP[:8] and msg.in_port != 3:
			new_port = self.out_port(src_ip,src_port)
			if msg.in_port == 1:
                match = datapath.ofproto_parser.OFPMatch(dl_type = 0x0800,in_port = 1,nw_proto = ipPkt.proto,tp_src = src_port,nw_src = src_ip,nw_dst_mask = 24,nw_dst = PUBLIC_IP)    
			else:
		        match = datapath.ofproto_parser.OFPMatch(dl_type = 0x0800,in_port = 2,nw_proto = ipPkt.proto,nw_src = src_ip,nw_dst_mask = 24,nw_dst = PUBLIC_IP,tp_src = src_port)
			actions = [datapath.ofproto_parser.OFPActionSetDlSrc(R1_MAC_PUBLIC),datapath.ofproto_parser.OFPActionSetDlDst(PUBLIC_MAC),datapath.ofproto_parser.OFPActionSetNwSrc(R1_IP_PUBLIC),datapath.ofproto_parser.OFPActionSetTpSrc(new_port),datapath.ofproto_parser.OFPActionOutput(3)]
		else:
			if msg.in_port == 1:
				if dst_ip[:10] == LAN1[:10]:
					match = datapath.ofproto_parser.OFPMatch(dl_type = 0x0800,in_port = 1,nw_dst_mask = 24,nw_dst = LAN1)
					actions = [datapath.ofproto_parser.OFPActionSetDlSrc(R1_MAC_LEFT),datapath.ofproto_parser.OFPActionSetDlDst(BCAST),datapath.ofproto_parser.OFPActionOutput(2)]
			elif msg.in_port == 2:
				if dst_ip[:10] == LAN2[:10]:
					match = datapath.ofproto_parser.OFPMatch(dl_type = 0x0800,in_port = 2,nw_dst_mask = 24,nw_dst = LAN2)
					actions = [datapath.ofproto_parser.OFPActionSetDlSrc(R1_MAC_RIGHT),datapath.ofproto_parser.OFPActionSetDlDst(R2_MAC_LEFT),datapath.ofproto_parser.OFPActionOutput(1)]
             	elif msg.in_port == 3:
					[dst_ip,port] = self.find_host(dst_port)
					if dst_ip == -1 or port == -1:
						return
					if dst_ip[:10] == LAN1[:10]:
						out_port = 2
						srcMAC = R1_MAC_LEFT
						match = datapath.ofproto_parser.OFPMatch(dl_type = 0x0800,in_port = 3,nw_proto = ipPkt.proto,nw_dst_mask = 24,nw_dst = PUBLIC_IP,tp_dst = dst_port)
						actions = [datapath.ofproto_parser.OFPActionSetDlSrc(srcMAC),datapath.ofproto_parser.OFPActionSetDlDst(BCAST),datapath.ofproto_parser.OFPActionSetTpDst(port),datapath.ofproto_parser.OFPActionSetNwDst(dst_ip),datapath.ofproto_parser.OFPActionOutput(out_port)]
					elif dst_ip[:10] == LAN2[:10]:
						out_port = 1
						srcMAC = R1_MAC_RIGHT
						match = datapath.ofproto_parser.OFPMatch(dl_type = 0x0800,in_port = 3,nw_proto = ipPkt.proto,nw_dst_mask = 24,nw_dst = PUBLIC_IP,tp_dst = dst_port)
						actions = [datapath.ofproto_parser.OFPActionSetDlSrc(srcMAC),datapath.ofproto_parser.OFPActionSetDlDst(R2_MAC_LEFT),datapath.ofproto_parser.OFPActionSetTpDst(port),datapath.ofproto_parser.OFPActionSetNwDst(dst_ip),datapath.ofproto_parser.OFPActionOutput(out_port)]
				
		self.add_flow(datapath,match,actions)
		
		out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,buffer_id=0xffffffff,in_port=msg.in_port,actions=actions,data=msg.data)
		datapath.send_msg(out)
			return
        return
        if dpid == 0x1B:
            if eth.ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
		arpPkt = pkt.get_protocol(arp.arp)
                if arpPkt.opcode == 1 and arpPkt.dst_ip == R2_IP_RIGHT:
                        self.send_arp_reply(datapath,R2_MAC_RIGHT,R2_IP_RIGHT,src,arpPkt.src_ip,msg.in_port)
                return
            elif eth.ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
		if msg.in_port == 1:
			match = datapath.ofproto_parser.OFPMatch(dl_type = 0x0800,in_port = 1,nw_dst_mask = 24,nw_dst = LAN2)
			actions = [datapath.ofproto_parser.OFPActionSetDlSrc(R2_MAC_RIGHT),datapath.ofproto_parser.OFPActionSetDlDst(BCAST),datapath.ofproto_parser.OFPActionOutput(2)]
		elif msg.in_port == 2:
			ipPkt = pkt.get_protocol(ipv4.ipv4)
			src_ip = ipPkt.src
			if ipPkt.dst[:8] == PUBLIC_IP[:8]:
				match = datapath.ofproto_parser.OFPMatch(dl_type = 0x0800,in_port = 2,nw_dst_mask = 24,nw_dst = PUBLIC_IP)
			else:
				match = datapath.ofproto_parser.OFPMatch(dl_type = 0x0800,in_port = 2,nw_dst_mask = 24,nw_dst = LAN1)
			actions = [datapath.ofproto_parser.OFPActionSetDlSrc(R2_MAC_LEFT),datapath.ofproto_parser.OFPActionSetDlDst(R1_MAC_RIGHT),datapath.ofproto_parser.OFPActionOutput(1)]

		self.add_flow(datapath,match,actions)
		out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,buffer_id=0xffffffff,in_port=msg.in_port,actions=actions,data=msg.data)
		datapath.send_msg(out)
                return
            return
                 
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        match = datapath.ofproto_parser.OFPMatch(
            in_port=msg.in_port, dl_dst=haddr_to_bin(dst))

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)
	

    def send_arp_reply(self, datapath, srcMac, srcIp, dstMac, dstIp, outPort):
        e = ethernet.ethernet(dstMac, srcMac, ether_types.ETH_TYPE_ARP)
        a = arp.arp(1, 0x0800, 6, 4, 2, srcMac, srcIp, dstMac, dstIp)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
