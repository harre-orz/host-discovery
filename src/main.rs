#![feature(slice_patterns)]
extern crate pnet;

use pnet::datalink::{self};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::{Packet, MutablePacket};
use pnet::packet::ethernet::{MutableEthernetPacket, EtherType};
use pnet::packet::arp::{ArpPacket, MutableArpPacket, ArpHardwareType, ArpOperation};
use pnet::util::MacAddr;
use std::env;
use std::thread;
use std::process::exit;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

const ETHER_TYPE_ARP: EtherType = EtherType(0x0806);
const ARP_REQUEST: ArpOperation = ArpOperation(1);
const ARP_REPLY: ArpOperation = ArpOperation(2);

fn main() {
    let ifname = env::args().nth(1).unwrap_or_else(|| {
        println!("usage: host-discovery <interface-name>");
        exit(1);
    });

    let iface = datalink::interfaces()
        .into_iter().filter(|ifa| ifa.name == ifname)
        .next().unwrap_or_else(|| {
            println!("not found device {}", ifname);
            exit(1);
        });

    let self_ip = iface.ips.iter().flat_map(|v| v.iter()).filter_map(|ip| {
        if let &IpAddr::V4(ipv4) = ip {
            Some(ipv4.clone())
        } else {
            None
        }
    }).next().unwrap();
    println!("found device {:?} ({})", iface, self_ip);

    let (mut tx, mut rx) = match datalink::channel(&iface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e),
    };

    let _thrd = thread::spawn(move || {
        let mut it = rx.iter();
        loop {
            match it.next() {
                Ok(eth_pkt) => {
                    if eth_pkt.get_ethertype() == ETHER_TYPE_ARP {
                        if let Some(arp_pkt) = ArpPacket::new(eth_pkt.payload()) {
                            if arp_pkt.get_operation() == ARP_REPLY {
                                let ip_addr = arp_pkt.get_sender_proto_addr();
                                let mac_addr = arp_pkt.get_sender_hw_addr();
                                println!("discovered host {} {}", ip_addr, mac_addr);
                            }
                        }
                    }
                },
                Err(e) => {
                    panic!("An error occurred while reading: {}", e);
                }
            }
        }
    });

    let len = MutableEthernetPacket::minimum_packet_size() + MutableArpPacket::minimum_packet_size();

    let [a,b,c,_] = self_ip.clone().octets();  // TODO: supports other than /24
    for d in 1..255 {
        let target_ip = Ipv4Addr::new(a,b,c,d);
        if target_ip == self_ip {
            continue;
        }

        tx.build_and_send(1, len, &mut |mut eth_pkt| {
            eth_pkt.set_ethertype(ETHER_TYPE_ARP);
            eth_pkt.set_source(iface.mac_address());
            eth_pkt.set_destination(MacAddr::new(0xFF,0xFF,0xFF,0xFF,0xFF,0xFF));
            let mut arp_pkt = MutableArpPacket::new(eth_pkt.payload_mut()).unwrap();
            arp_pkt.set_hardware_type(ArpHardwareType(1));
            arp_pkt.set_protocol_type(EtherType(0x0800));
            arp_pkt.set_hw_addr_len(6);
            arp_pkt.set_proto_addr_len(4);
            arp_pkt.set_operation(ARP_REQUEST);
            arp_pkt.set_sender_hw_addr(iface.mac_address());
            arp_pkt.set_sender_proto_addr(self_ip);
            arp_pkt.set_target_hw_addr(MacAddr::new(0,0,0,0,0,0));
            arp_pkt.set_target_proto_addr(target_ip);
        });
        thread::sleep(Duration::from_millis(100));
    }

    thread::sleep(Duration::from_secs(1));
    exit(0);
}
