use reticulum::hash::AddressHash;
use reticulum::packet::{Packet, PacketContext, PacketType};

pub fn log_inbound_packet(packet: &Packet, our_destinations: &[AddressHash]) {
    let dest = &packet.destination;
    let ptype = &packet.header.packet_type;
    let ctx = &packet.context;

    let is_for_us = our_destinations.iter().any(|d| d == dest);

    let category = match ptype {
        PacketType::Announce => "ANNOUNCE",
        PacketType::LinkRequest => "LINK_REQUEST",
        PacketType::Proof => match ctx {
            PacketContext::LinkRequestProof => "LINK_PROOF",
            _ => "PROOF_OTHER",
        },
        PacketType::Data => "DATA",
    };

    let target = if is_for_us { "FOR_US" } else { "NOT_FOR_US" };

    log::info!(
        "[PACKET_IN] {} {} dest={} ctx={:?} hash={}",
        category,
        target,
        dest,
        ctx,
        packet.hash()
    );
}

pub fn log_outbound_packet(packet: &Packet, reason: &str) {
    let dest = &packet.destination;
    let ptype = &packet.header.packet_type;
    let ctx = &packet.context;

    let category = match ptype {
        PacketType::Announce => "ANNOUNCE",
        PacketType::LinkRequest => "LINK_REQUEST",
        PacketType::Proof => "PROOF",
        PacketType::Data => "DATA",
    };

    log::info!(
        "[PACKET_OUT] {} dest={} ctx={:?} reason={} hash={}",
        category,
        dest,
        ctx,
        reason,
        packet.hash()
    );
}

pub fn log_event(event_name: &str, details: &str) {
    log::info!("[EVENT] {} {}", event_name, details);
}

pub fn log_unhandled_packet(packet: &Packet, reason: &str) {
    log::warn!(
        "[PACKET_UNHANDLED] type={:?} dest={} ctx={:?} reason={}",
        packet.header.packet_type,
        packet.destination,
        packet.context,
        reason
    );
}
