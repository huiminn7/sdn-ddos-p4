#include <core.p4>
#include <v1model.p4>

/* ========== CONSTANTS ========== */
#define CPU_PORT 255

/* ========== HEADER DEFINITIONS ========== */
header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<4>  reserved;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

// CPU headers for ONOS communication
header cpu_in_header_t {
    bit<9> ingress_port;
    bit<7> _pad;
}

header cpu_out_header_t {
    bit<9> egress_port;
    bit<7> _pad;
}

struct metadata {
    bit<8> drop;
}

struct headers {
    ethernet_t        ethernet;
    ipv4_t            ipv4;
    tcp_t             tcp;
    cpu_in_header_t   cpu_in;
    cpu_out_header_t  cpu_out;
}

/* ========== PARSER ========== */
parser MyParser(packet_in b, out headers h, inout metadata m, inout standard_metadata_t sm) {
    state start {
        b.extract(h.ethernet);
        transition select(h.ethernet.ether_type) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        b.extract(h.ipv4);
        transition select(h.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }
    state parse_tcp {
        b.extract(h.tcp);
        transition accept;
    }
}

/* ========== INGRESS PIPELINE ========== */
control MyIngress(inout headers h, inout metadata m, inout standard_metadata_t sm) {

    /* Actions */
    action drop() {
        mark_to_drop(sm);
    }

    action forward(bit<9> port) {
        sm.egress_spec = port;
    }
    
    action send_to_cpu() {
        sm.egress_spec = CPU_PORT;
    }

    /* MAC Table for L2 switching */
    table mac_table {
        key = {
            h.ethernet.dst_addr: exact;
        }
        actions = {
            forward;
            drop;
            send_to_cpu;  // Unknown MAC goes to ONOS
        }
        size = 64;
        default_action = send_to_cpu();  // ONOS will learn
    }

    /* DDoS Table - Match on source IP */
    action allow() {
    // do nothing, keep existing egress_spec from mac_table
    }

    table ddos_table {
    	key = {
            h.ipv4.src_addr: exact;
    	}
    	actions = {
            drop;
            allow;
        }
        default_action = allow();
    }

    /* SYN Flood Table */
    table syn_table {
        key = {
            h.ipv4.src_addr: exact;
            h.tcp.flags: exact;
        }
        actions = {
            drop;
            send_to_cpu;
            forward;
        }
        size = 1024;
        default_action = forward(0);
    }
    
    // Handle packet-out from ONOS
    apply {
        // If packet from ONOS, just forward
        if (h.cpu_out.isValid()) {
            sm.egress_spec = h.cpu_out.egress_port;
            h.cpu_out.setInvalid();
            exit;
        }
        
        // Normal processing
        mac_table.apply();
        
        if (h.ipv4.isValid()) {
            if (h.tcp.isValid() && h.tcp.flags == 2) {
                syn_table.apply();
            }
            ddos_table.apply();
        }
    }
}

/* ========== EGRESS PIPELINE ========== */
control MyEgress(inout headers h, inout metadata m, inout standard_metadata_t sm) {
    apply {
        // Packet-in to ONOS
        if (sm.egress_port == CPU_PORT) {
            h.cpu_in.setValid();
            h.cpu_in.ingress_port = sm.ingress_port;
        }
    }
}

/* ========== DEPARSER ========== */
control MyDeparser(packet_out b, in headers h) {
    apply {
        b.emit(h.ethernet);
        b.emit(h.ipv4);
        b.emit(h.tcp);
        b.emit(h.cpu_in);
        b.emit(h.cpu_out);
    }
}

/* ========== NO-OP CONTROLS ========== */
control MyComputeChecksum(inout headers h, inout metadata m) {
    apply { }
}

control MyVerifyChecksum(inout headers h, inout metadata m) {
    apply { }
}

/* ========== MAIN ========== */
V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;
