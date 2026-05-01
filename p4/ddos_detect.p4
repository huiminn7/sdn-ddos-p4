#include <core.p4>
#include <v1model.p4>

#define CPU_PORT 255
#define SYN_THRESHOLD 30
#define ACK_MIN_THRESHOLD 5
#define REG_SIZE 1024

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

header tcp_options_t {
    varbit<320> options;
}

header cpu_in_header_t {
    bit<9> ingress_port;
    bit<7> _pad;
}

header cpu_out_header_t {
    bit<9> egress_port;
    bit<7> _pad;
}

struct metadata {
    bit<32> syn_count;
    bit<32> ack_count;
    bit<1>  trigger_digest;
}

struct headers {
    ethernet_t        ethernet;
    ipv4_t            ipv4;
    tcp_t             tcp;
    tcp_options_t     tcp_options;
    cpu_in_header_t   cpu_in;
    cpu_out_header_t  cpu_out;
}

struct ddos_digest_t {
    bit<32> src_ip;
    bit<32> dst_ip;
    bit<32> syn_count;
    bit<32> ack_count;
    bit<9>  ingress_port;
}

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
        transition select(h.tcp.data_offset) {
            5: accept;                 // 20-byte TCP header, no options
            6: parse_tcp_options_32;    // 4 bytes options
            7: parse_tcp_options_64;    // 8 bytes options
            8: parse_tcp_options_96;    // 12 bytes options
            9: parse_tcp_options_128;   // 16 bytes options
            10: parse_tcp_options_160;  // 20 bytes options
            11: parse_tcp_options_192;  // 24 bytes options
            12: parse_tcp_options_224;  // 28 bytes options
            13: parse_tcp_options_256;  // 32 bytes options
            14: parse_tcp_options_288;  // 36 bytes options
            15: parse_tcp_options_320;  // 40 bytes options
            default: accept;
        }
    }

    state parse_tcp_options_32 {
        b.extract(h.tcp_options, 32w32);
        transition accept;
    }

    state parse_tcp_options_64 {
        b.extract(h.tcp_options, 32w64);
        transition accept;
    }

    state parse_tcp_options_96 {
        b.extract(h.tcp_options, 32w96);
        transition accept;
    }

    state parse_tcp_options_128 {
        b.extract(h.tcp_options, 32w128);
        transition accept;
    }

    state parse_tcp_options_160 {
        b.extract(h.tcp_options, 32w160);
        transition accept;
    }

    state parse_tcp_options_192 {
        b.extract(h.tcp_options, 32w192);
        transition accept;
    }

    state parse_tcp_options_224 {
        b.extract(h.tcp_options, 32w224);
        transition accept;
    }

    state parse_tcp_options_256 {
        b.extract(h.tcp_options, 32w256);
        transition accept;
    }

    state parse_tcp_options_288 {
        b.extract(h.tcp_options, 32w288);
        transition accept;
    }

    state parse_tcp_options_320 {
        b.extract(h.tcp_options, 32w320);
        transition accept;
    }
}

control MyIngress(inout headers h, inout metadata m, inout standard_metadata_t sm) {

    register<bit<32>>(REG_SIZE) syn_counter;
    register<bit<32>>(REG_SIZE) ack_counter;

    action drop() {
        mark_to_drop(sm);
    }

    action forward(bit<9> port) {
        sm.egress_spec = port;
    }

    action send_to_cpu() {
        sm.egress_spec = CPU_PORT;
    }

    action allow() {
    }

        action count_syn() {
        bit<32> idx;
        bit<32> old_syn_count;
        bit<32> new_syn_count;
        bit<32> current_ack_count;

        idx = h.ipv4.src_addr & 32w1023;

        syn_counter.read(old_syn_count, idx);
        new_syn_count = old_syn_count + 1;
        syn_counter.write(idx, new_syn_count);

        ack_counter.read(current_ack_count, idx);

        m.syn_count = new_syn_count;
        m.ack_count = current_ack_count;

        // Trigger only when SYN is high but ACK completion is still low.
        if (new_syn_count >= SYN_THRESHOLD && current_ack_count <= ACK_MIN_THRESHOLD) {
            m.trigger_digest = 1;
        }
    }

    action count_ack() {
        bit<32> idx;
        bit<32> old_ack_count;
        bit<32> new_ack_count;

        idx = h.ipv4.src_addr & 32w1023;

        ack_counter.read(old_ack_count, idx);
        new_ack_count = old_ack_count + 1;
        ack_counter.write(idx, new_ack_count);

        m.ack_count = new_ack_count;
    }

    table mac_table {
        key = {
            h.ethernet.dst_addr: exact;
        }
        actions = {
            forward;
            drop;
            send_to_cpu;
        }
        size = 64;
        default_action = send_to_cpu();
    }

    table ddos_table {
        key = {
            h.ipv4.src_addr: exact;
        }
        actions = {
            drop;
            allow;
        }
        size = 1024;
        default_action = allow();
    }

    apply {
        if (h.cpu_out.isValid()) {
            sm.egress_spec = h.cpu_out.egress_port;
            h.cpu_out.setInvalid();
            exit;
        }

        m.trigger_digest = 0;
        m.syn_count = 0;
        m.ack_count = 0;

        mac_table.apply();

                if (h.ipv4.isValid() && h.tcp.isValid()) {
            // Pure SYN: SYN=1, ACK=0
            // Count only client-side SYN, not server SYN-ACK.
            if (((h.tcp.flags & 8w2) == 8w2) && ((h.tcp.flags & 8w16) == 8w0)) {
                count_syn();
            }

            // Pure ACK: ACK=1, SYN=0
            // Approximation of completed TCP handshake/client ACK.
            if (((h.tcp.flags & 8w16) == 8w16) && ((h.tcp.flags & 8w2) == 8w0)) {
                count_ack();
            }
        }

        if (h.ipv4.isValid()) {
            ddos_table.apply();
        }

        if (m.trigger_digest == 1) {
            ddos_digest_t d;
            d.src_ip = h.ipv4.src_addr;
            d.dst_ip = h.ipv4.dst_addr;
            d.syn_count = m.syn_count;
            d.ack_count = m.ack_count;
            d.ingress_port = sm.ingress_port;
            digest(1, d);
        }
    }
}

control MyEgress(inout headers h, inout metadata m, inout standard_metadata_t sm) {
    apply {
        if (sm.egress_port == CPU_PORT) {
            h.cpu_in.setValid();
            h.cpu_in.ingress_port = sm.ingress_port;
        }
    }
}

control MyDeparser(packet_out b, in headers h) {
    apply {
        b.emit(h.ethernet);
        b.emit(h.ipv4);
        b.emit(h.tcp);
        b.emit(h.tcp_options);
        b.emit(h.cpu_in);
        b.emit(h.cpu_out);
    }
}

control MyComputeChecksum(inout headers h, inout metadata m) {
    apply { }
}

control MyVerifyChecksum(inout headers h, inout metadata m) {
    apply { }
}

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;
