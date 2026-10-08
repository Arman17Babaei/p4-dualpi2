#include <core.p4>
#include <v1model.p4>

#define WRITE_PORT_REG(r, v) r.write((bit<32>) standard_metadata.egress_port, v)
#define READ_PORT_REG(r, v) r.read(v, (bit<32>) standard_metadata.egress_port)

const bit<16> TYPE_IPV4 = 16w0x0800;
const bit<32> MAX_PROB = 32w0xFFFFFFFF;
const bit<33> PROB_ONE = 33w0x100000000;
const int<64> MAX_PROB_I64 = 4294967295;
const bit<32> PORT_REGISTER_SIZE = 512;
const bit<32> MAX_UPDATE_LAPS = 1024;
const int<32> DEFAULT_ALPHA_Q32_PER_US = 687;
const int<32> DEFAULT_BETA_Q32_PER_US  = 13744;
const int<32> DEFAULT_TARGET_US        = 15000;
const bit<32> DEFAULT_UPDATE_US        = 32w16000;
const bit<8>  DEFAULT_COUPLING_FACTOR  = 8w2;
const bit<32> DEFAULT_OVERLOAD_BASE_P  = 32w0x7FFFFFFF;
const bit<1>  DEFAULT_DROP_OVERLOAD    = 1w1;
const int<32> DEFAULT_L4S_MIN_US       = 5000;
const int<32> DEFAULT_L4S_RANGE_US     = 0;
const bit<32> DEFAULT_L4S_SLOPE_Q32_PER_US = 32w0;
const bit<19> DEFAULT_L4S_MIN_QUEUE_PKTS   = 19w0;
const bit<19> DEFAULT_COUPLED_MIN_BACKLOG_PKTS = 19w2;
const bit<32> DEFAULT_STATE_TIMEOUT_US = 32w65536;
const bit<32> DEFAULT_IDLE_RESET_US    = 32w1000000;

typedef bit<9>  egressSpec_t; typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t; typedef int<32> gain_t; typedef int<32> delay_t;
typedef bit<8>  coupling_t; typedef bit<1>  flag_t;

register<bit<48>>(PORT_REGISTER_SIZE) r_update_time;
register<int<32>>(PORT_REGISTER_SIZE) r_last_qdelay;
register<bit<32>>(PORT_REGISTER_SIZE) r_probability;
register<int<32>>(PORT_REGISTER_SIZE) r_qdelay_c;
register<int<32>>(PORT_REGISTER_SIZE) r_qdelay_l;
register<bit<32>>(PORT_REGISTER_SIZE) r_qdepth_c;
register<bit<32>>(PORT_REGISTER_SIZE) r_qdepth_l;
register<bit<48>>(PORT_REGISTER_SIZE) r_last_seen_c;
register<bit<48>>(PORT_REGISTER_SIZE) r_last_seen_l;
register<bit<32>>(PORT_REGISTER_SIZE) r_recur_c;
register<bit<32>>(PORT_REGISTER_SIZE) r_recur_l_mark;
register<bit<32>>(PORT_REGISTER_SIZE) r_recur_l_drop;
register<bit<32>>(PORT_REGISTER_SIZE) r_dropped;

header ethernet_t { macAddr_t dstAddr; macAddr_t srcAddr; bit<16>   etherType; }
header ipv4_t {
    bit<4>    version; bit<4>    ihl; bit<6>    diffserv; bit<2>    ecn;
    bit<16>   totalLen; bit<16>   identification; bit<3>    flags;
    bit<13>   fragOffset; bit<8>    ttl; bit<8>    protocol;
    bit<16>   hdrChecksum; ip4Addr_t srcAddr; ip4Addr_t dstAddr;
}
struct metadata { bit<1> mark_drop; bit<1> is_l4s; bit<1> unsupported_ipv4; }
struct headers { ethernet_t ethernet; ipv4_t     ipv4; }

parser MyParser(packet_in packet, out headers hdr, inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        meta.mark_drop = 1w0; meta.is_l4s = 1w0; meta.unsupported_ipv4 = 1w0;
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4; default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.version, hdr.ipv4.ihl) {
            (4w4, 4w5): accept;
            default: unsupported_ipv4;
        }
    }
    state unsupported_ipv4 { meta.unsupported_ipv4 = 1w1; transition accept; }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(hdr.ipv4.isValid() && meta.unsupported_ipv4 == 1w0,
            { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.ecn,
              hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags,
              hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol,
              hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control MyIngress(inout headers hdr, inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() { mark_to_drop(standard_metadata); }
    action ipv4_forward(macAddr_t srcAddr, macAddr_t dstAddr,
                        egressSpec_t port) {
        standard_metadata.egress_spec = port; hdr.ethernet.srcAddr = srcAddr;
        hdr.ethernet.dstAddr = dstAddr; hdr.ipv4.ttl = hdr.ipv4.ttl - 8w1;
    }
    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { ipv4_forward; drop; }
        size = 1024; default_action = drop();
    }
    apply {
        if (standard_metadata.parser_error != error.NoError) {
            mark_to_drop(standard_metadata);
        } else if (hdr.ipv4.isValid()) {
            if (meta.unsupported_ipv4 == 1w1 ||
                standard_metadata.checksum_error == 1w1) {
                mark_to_drop(standard_metadata);
            } else if (hdr.ipv4.ttl <= 8w1) {
                mark_to_drop(standard_metadata);
            } else {
                meta.is_l4s = ((hdr.ipv4.ecn & 2w1) != 2w0) ? 1w1 : 1w0;
                standard_metadata.priority = (meta.is_l4s == 1w1) ? 3w1 : 3w0;
                ipv4_lpm.apply();
            }
        }
    }
}

control MyEgress(inout headers hdr, inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action drop_and_count() {
        bit<32> dropped_packets = 0; mark_to_drop(standard_metadata);
        READ_PORT_REG(r_dropped, dropped_packets);
        if (dropped_packets != MAX_PROB) {
            dropped_packets = dropped_packets + 32w1;
        }
        WRITE_PORT_REG(r_dropped, dropped_packets);
    }
    action dualpi2(gain_t alpha_q32_per_us, gain_t beta_q32_per_us,
                   delay_t target_us, coupling_t coupling_factor,
                   bit<32> overload_base_prob, flag_t drop_on_overload,
                   delay_t l4s_min_us, delay_t l4s_range_us,
                   bit<32> l4s_slope_q32_per_us, bit<19> l4s_min_queue_pkts,
                   bit<19> coupled_min_backlog_pkts, bit<32> state_timeout_us,
                   bit<32> idle_reset_us, flag_t export_qdelay_in_ipv4_id) {
        bit<48> now = standard_metadata.egress_global_timestamp;
        bit<48> last_update_time = 0; int<32> last_qdelay_max = 0;
        bit<32> base_prob = 0; int<32> qdelay_c = 0; int<32> qdelay_l = 0;
        bit<32> qdepth_c = 0; bit<32> qdepth_l = 0; bit<48> last_seen_c = 0;
        bit<48> last_seen_l = 0; bit<32> recur_c = 0; bit<32> recur_l_mark = 0;
        bit<32> recur_l_drop = 0; int<32> qdelay_now = 0;
        bit<32> qdepth_now = (bit<32>) standard_metadata.deq_qdepth;
        bit<1> classic_hit = 1w0; bit<1> l4s_mark_hit = 1w0;
        bit<1> l4s_drop_hit = 1w0;
        READ_PORT_REG(r_update_time, last_update_time);
        READ_PORT_REG(r_last_qdelay, last_qdelay_max);
        READ_PORT_REG(r_probability, base_prob);
        READ_PORT_REG(r_qdelay_c, qdelay_c);
        READ_PORT_REG(r_qdelay_l, qdelay_l);
        READ_PORT_REG(r_qdepth_c, qdepth_c);
        READ_PORT_REG(r_qdepth_l, qdepth_l);
        READ_PORT_REG(r_last_seen_c, last_seen_c);
        READ_PORT_REG(r_last_seen_l, last_seen_l);
        READ_PORT_REG(r_recur_c, recur_c);
        READ_PORT_REG(r_recur_l_mark, recur_l_mark);
        READ_PORT_REG(r_recur_l_drop, recur_l_drop);
        if (standard_metadata.deq_timedelta > 32w0x7FFFFFFF) {
            qdelay_now = 2147483647;
        } else { qdelay_now = (int<32>) standard_metadata.deq_timedelta; }
        if (export_qdelay_in_ipv4_id == 1w1) {
            hdr.ipv4.identification = (qdelay_now > 65535) ? 16w0xFFFF :
                (bit<16>) (bit<32>) qdelay_now;
        }
        if (meta.is_l4s == 1w1) {
            last_seen_l = now; qdepth_l = qdepth_now;
            qdelay_l = (qdepth_now == 0) ? 0 : qdelay_now;
        } else {
            last_seen_c = now; qdepth_c = qdepth_now;
            qdelay_c = (qdepth_now == 0) ? 0 : qdelay_now;
        }
        if (state_timeout_us != 0) {
            if (last_seen_c == 0 ||
                (now - last_seen_c) > (bit<48>) state_timeout_us) {
                qdelay_c = 0; qdepth_c = 0;
            }
            if (last_seen_l == 0 ||
                (now - last_seen_l) > (bit<48>) state_timeout_us) {
                qdelay_l = 0; qdepth_l = 0;
            }
        }
        bit<32> aggregate_backlog_pkts = qdepth_c + qdepth_l + 32w1;
        bit<1> allow_coupled_aqm = (aggregate_backlog_pkts >=
             (bit<32>) coupled_min_backlog_pkts) ? 1w1 : 1w0;
        int<32> qdelay_max = (qdelay_l > qdelay_c) ? qdelay_l : qdelay_c;
        if (last_update_time == 0) {
            last_update_time = now; last_qdelay_max = qdelay_max;
        } else {
            bit<48> elapsed_us = now - last_update_time;
            if (idle_reset_us != 0 && elapsed_us >= (bit<48>) idle_reset_us) {
                base_prob = 0; last_qdelay_max = 0; last_update_time = now;
                recur_c = 0; recur_l_mark = 0; recur_l_drop = 0;
            } else {
                bit<48> update_laps_48 =
                    (elapsed_us >= (bit<48>) DEFAULT_UPDATE_US) ? 48w1 : 48w0;
                bit<32> update_laps = (bit<32>) update_laps_48;
                bit<1> laps_capped = 1w0;
                if (update_laps > MAX_UPDATE_LAPS) {
                    update_laps = MAX_UPDATE_LAPS; laps_capped = 1w1;
                }
                if (update_laps >= 1) {
                    int<64> error_us =
                        (int<64>) qdelay_max - (int<64>) target_us;
                    int<64> delta_q_us = (int<64>) qdelay_max -
                        (int<64>) last_qdelay_max;
                    int<64> alpha_term = (int<64>) (bit<64>) update_laps *
                        error_us * (int<64>) alpha_q32_per_us;
                    int<64> beta_term = delta_q_us * (int<64>) beta_q32_per_us;
                    int<64> delta_prob = alpha_term + beta_term;
                    int<64> candidate_prob =
                        (int<64>) (bit<64>) base_prob + delta_prob;
                    if (candidate_prob <= 0) {
                        base_prob = 0;
                    } else if (candidate_prob >= MAX_PROB_I64) {
                        base_prob = MAX_PROB;
                    } else { base_prob = (bit<32>) (bit<64>) candidate_prob; }
                    if (drop_on_overload == 1w0 && coupling_factor != 0 &&
                        base_prob > overload_base_prob) {
                        base_prob = overload_base_prob;
                    }
                    if (laps_capped == 1w1) {
                        last_update_time = now;
                    } else {
                        bit<48> advance_us = (bit<48>) update_laps *
                            (bit<48>) DEFAULT_UPDATE_US;
                        last_update_time = last_update_time + advance_us;
                    }
                    last_qdelay_max = qdelay_max;
                }
            }
        }
        bit<64> classic_prob_64 = (bit<64>) base_prob * (bit<64>) base_prob;
        bit<32> classic_prob = (bit<32>) (classic_prob_64 >> 32);
        if (base_prob == MAX_PROB) { classic_prob = MAX_PROB; }
        bit<64> coupled_prob_64 =
            (bit<64>) base_prob * (bit<64>) coupling_factor;
        bit<32> coupled_prob = (coupled_prob_64 >= (bit<64>) MAX_PROB)
                ? MAX_PROB : (bit<32>) coupled_prob_64;
        bit<1> overload = (drop_on_overload == 1w1 && coupling_factor != 0 &&
             base_prob >= overload_base_prob) ? 1w1 : 1w0;
        bit<32> native_l4s_prob = 0;
        if (meta.is_l4s == 1w1 &&
            standard_metadata.enq_qdepth >= l4s_min_queue_pkts &&
            qdelay_now > l4s_min_us) {
            if (l4s_range_us <= 0) {
                native_l4s_prob = MAX_PROB;
            } else {
                int<64> l4s_max_us = (int<64>) l4s_min_us +
                    (int<64>) l4s_range_us;
                if ((int<64>) qdelay_now >= l4s_max_us) {
                    native_l4s_prob = MAX_PROB;
                } else {
                    bit<32> excess_us = (bit<32>) (qdelay_now - l4s_min_us);
                    bit<64> ramp_prob_64 = (bit<64>) excess_us *
                        (bit<64>) l4s_slope_q32_per_us;
                    native_l4s_prob = (ramp_prob_64 >= (bit<64>) MAX_PROB)
                            ? MAX_PROB : (bit<32>) ramp_prob_64;
                }
            }
        }
        bit<32> l4s_prob = (native_l4s_prob > coupled_prob) ? native_l4s_prob
                : coupled_prob;
        if (allow_coupled_aqm == 1w0) {
            recur_c = 0; recur_l_drop = 0;
        } else if (meta.is_l4s == 1w0) {
            if (classic_prob == MAX_PROB) {
                classic_hit = 1w1; recur_c = 0;
            } else if (classic_prob != 0) {
                bit<33> classic_sum =
                    (bit<33>) recur_c + (bit<33>) classic_prob;
                if (classic_sum >= PROB_ONE) {
                    classic_hit = 1w1;
                    recur_c = (bit<32>) (classic_sum - PROB_ONE);
                } else { recur_c = (bit<32>) classic_sum; }
            }
        } else if (overload == 1w1) {
            if (classic_prob == MAX_PROB) {
                l4s_drop_hit = 1w1; recur_l_drop = 0;
            } else if (classic_prob != 0) {
                bit<33> l4s_drop_sum = (bit<33>) recur_l_drop +
                    (bit<33>) classic_prob;
                if (l4s_drop_sum >= PROB_ONE) {
                    l4s_drop_hit = 1w1;
                    recur_l_drop = (bit<32>) (l4s_drop_sum - PROB_ONE);
                } else { recur_l_drop = (bit<32>) l4s_drop_sum; }
            }
        } else { recur_l_drop = 0; }
        bit<32> effective_l4s_prob = native_l4s_prob;
        if (allow_coupled_aqm == 1w1) {
            effective_l4s_prob = (overload == 1w1) ? MAX_PROB : l4s_prob;
        }
        if (meta.is_l4s == 1w1 && l4s_drop_hit == 1w0) {
            if (effective_l4s_prob == MAX_PROB) {
                l4s_mark_hit = 1w1; recur_l_mark = 0;
            } else if (effective_l4s_prob != 0) {
                bit<33> l4s_mark_sum = (bit<33>) recur_l_mark +
                    (bit<33>) effective_l4s_prob;
                if (l4s_mark_sum >= PROB_ONE) {
                    l4s_mark_hit = 1w1;
                    recur_l_mark = (bit<32>) (l4s_mark_sum - PROB_ONE);
                } else { recur_l_mark = (bit<32>) l4s_mark_sum; }
            }
        }
        bit<2> ecn = hdr.ipv4.ecn; bit<1> not_ect = (ecn == 2w0) ? 1w1 : 1w0;
        if (meta.is_l4s == 1w0) {
            if (allow_coupled_aqm == 1w1 && classic_hit == 1w1) {
                if (not_ect == 1w1 || overload == 1w1) {
                    meta.mark_drop = 1w1;
                } else { hdr.ipv4.ecn = 2w3; }
            }
        } else {
            if (allow_coupled_aqm == 1w1 && overload == 1w1 &&
                l4s_drop_hit == 1w1) {
                meta.mark_drop = 1w1;
            } else if (l4s_mark_hit == 1w1) { hdr.ipv4.ecn = 2w3; }
        }
        WRITE_PORT_REG(r_qdelay_c, qdelay_c);
        WRITE_PORT_REG(r_qdelay_l, qdelay_l);
        WRITE_PORT_REG(r_qdepth_c, qdepth_c);
        WRITE_PORT_REG(r_qdepth_l, qdepth_l);
        WRITE_PORT_REG(r_last_seen_c, last_seen_c);
        WRITE_PORT_REG(r_last_seen_l, last_seen_l);
        WRITE_PORT_REG(r_recur_c, recur_c);
        WRITE_PORT_REG(r_recur_l_mark, recur_l_mark);
        WRITE_PORT_REG(r_recur_l_drop, recur_l_drop);
        WRITE_PORT_REG(r_probability, base_prob);
        WRITE_PORT_REG(r_last_qdelay, last_qdelay_max);
        WRITE_PORT_REG(r_update_time, last_update_time);
    }
    table aqm {
        key = { standard_metadata.egress_port: exact; }
        actions = { dualpi2; NoAction; }
        size = 512;
        default_action = dualpi2( DEFAULT_ALPHA_Q32_PER_US,
            DEFAULT_BETA_Q32_PER_US, DEFAULT_TARGET_US, DEFAULT_COUPLING_FACTOR,
            DEFAULT_OVERLOAD_BASE_P, DEFAULT_DROP_OVERLOAD, DEFAULT_L4S_MIN_US,
            DEFAULT_L4S_RANGE_US, DEFAULT_L4S_SLOPE_Q32_PER_US,
            DEFAULT_L4S_MIN_QUEUE_PKTS, DEFAULT_COUPLED_MIN_BACKLOG_PKTS,
            DEFAULT_STATE_TIMEOUT_US, DEFAULT_IDLE_RESET_US, 1w0);
    }
    apply {
        meta.mark_drop = 1w0;
        if (hdr.ipv4.isValid()) {
            aqm.apply();
            if (meta.mark_drop == 1w1) { drop_and_count(); }
        }
    }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(hdr.ipv4.isValid() && meta.unsupported_ipv4 == 1w0,
            { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.ecn,
              hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags,
              hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol,
              hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply { packet.emit(hdr.ethernet); packet.emit(hdr.ipv4); }
}

V1Switch( MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(),
    MyComputeChecksum(), MyDeparser() ) main;
