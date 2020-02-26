# encoding: utf-8

require 'bindata'

# noinspection RubyResolve
class GenericInterface < BinData::Record
  endian :big
  uint32 :interface_index
  uint32 :interface_type
  uint64 :interface_speed
  uint32 :interface_direction
  uint32 :interface_status
  uint64 :input_octets
  uint32 :input_packets
  uint32 :input_multicast_packets
  uint32 :input_broadcast_packets
  uint32 :input_discarded_packets
  uint32 :input_errors
  uint32 :input_unknown_protocol_packets
  uint64 :output_octets
  uint32 :output_packets
  uint32 :output_multicast_packets
  uint32 :output_broadcast_packets
  uint32 :output_discarded_packets
  uint32 :output_errors
  uint32 :promiscous_mode
end

# noinspection RubyResolve
class EthernetInterfaces < BinData::Record
  endian :big
  uint32 :dot3StatsAlignmentErrors
  uint32 :dot3StatsFCSErrors
  uint32 :dot3StatsSingleCollisionFrames
  uint32 :dot3StatsMultipleCollisionFrames
  uint32 :dot3StatsSQETestErrors
  uint32 :dot3StatsDeferredTransmissions
  uint32 :dot3StatsLateCollisions
  uint32 :dot3StatsExcessiveCollisions
  uint32 :dot3StatsInternalMacTransmitErrors
  uint32 :dot3StatsCarrierSenseErrors
  uint32 :dot3StatsFrameTooLongs
  uint32 :dot3StatsInternalMacReceiveErrors
  uint32 :dot3StatsSymbolErrors
end

# noinspection RubyResolve
class TokenRing < BinData::Record
  endian :big
  uint32 :dot5StatsLineErrors
  uint32 :dot5StatsBurstErrors
  uint32 :dot5StatsACErrors
  uint32 :dot5StatsAbortTransErrors
  uint32 :dot5StatsInternalErrors
  uint32 :dot5StatsLostFrameErrors
  uint32 :dot5StatsReceiveCongestions
  uint32 :dot5StatsFrameCopiedErrors
  uint32 :dot5StatsTokenErrors
  uint32 :dot5StatsSoftErrors
  uint32 :dot5StatsHardErrors
  uint32 :dot5StatsSignalLoss
  uint32 :dot5StatsTransmitBeacons
  uint32 :dot5StatsRecoverys
  uint32 :dot5StatsLobeWires
  uint32 :dot5StatsRemoves
  uint32 :dot5StatsSingles
  uint32 :dot5StatsFreqErrors
end

# noinspection RubyResolve
class HundredBaseVG < BinData::Record
  endian :big
  uint32 :dot12InHighPriorityFrames
  uint64 :dot12InHighPriorityOctets
  uint32 :dot12InNormPriorityFrames
  uint64 :dot12InNormPriorityOctets
  uint32 :dot12InIPMErrors
  uint32 :dot12InOversizeFrameErrors
  uint32 :dot12InDataErrors
  uint32 :dot12InNullAddressedFrames
  uint32 :dot12OutHighPriorityFrames
  uint64 :dot12OutHighPriorityOctets
  uint32 :dot12TransitionIntoTrainings
  uint64 :dot12HCInHighPriorityOctets
  uint64 :dot12HCInNormPriorityOctets
  uint64 :dot12HCOutHighPriorityOctets
end

# noinspection RubyResolve
class Vlan < BinData::Record
  endian :big
  uint32 :vlan_id
  uint64 :octets
  uint32 :ucastPkts
  uint32 :multicastPkts
  uint32 :broadcastPkts
  uint32 :discards
end

# noinspection RubyResolve
class Ieee80211Counters < BinData::Record
  endian :big
  uint32 :dot11_transmitted_fragments
  uint32 :dot11_multicast_transmitted_frames
  uint32 :dot11_failures
  uint32 :dot11_retries
  uint32 :dot11_multiple_retries
  uint32 :dot11_duplicate_frames
  uint32 :dot11_rts_successes
  uint32 :dot11_rts_failures
  uint32 :dot11_ack_failures
  uint32 :dot11_received_fragments
  uint32 :dot11_multicast_received_frames
  uint32 :dot11_fcs_errors
  uint32 :dot11_transmitted_frames
  uint32 :dot11_wep_undecryptables
  uint32 :dot11_qos_discarded_fragments
  uint32 :dot11_associated_stations
  uint32 :dot11_qos_cf_polls_eceived
  uint32 :dot11_qos_cf_polls_unused
  uint32 :dot11_qos_cf_polls_unusable
  uint32 :dot11_qos_cf_polls_lost
end

# noinspection RubyResolve
class ProcessorInformation < BinData::Record
  endian :big
  uint32 :five_sec_cpu_percent
  uint32 :one_min_cpu_percent
  uint32 :five_min_cpu_percent
  uint64 :total_memory
  uint64 :free_memory
end

# noinspection RubyResolve
class RadioUtilization < BinData::Record
  endian :big
  uint32 :radio_elapsed_time_ms
  uint32 :radio_on_channel_time_ms
  uint32 :radio_on_channel_busy_time_ms
end

# noinspection RubyResolve
class OfPort < BinData::Record
  endian :big
  uint64 :datapath_id
  uint32 :port_no
end

# noinspection RubyResolve
class PortName < BinData::Record
  endian :big
  sflow_string :name
end

# noinspection RubyResolve
class HttpCounters < BinData::Record
  endian :big
  uint32 :method_option_count
  uint32 :method_get_count
  uint32 :method_head_count
  uint32 :method_post_count
  uint32 :method_put_count
  uint32 :method_delete_count
  uint32 :method_trace_count
  uint32 :method_connect_count
  uint32 :method_other_count
  uint32 :status_1XX_count
  uint32 :status_2XX_count
  uint32 :status_3XX_count
  uint32 :status_4XX_count
  uint32 :status_5XX_count
  uint32 :status_other_count
end

# noinspection RubyResolve
class LagPortStats < BinData::Record
  endian :big
  sflow_mac_address :dot3adAggPortActorSystemID
  skip :length => 2
  sflow_mac_address :dot3adAggPortPartnerOperSystemID
  skip :length => 2
  uint32 :dot3adAggPortAttachedAggID
  bit8 :dot3adAggPortActorAdminState
  bit8 :dot3adAggPortActorOperState
  bit8 :dot3adAggPortPartnerAdminState
  bit8 :dot3adAggPortPartnerOperState
  uint32 :dot3adAggPortStatsLACPDUsRx
  uint32 :dot3adAggPortStatsMarkerPDUsRx
  uint32 :dot3adAggPortStatsMarkerResponsePDUsRx
  uint32 :dot3adAggPortStatsUnknownRx
  uint32 :dot3adAggPortStatsIllegalRx
  uint32 :dot3adAggPortStatsLACPDUsTx
  uint32 :dot3adAggPortStatsMarkerPDUsTx
  uint32 :dot3adAggPortStatsMarkerResponsePDUsTx
end

# noinspection RubyResolve
class HostDescr < BinData::Record
  endian :big
  sflow_string :hostname
  array :uuid, :type => :uint8, :initial_length => 16
  uint32 :machine_type
  uint32 :os_name
  sflow_string :os_release
end

# noinspection RubyResolve
class HostAdapters < BinData::Record
  endian :big
  uint32 :adapters_count
  array :adapters, :initial_length => :adapters_count do
    uint32 :if_index
    uint32 :mac_address_count
    array :mac_addresses, :initial_length => :mac_address_count do
      sflow_mac_address :mac_address
      skip :length => 2
    end
  end
end

# noinspection RubyResolve
class HostParent < BinData::Record
  endian :big
  uint32 :container_type
  uint32 :container_index
end

# noinspection RubyResolve
class HostCpu < BinData::Record
  endian :big
  float_be :load_one
  float_be :load_five
  float_be :load_fifteen
  uint32 :proc_run
  uint32 :proc_total
  uint32 :cpu_num
  uint32 :cpu_speed
  uint32 :uptime
  uint32 :cpu_user
  uint32 :cpu_nice
  uint32 :cpu_system
  uint32 :cpu_idle
  uint32 :cpu_wio
  uint32 :cpu_intr
  uint32 :cpu_sintr
  uint32 :interrupts
  uint32 :contexts
  uint32 :cpu_steal
  uint32 :cpu_guest
  uint32 :cpu_guest_nice
end

# noinspection RubyResolve
class HostMemory < BinData::Record
  endian :big
  uint64 :mem_total
  uint64 :mem_free
  uint64 :mem_shared
  uint64 :mem_buffers
  uint64 :mem_cached
  uint64 :swap_total
  uint64 :swap_free
  uint32 :page_in
  uint32 :page_out
  uint32 :swap_in
  uint32 :swap_out
end

# noinspection RubyResolve
class HostDiskIo < BinData::Record
  endian :big
  uint64 :disk_total
  uint64 :disk_free
  uint32 :part_max_used_percent
  uint32 :reads
  uint64 :bytes_read
  uint32 :read_time
  uint32 :writes
  uint64 :bytes_written
  uint32 :write_time
end

# noinspection RubyResolve
class HostNetIo < BinData::Record
  endian :big
  uint64 :bytes_in
  uint32 :pkts_in
  uint32 :errs_in
  uint32 :drops_in
  uint64 :bytes_out
  uint32 :packets_out
  uint32 :errs_out
  uint32 :drops_out
end

# noinspection RubyResolve
class Mib2IpGroup < BinData::Record
  endian :big
  uint32 :ip_forwarding
  uint32 :ip_default_ttl
  uint32 :ip_in_receives
  uint32 :ip_in_hdr_errors
  uint32 :ip_in_addr_errors
  uint32 :ip_forw_datagrams
  uint32 :ip_in_unknown_protos
  uint32 :ip_in_discards
  uint32 :ip_in_delivers
  uint32 :ip_out_requests
  uint32 :ip_out_discards
  uint32 :ip_out_no_routes
  uint32 :ip_reasm_timeout
  uint32 :ip_reasm_reqds
  uint32 :ip_reasm_oks
  uint32 :ip_reasm_fails
  uint32 :ip_frag_oks
  uint32 :ip_frag_fails
  uint32 :ip_frag_creates
end

# noinspection RubyResolve
class Mib2IcmpGroup < BinData::Record
  endian :big
  uint32 :icmp_in_msgs
  uint32 :icmp_in_errors
  uint32 :icmp_in_dest_unreachs
  uint32 :icmp_in_time_excds
  uint32 :icmp_in_param_probs
  uint32 :icmp_in_src_quenchs
  uint32 :icmp_in_redirects
  uint32 :icmp_in_echos
  uint32 :icmp_in_echo_reps
  uint32 :icmp_in_timestamps
  uint32 :icmp_in_addr_masks
  uint32 :icmp_in_addr_mask_reps
  uint32 :icmp_out_msgs
  uint32 :icmp_out_errors
  uint32 :icmp_out_dest_unreachs
  uint32 :icmp_out_time_excds
  uint32 :icmp_out_param_probs
  uint32 :icmp_out_src_quenchs
  uint32 :icmp_out_redirects
  uint32 :icmp_out_echos
  uint32 :icmp_out_echo_reps
  uint32 :icmp_out_timestamps
  uint32 :icmp_out_timestamp_reps
  uint32 :icmp_out_addr_masks
  uint32 :icmp_out_addr_mask_reps
end

# noinspection RubyResolve
class Mib2TcpGroup < BinData::Record
  endian :big
  uint32 :tcp_rto_algorithm
  uint32 :tcp_rto_min
  uint32 :tcp_rto_max
  uint32 :tcp_max_conn
  uint32 :tcp_active_opens
  uint32 :tcp_passive_opens
  uint32 :tcp_attempt_fails
  uint32 :tcp_estab_resets
  uint32 :tcp_curr_estab
  uint32 :tcp_in_segs
  uint32 :tcp_out_segs
  uint32 :tcp_retrans_segs
  uint32 :tcp_in_errs
  uint32 :tcp_out_rsts
  uint32 :tcp_in_csum_errs
end

# noinspection RubyResolve
class Mib2UdpGroup < BinData::Record
  endian :big
  uint32 :udp_in_datagrams
  uint32 :udp_no_ports
  uint32 :udp_in_errors
  uint32 :udp_out_datagrams
  uint32 :udp_rcvbuf_errors
  uint32 :udp_sndbuf_errors
  uint32 :udp_in_csum_errors
end

# noinspection RubyResolve
class VirtNode < BinData::Record
  endian :big
  uint32 :mhz
  uint32 :cpus
  uint64 :memory
  uint64 :memory_free
  uint32 :num_domains
end

# noinspection RubyResolve
class VirtCpu < BinData::Record
  endian :big
  uint32 :state
  uint32 :cpu_time
  uint32 :nr_virt_cpu
end

# noinspection RubyResolve
class VirtMemory < BinData::Record
  endian :big
  uint64 :memory
  uint64 :max_memory
end

# noinspection RubyResolve
class VirtDiskIo < BinData::Record
  endian :big
  uint64 :capacity
  uint64 :allocation
  uint64 :physical
  uint32 :rd_req
  uint64 :rd_bytes
  uint32 :wr_req
  uint64 :wr_bytes
  uint32 :errs
end

# noinspection RubyResolve
class VirtNetIo < BinData::Record
  endian :big
  uint64 :rx_bytes
  uint32 :rx_packets
  uint32 :rx_errs
  uint32 :rx_drop
  uint64 :tx_bytes
  uint32 :tx_packets
  uint32 :tx_errs
  uint32 :tx_drop
end

# noinspection RubyResolve
class OvsDpStats < BinData::Record
  endian :big
  uint32 :ovs_dp_hits                                                
  uint32 :ovs_dp_misses
  uint32 :ovs_dp_lost
  uint32 :ovs_dp_mask_hits
  uint32 :ovs_dp_flows
  uint32 :ovs_dp_masks
end
