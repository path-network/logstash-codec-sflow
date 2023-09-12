# encoding: utf-8

require 'bindata'
require 'logstash/codecs/sflow/flow_record'
require 'logstash/codecs/sflow/counter_record'

class FlowSampleRecordData < BinData::Choice
  mandatory_parameter :record_length

  raw_packet_header '0-1', :record_length => :record_length
  ethernet_frame_data '0-2'
  ip4_data '0-3'
  ip6_data '0-4'
  extended_switch_data '0-1001'
  extended_router_data '0-1002'
  extended_gateway_data '0-1003'
  extended_user_data '0-1004'
  extended_url_data '0-1005'
  extended_mpls_data '0-1006'
  extended_nat_data '0-1007'
  extended_mpls_tunnel '0-1008'
  extended_mpls_vc '0-1009'
  extended_mpls_ftn '0-1010'
  extended_mpls_ldp_fec '0-1012'
  extended_vlan_tunnel '0-1012'
  extended_l2_tunnel_egress '0-1021'
  extended_l2_tunnel_ingress '0-1022'
  extended_ipv4_tunnel_egress '0-1023'
  extended_ipv4_tunnel_ingress '0-1024'
  extended_ipv6_tunnel_egress '0-1025'
  extended_ipv6_tunnel_ingress '0-1026'
  extended_decapsulate_egress '0-1027'
  extended_decapsulate_ingress '0-1028'
  extended_vni_egress '0-1029'
  extended_vni_ingress '0-1030'
  extended_socket_ipv4 '0-2100'
  extended_socket_ipv6 '0-2101'
  skip :default, :length => :record_length
end

class CounterSampleRecordData < BinData::Choice
  mandatory_parameter :record_length

  generic_interface '0-1'
  ethernet_interfaces '0-2'
  token_ring '0-3'
  hundred_base_vg '0-4'
  vlan '0-5'
  ieee80211_counters '0-6'
  lag_port_stats '0-7'
  processor_information '0-1001'
  radio_utilization '0-1002'
  of_port '0-1004'
  port_name '0-1005'
  host_descr '0-2000'
  host_adapters '0-2001'
  host_parent '0-2002'
  host_cpu '0-2003'
  host_memory '0-2004'
  host_disk_io '0-2005'
  host_net_io '0-2006'
  mib2_ip_group '0-2007'
  mib2_icmp_group '0-2008'
  mib2_tcp_group '0-2009'
  mib2_udp_group '0-2010'
  virt_node '0-2100'
  virt_cpu '0-2101'
  virt_memory '0-2102'
  virt_disk_io '0-2103'
  virt_net_io '0-2104'
  http_counters '0-2201'
  ovs_dp_stats '0-2207'
  skip :default, :length => :record_length
end

# noinspection RubyResolve
class FlowSample < BinData::Record
  endian :big
  uint32 :flow_sequence_number
  uint8 :sourceIdType
  uint24 :sourceIdIndex
  uint32 :samplingRate
  uint32 :samplingPool
  uint32 :drops
  uint32 :input
  uint32 :output
  uint32 :record_count
  array :records, :initial_length => :record_count do
    bit20 :record_entreprise
    bit12 :record_format
    uint32 :record_length
    flow_sample_record_data :record_data,
                            :selection => lambda { "#{record_entreprise}-#{record_format}" },
                            :record_length => :record_length
  end
end

# noinspection RubyResolve
class CounterSample < BinData::Record
  endian :big
  uint32 :sample_seq_number
  uint8 :sourceIdType
  uint24 :sourceIdIndex
  uint32 :record_count
  array :records, :initial_length => :record_count do
    bit20 :record_entreprise
    bit12 :record_format
    uint32 :record_length
    counter_sample_record_data :record_data,
                               :selection => lambda { "#{record_entreprise}-#{record_format}" },
                               :record_length => :record_length
    #processor_information :record_data
  end
end

# noinspection RubyResolve
class ExpandedFlowSample < BinData::Record
  endian :big
  uint32 :flow_sequence_number
  uint32 :sourceIdType
  uint32 :sourceIdIndex
  uint32 :samplingRate
  uint32 :samplePool
  uint32 :drops
  uint32 :inputInterfaceFormat
  uint32 :input
  uint32 :outputInterfaceFormat
  uint32 :output
  uint32 :record_count
  array :records, :initial_length => :record_count do
    bit20 :record_entreprise
    bit12 :record_format
    uint32 :record_length
    flow_sample_record_data :record_data,
                            :selection => lambda { "#{record_entreprise}-#{record_format}" },
                            :record_length => :record_length
  end
end

# noinspection RubyResolve
class ExpandedCounterSample < BinData::Record
  endian :big
  uint32 :sample_seq_number
  uint32 :sourceIdType
  uint32 :sourceIdIndex
  uint32 :record_count
  array :records, :initial_length => :record_count do
    bit20 :record_entreprise
    bit12 :record_format
    uint32 :record_length
    counter_sample_record_data :record_data,
                               :selection => lambda { "#{record_entreprise}-#{record_format}" },
                               :record_length => :record_length
    #processor_information :record_data
  end
end
