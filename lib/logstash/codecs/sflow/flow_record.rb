# encoding: utf-8

require 'bindata'
require 'logstash/codecs/sflow/util'
require 'logstash/codecs/sflow/packet_header'

# noinspection RubyResolve
class RawPacketHeader < BinData::Record
  mandatory_parameter :record_length

  endian :big
  uint32 :protocol
  uint32 :frame_length
  uint32 :stripped
  uint32 :header_size
  choice :sample_header, :selection => :protocol do
    ethernet_header 1, :size_header => lambda { header_size * 8 }
    ip_header 11, :size_header => lambda { header_size * 8 }
    skip :default, :length => :header_size
  end
  bit :padded, :nbits => lambda { (record_length - (header_size + 16)) * 8 } #padded data
end

# noinspection RubyResolve
class EthernetFrameData < BinData::Record
  endian :big
  uint32 :packet_length
  sflow_mac_address :src_mac
  skip :length => 2
  sflow_mac_address :dst_mac
  skip :length => 2
  uint32 :eth_type
end

# noinspection RubyResolve
class IP4Data < BinData::Record
  endian :big
  uint32 :ip_packet_length
  uint32 :ip_protocol
  sflow_ip4_addr :src_ip
  sflow_ip4_addr :dst_ip
  uint32 :src_port
  uint32 :dst_port
  uint32 :tcp_flags
  uint32 :ip_type
end

# noinspection RubyResolve
class IP6Data < BinData::Record
  endian :big
  uint32 :ip_packet_length
  uint32 :ip_next_header
  sflow_ip6_addr :src_ip
  sflow_ip6_addr :dst_ip
  uint32 :src_port
  uint32 :dst_port
  uint32 :tcp_flags
  uint32 :ip_priority
end

# noinspection RubyResolve
class ExtendedSwitchData < BinData::Record
  endian :big
  uint32 :src_vlan
  uint32 :src_priority
  uint32 :dst_vlan
  uint32 :dst_priority
end

# noinspection RubyResolve
class ExtendedRouterData < BinData::Record
  endian :big
  uint32 :ip_version
  choice :ip_address_next_hop_router, :selection => :ip_version do
    sflow_ip4_addr 1
    sflow_ip6_addr 2
  end
  uint32 :src_mask_len
  uint32 :dst_mask_len
end
