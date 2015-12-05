require 'bindata'
require 'logstash/codecs/sflow/util'

class RawPacketHeader < BinData::Record
  endian :big
  uint32 :protocol
  uint32 :frame_length
  uint32 :stripped
  uint32 :header_size
  skip :length => :header_size
end

class EthernetFrameData < BinData::Record
  endian :big
  uint32 :packet_length
  uint8 :src_mac
  uint8 :dst_mac
  uint32 :type
end

class IP4Data < BinData::Record
  endian :big
  uint32 :ip_packet_length
  uint32 :ip_protocol
  ip4_addr :src_ip
  ip4_addr :dst_ip
  uint32 :src_port
  uint32 :dst_port
  uint32 :tcp_flags
  uint32 :type
end

class IP6Data < BinData::Record
  endian :big
  uint32 :ip_packet_length
  uint32 :ip_next_header
  ip6_addr :src_ip
  ip6_addr :dst_ip
  uint32 :src_port
  uint32 :dst_port
  uint32 :tcp_flags
  uint32 :ip_priority
end

class ExtendedSwitchData < BinData::Record
  endian :big
  uint32 :src_vlan
  uint32 :src_priority
  uint32 :dst_vlan
  uint32 :dst_priority
end

class ExtendedRouterData < BinData::Record
  endian :big
  uint32 :ip_version
  choice :ip_address_next_hop_router, :selection => :ip_version do
    ip4_addr 1
    ip6_addr 2
  end
  uint32 :src_mask_len
  uint32 :dst_mask_len
end
