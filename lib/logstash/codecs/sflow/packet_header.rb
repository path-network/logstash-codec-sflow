# encoding: utf-8

require 'bindata'
require 'logstash/codecs/sflow/util'


# noinspection RubyResolve
class UnknownHeader < BinData::Record
  mandatory_parameter :size_header

  endian :big
  bit :data, :nbits => :size_header
end


# noinspection RubyResolve,RubyResolve
class TcpHeader < BinData::Record
  mandatory_parameter :size_header

  endian :big
  uint16 :srcPort
  uint16 :dstPort
  uint32 :tcp_seq_number
  uint32 :tcp_ack_number
  bit4 :tcp_header_length # times 4
  bit3 :tcp_reserved
  bit1 :tcp_is_nonce
  bit1 :tcp_is_cwr
  bit1 :tcp_is_ecn_echo
  bit1 :tcp_is_urgent
  bit1 :tcp_is_ack
  bit1 :tcp_is_push
  bit1 :tcp_is_reset
  bit1 :tcp_is_syn
  bit1 :tcp_is_fin
  uint16 :tcp_window_size
  uint16 :tcp_checksum
  uint16 :tcp_urgent_pointer
  array :tcp_options, :initial_length => lambda { tcp_header_length - 5 }, :onlyif => lambda { is_options?(size_header) } do
    string :tcp_option, :length => 4, :pad_byte => "\0"
  end
  bit :data, :nbits => lambda { size_header - data.rel_offset * 8 }

  def is_options?(size_header)
    tcp_header_length.to_i > 5 and size_header >= tcp_header_length * 4 * 8
  end
end

# noinspection RubyResolve
class UdpHeader < BinData::Record
  mandatory_parameter :size_header

  endian :big
  uint16 :srcPort
  uint16 :dstPort
  uint16 :udp_length
  uint16 :udp_checksum
  bit :data, :nbits => lambda { size_header - 64 } #skip udp data
end

# noinspection RubyResolve,RubyResolve
class IPV4Header < BinData::Record
  mandatory_parameter :size_header

  endian :big
  bit4 :ipVersion
  bit4 :ip_header_length # times 4
  bit6 :ip_dscp
  bit2 :ip_ecn
  uint16 :ip_total_length
  uint16 :ip_identification
  bit3 :ip_flags
  bit13 :ip_fragment_offset
  uint8 :ip_ttl
  uint8 :protocol
  uint16 :ip_checksum
  sflow_ip4_addr :srcIpv4
  sflow_ip4_addr :dstIpv4
  array :ip_options, :initial_length => lambda { ip_header_length - 5 }, :onlyif => :is_options? do
    string :ip_option, :length => 4, :pad_byte => "\0"
  end
  choice :ip_data, :selection => :protocol, :onlyif => lambda { has_data?(size_header) } do
    tcp_header 6, :size_header => lambda { size_header - (ip_header_length * 4 * 8) }
    udp_header 17, :size_header => lambda { size_header - (ip_header_length * 4 * 8) }
    unknown_header :default, :size_header => lambda { size_header - (ip_header_length * 4 * 8) }
  end

  def has_data?(size_header)
    bytes_left = size_header / 8 - ip_header_length * 4
    case protocol
    when 6
      return bytes_left >= 20
    when 17
      return bytes_left >= 8
    else
      return true
    end
  end

  def is_options?
    ip_header_length.to_i > 5
  end
end

# noinspection RubyResolve
class IPV6Header < BinData::Record
  mandatory_parameter :size_header

  endian :big
  bit4 :ipVersion
  bit6 :ip_dscp
  bit2 :ip_ecn
  bit20 :ipv6_flow_label
  uint16 :ip_payload_length
  uint8 :protocol
  uint8 :ipv6_hop_limit
  sflow_ip6_addr :srcIp
  sflow_ip6_addr :dstIp
  choice :ip_data, :selection => :protocol do
    tcp_header 6, :size_header => lambda { size_header - 320 }
    udp_header 17, :size_header => lambda { size_header - 320 }
    unknown_header :default, :size_header => lambda { size_header - 320 }
  end
end

# noinspection RubyResolve
class VLANHeader < BinData::Record
  mandatory_parameter :size_header

  endian :big
  bit3 :vlan_priority
  bit1 :vlan_cfi
  bit12 :vlanId
  uint16 :vlan_type
  choice :vlan_data, :selection => :vlan_type do
    ipv4_header 2048, :size_header => lambda { size_header - (4 * 8) }
    ipv6_header 34525, :size_header => lambda { size_header - (4 * 8) }
    unknown_header :default, :size_header => lambda { size_header - (4 * 8) }
  end
end

# noinspection RubyResolve
class EthernetHeader < BinData::Record
  mandatory_parameter :size_header

  endian :big
  sflow_mac_address :ethDst
  sflow_mac_address :ethSrc
  uint16 :eth_type
  choice :eth_data, :selection => :eth_type do
    ipv4_header 2048, :size_header => lambda { size_header - (14 * 8) }
    vlan_header 33024, :size_header => lambda { size_header - (14 * 8) }
    ipv6_header 34525, :size_header => lambda { size_header - (14 * 8) }
    unknown_header :default, :size_header => lambda { size_header - (14 * 8) }
  end
end
