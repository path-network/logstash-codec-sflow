# encoding: utf-8

require 'bindata'
require 'logstash/codecs/sflow/util'


class TcpHeader < BinData::Record
  mandatory_parameter :size_header

  endian :big
  uint16 :src_port
  uint16 :dst_port
  uint32 :tcp_seq_number
  uint32 :tcp_ack_number
  bit4 :tcp_header_length # times 4
  bit3 :reserved
  bit1 :is_nonce
  bit1 :is_cwr
  bit1 :is_ecn_echo
  bit1 :is_urgent
  bit1 :is_ack
  bit1 :is_push
  bit1 :is_reset
  bit1 :is_syn
  bit1 :is_fin
  uint16 :window_size
  uint16 :tcp_checksum
  uint16 :urgent_pointer
  array :options, :initial_length => lambda { (((tcp_header_length * 4) - 20)/4).ceil }, :onlyif => :is_options? do
    string :option, :length => 4, :pad_byte => "\0"
  end
  bit :nbits => lambda { size_header - (tcp_header_length * 4 * 8) }

  def is_options?
    tcp_header_length.to_i > 5
  end
end

class UdpHeader < BinData::Record
  endian :big
  uint16 :src_port
  uint16 :dst_port
  uint16 :udp_length
  uint16 :udp_checksum
  skip :length => lambda { udp_length - 64 } #skip udp data
end

class IPV4Header < BinData::Record
  mandatory_parameter :size_header

  endian :big
  bit4 :ip_header_length # times 4
  bit6 :dscp
  bit2 :ecn
  uint16 :total_length
  uint16 :identification
  bit3 :flags
  bit13 :fragment_offset
  uint8 :ttl
  uint8 :protocol
  uint16 :checksum
  ip4_addr :src_ip
  ip4_addr :dst_ip
  array :options, :initial_length => lambda { (((ip_header_length * 4) - 20)/4).ceil }, :onlyif => :is_options? do
    string :option, :length => 4, :pad_byte => "\0"
  end
  choice :layer4, :selection => :protocol do
    tcp_header 6, :size_header => lambda { size_header - (ip_header_length * 4 * 8) }
    udp_header 17
    bit :default, :nbits => lambda { size_header - (ip_header_length * 4 * 8) }
  end

  def is_options?
    ip_header_length.to_i > 5
  end
end

class IPHeader < BinData::Record
  mandatory_parameter :size_header

  endian :big
  bit4 :version
  choice :header, :selection => :version do
    ipv4_header 4, :size_header => :size_header
    bit :default, :nbits => lambda { size_header - 4 }
  end
end

class EthernetHeader < BinData::Record
  mandatory_parameter :size_header

  endian :big
  mac_address :eth_src
  mac_address :eth_dst
  uint16 :eth_type
  choice :eth_data, :selection => :eth_type do
    ip_header 2048, :size_header => :size_header
    bit :default, :nbits => lambda { size_header - 28 }
  end
end
