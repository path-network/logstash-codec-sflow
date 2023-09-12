# encoding: utf-8

require 'bindata'
require 'logstash/codecs/sflow/util'
require 'logstash/codecs/sflow/packet_header'

# noinspection RubyResolve
class RawPacketHeader < BinData::Buffer
  mandatory_parameter :record_length
  default_parameters :length => :record_length

  endian :big
  uint32 :headerProtocol
  #@author jeonhn
  #@change-date : 2018. 7. 13.
  #@fix : packets to frame_length
  uint32 :packets
  uint32 :stripped
  uint32 :header_size
  choice :sample_header, :selection => :headerProtocol do
    ethernet_header 1, :size_header => lambda { header_size * 8 }
    ipv4_header 11, :size_header => lambda { header_size * 8 }
    ipv6_header 12, :size_header => lambda { header_size * 8 }
    skip :default, :length => :header_size
  end
end

# noinspection RubyResolve
class EthernetFrameData < BinData::Record
  endian :big
  uint32 :packet_length
  sflow_mac_address :srcMac
  skip :length => 2
  sflow_mac_address :dstMac
  skip :length => 2
  uint32 :eth_type
end

# noinspection RubyResolve
class IP4Data < BinData::Record
  endian :big
  uint32 :ip_packet_length
  uint32 :protocol
  sflow_ip4_addr :srcIpv4
  sflow_ip4_addr :dstIpv4
  uint32 :srcPort
  uint32 :dstPort
  uint32 :tcpFlags
  uint32 :ip_type
end

# noinspection RubyResolve
class IP6Data < BinData::Record
  endian :big
  uint32 :ip_packet_length
  uint32 :ip_next_header
  sflow_ip6_addr :srcIpv6
  sflow_ip6_addr :dstIpv6
  uint32 :srcPort
  uint32 :dstPort
  uint32 :tcpFlags
  uint32 :ip_priority
end

# noinspection RubyResolve
class ExtendedSwitchData < BinData::Record
  endian :big
  uint32 :srcVlan
  uint32 :srcPriority
  uint32 :dstVlan
  uint32 :dstPriority
end

# noinspection RubyResolve
class ExtendedRouterData < BinData::Record
  endian :big
  uint32 :ipVersion
  choice :ip_address_next_hop_router, :selection => :ipVersion do
    sflow_ip4_addr 1
    sflow_ip6_addr 2
  end
  uint32 :srcMask
  uint32 :dstMask
end

# noinspection RubyResolve
class ExtendedGatewayData < BinData::Record
  endian :big
  uint32 :ipVersion
  choice :ip_address_next_hop_router, :selection => :ipVersion do
    sflow_ip4_addr 1
    sflow_ip6_addr 2
  end
  uint32 :as_number_of_router
  uint32 :as_number_of_source
  uint32 :as_number_of_source_peer
  uint32 :dest_as_path_count
  array :dest_as_paths, :initial_length => :dest_as_path_count do
    uint32 :as_path_segment_type
    uint32 :as_number_count
    array :as_numbers, :type => :uint32, :initial_length => :as_number_count
  end
  uint32 :communities_count
  array :communities, :type => :uint32, :initial_length => :communities_count
  uint32 :local_pref
end

# noinspection RubyResolve
class ExtendedUserData < BinData::Record
  endian :big
  uint32 :source_charset
  sflow_string :source_user
  uint32 :destination_charset
  sflow_string :destination_user
end

# noinspection RubyResolve
class ExtendedUrlData < BinData::Record
  endian :big
  uint32 :direction
  sflow_string :url
  sflow_string :host
end

# noinspection RubyResolve
class ExtendedMplsData < BinData::Record
  endian :big
  uint32 :ipVersion
  choice :ip_address_next_hop_router, :selection => :ipVersion do
    sflow_ip4_addr 1
    sflow_ip6_addr 2
  end
  uint32 :in_label_stack_count
  array :in_label_stack, :type => :uint32, :initial_length => :in_label_stack_count
  uint32 :out_label_stack_count
  array :out_label_stack, :type => :uint32, :initial_length => :out_label_stack_count
end

# noinspection RubyResolve
class ExtendedNatData < BinData::Record
  endian :big
  uint32 :srcIpVersion
  choice :srcIpAddress, :selection => :srcIpVersion do
    sflow_ip4_addr 1
    sflow_ip6_addr 2
  end
  uint32 :dstIpVersion
  choice :dstIpAddress, :selection => :dstIpVersion do
    sflow_ip4_addr 1
    sflow_ip6_addr 2
  end
end

# noinspection RubyResolve
class ExtendedMplsTunnel < BinData::Record
  endian :big
  sflow_string :tunnel_name
  uint32 :tunnel_id
  uint32 :tunnel_cos_value
end

# noinspection RubyResolve
class ExtendedMplsVc < BinData::Record
  endian :big
  sflow_string :vc_instance_name
  uint32 :vll_vc_id
  uint32 :vc_label_cos_value
end

# noinspection RubyResolve
class ExtendedMplsFtn < BinData::Record
  endian :big
  sflow_string :mpls_ftn_descr
  uint32 :mpls_ftn_mask
end

# noinspection RubyResolve
class ExtendedMplsLdpFec < BinData::Record
  endian :big
  uint32 :mpls_fec_addr_prefix_length
end

# noinspection RubyResolve
class ExtendedVlanTunnel < BinData::Record
  endian :big
  uint32 :layers_count
  array :layers, :type => :uint32, :initial_length => :layers_count
end

# noinspection RubyResolve
class ExtendedL2TunnelEgress < BinData::Record
  endian :big
  ethernet_frame_data :header
end

# noinspection RubyResolve
class ExtendedL2TunnelIngress < BinData::Record
  endian :big
  ethernet_frame_data :header
end

# noinspection RubyResolve
class ExtendedIpv4TunnelEgress < BinData::Record
  endian :big
  ip4_data :header
end

# noinspection RubyResolve
class ExtendedIpv4TunnelIngress < BinData::Record
  endian :big
  ip4_data :header
end

# noinspection RubyResolve
class ExtendedIpv6TunnelEgress < BinData::Record
  endian :big
  ip6_data :header
end

# noinspection RubyResolve
class ExtendedIpv6TunnelIngress < BinData::Record
  endian :big
  ip6_data :header
end

# noinspection RubyResolve
class ExtendedDecapsulateEgress < BinData::Record
  endian :big
  uint32 :inner_header_offset
end

# noinspection RubyResolve
class ExtendedDecapsulateIngress < BinData::Record
  endian :big
  uint32 :inner_header_offset
end

# noinspection RubyResolve
class ExtendedVniEgress < BinData::Record
  endian :big
  uint32 :vni
end

# noinspection RubyResolve
class ExtendedVniIngress < BinData::Record
  endian :big
  uint32 :vni
end

# noinspection RubyResolve
class ExtendedSocketIpv4 < BinData::Record
  endian :big
  uint32 :protocol
  sflow_ip4_addr :local_ip
  sflow_ip4_addr :remote_ip
  uint32 :local_port
  uint32 :remote_port
end

# noinspection RubyResolve
class ExtendedSocketIpv6 < BinData::Record
  endian :big
  uint32 :protocol
  sflow_ip6_addr :local_ip
  sflow_ip6_addr :remote_ip
  uint32 :local_port
  uint32 :remote_port
end
