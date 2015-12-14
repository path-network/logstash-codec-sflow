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
class ProcessorInformation < BinData::Record
  endian :big
  uint32 :five_sec_cpu_percent
  uint32 :one_min_cpu_percent
  uint32 :five_min_cpu_percent
  uint64 :total_memory
  uint64 :free_memory
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
