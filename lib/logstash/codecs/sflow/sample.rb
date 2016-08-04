# encoding: utf-8

require 'bindata'
require 'logstash/codecs/sflow/flow_record'
require 'logstash/codecs/sflow/counter_record'

# noinspection RubyResolve
class FlowSample < BinData::Record
  endian :big
  uint32 :flow_sequence_number
  uint8 :source_id_type
  uint24 :source_id_index
  uint32 :sampling_rate
  uint32 :sample_pool
  uint32 :drops
  uint32 :input_interface
  uint32 :output_interface
  uint32 :record_count
  array :records, :initial_length => :record_count do
    bit20 :record_entreprise
    bit12 :record_format
    uint32 :record_length
    choice :record_data, :selection => lambda { "#{record_entreprise}-#{record_format}" } do
      raw_packet_header '0-1', :record_length => :record_length
      ethernet_frame_data '0-2'
      ip4_data '0-3'
      ip6_data '0-4'
      extended_switch_data '0-1001'
      extended_router_data '0-1002'
      skip :default, :length => :record_length
    end
  end
end

# noinspection RubyResolve
class CounterSample < BinData::Record
  endian :big
  uint32 :sample_seq_number
  uint8 :source_id_type
  uint24 :source_id_index
  uint32 :record_count
  array :records, :initial_length => :record_count do
    bit20 :record_entreprise
    bit12 :record_format
    uint32 :record_length
    choice :record_data, :selection => lambda { "#{record_entreprise}-#{record_format}" } do
      generic_interface '0-1'
      ethernet_interfaces '0-2'
      token_ring '0-3'
      hundred_base_vg '0-4'
      vlan '0-5'
      processor_information '0-1001'
      http_counters '0-2201'
      skip :default, :length => :record_length
    end
    #processor_information :record_data
  end
end

# noinspection RubyResolve
class ExpandedFlowSample < BinData::Record
  endian :big
  uint32 :flow_sequence_number
  uint32 :source_id_type
  uint32 :source_id_index
  uint32 :sampling_rate
  uint32 :sample_pool
  uint32 :drops
  uint32 :input_interface_format
  uint32 :input_interface_value
  uint32 :output_interface_format
  uint32 :output_interface_value
  uint32 :record_count
  array :records, :initial_length => :record_count do
    bit20 :record_entreprise
    bit12 :record_format
    uint32 :record_length
    choice :record_data, :selection => lambda { "#{record_entreprise}-#{record_format}" } do
      raw_packet_header '0-1', :record_length => :record_length
          ethernet_frame_data '0-2'
      ip4_data '0-3'
      ip6_data '0-4'
      extended_switch_data '0-1001'
      extended_router_data '0-1002'
      skip :default, :length => :record_length
    end
  end
end

# noinspection RubyResolve
class ExpandedCounterSample < BinData::Record
  endian :big
  uint32 :sample_seq_number
  uint32 :source_id_type
  uint32 :source_id_index
  uint32 :record_count
  array :records, :initial_length => :record_count do
    bit20 :record_entreprise
    bit12 :record_format
    uint32 :record_length
    choice :record_data, :selection => lambda { "#{record_entreprise}-#{record_format}" } do
      generic_interface '0-1'
      ethernet_interfaces '0-2'
      token_ring '0-3'
      hundred_base_vg '0-4'
      vlan '0-5'
      processor_information '0-1001'
      http_counters '0-2201'
      skip :default, :length => :record_length
    end
    #processor_information :record_data
  end
end
