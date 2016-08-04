# encoding: utf-8

require 'bindata'
require 'logstash/codecs/sflow/util'
require 'logstash/codecs/sflow/sample'


class SFlowHeader < BinData::Record
  endian :big
  uint32 :sflow_version
end

# noinspection RubyResolve
class SFlow < BinData::Record
  endian :big
  uint32 :sflow_version
  uint32 :ip_version
  choice :agent_ip, :selection => :ip_version do
    sflow_ip4_addr 1
    sflow_ip6_addr 2
  end
  uint32 :sub_agent_id
  uint32 :sequence_number
  uint32 :uptime_in_ms
  uint32 :sample_count
  array :samples, :initial_length => :sample_count do
    bit20 :sample_entreprise
    bit12 :sample_format
    uint32 :sample_length
    choice :sample_data, :selection => lambda { "#{sample_entreprise}-#{sample_format}" } do
      flow_sample '0-1'
      counter_sample '0-2'
      expanded_flow_sample '0-3'
      expanded_counter_sample '0-4'
      skip :default, :length => :sample_length
    end
  end
end