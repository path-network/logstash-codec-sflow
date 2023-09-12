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
  uint32 :ipVersion
  choice :deviceIp, :selection => :ipVersion do
    sflow_ip4_addr 1
    sflow_ip6_addr 2
  end
  uint32 :subAgentId
  uint32 :sequence_number
  uint32 :uptimeInMs
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