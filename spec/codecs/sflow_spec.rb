# encoding: utf-8

require "logstash/devutils/rspec/spec_helper"
require "logstash/codecs/sflow"
require "logstash/codecs/sflow/datagram"

describe SFlow do
  it "should decode sflow counters" do
    payload = IO.read(File.join(File.dirname(__FILE__), "sflow_counters_sample.dat"), :mode => "rb")
    decoded = SFlow.read(payload)
  end

  it "should decode sflow 1 counters" do
    payload = IO.read(File.join(File.dirname(__FILE__), "sflow_1_counters_sample.dat"), :mode => "rb")
    decoded = SFlow.read(payload)
  end


  it "should decode sflow sample" do
    payload = IO.read(File.join(File.dirname(__FILE__), "sflow_flow_sample.dat"), :mode => "rb")
    decoded = SFlow.read(payload)
  end
end
