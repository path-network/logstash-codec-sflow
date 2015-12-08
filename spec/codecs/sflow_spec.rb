# encoding: utf-8

require "logstash/devutils/rspec/spec_helper"
require "logstash/codecs/sflow"

describe LogStash::Codecs::Sflow do
  before :each do
    @subject = LogStash::Codecs::Sflow.new
    payload = IO.read(File.join(File.dirname(__FILE__), "sflow_counters_sample.dat"), :mode => "rb")
    @subject.decode(payload)
    payload = IO.read(File.join(File.dirname(__FILE__), "sflow_flow_sample.dat"), :mode => "rb")
    @subject.decode(payload)
  end

  describe "#new" do
    it "LogStash::Codecs::Sflow" do
      @subject.should be_an_instance_of LogStash::Codecs::Sflow
    end
  end
end
