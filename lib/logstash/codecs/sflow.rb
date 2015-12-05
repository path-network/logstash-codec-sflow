# encoding: utf-8

# The "sflow" codec is for decoding sflow v5 flows.
class LogStash::Codecs::Sflow < LogStash::Codecs::Base
  config_name "sflow"

  def initialize(params = {})
    super(params)
    @threadsafe = false
  end

  def register
    require "logstash/codecs/sflow/datagram"
  end

  def decode(payload)
    decoded = SFlow.read(payload)

    events = []

    decoded['samples'].each do |sample|
      sample['sample_data']['records'].each do |record|
        event = {
            LogStash::Event::TIMESTAMP => LogStash::Timestamp.now
        }

        record.each_pair do |k, v|
          unless k.to_s.eql? 'record_data' or k.to_s.eql? 'record_length' or k.to_s.eql? 'record_count' or k.to_s.eql? 'record_entreprise' or k.to_s.eql? 'record_format'
            event["#{k}"] = v
          end
        end

        if record['record_data'].to_s.eql? ''
          next
        else
          record['record_data'].each_pair do |k, v|
            event["#{k}"] = v
          end
        end

        sample.each_pair do |k, v|
          unless k.to_s.eql? 'sample_data' or k.to_s.eql? 'sample_entreprise' or k.to_s.eql? 'sample_format' or k.to_s.eql? 'sample_length' or k.to_s.eql? 'sample_count'
            event["#{k}"] = v
          end
        end
        sample['sample_data'].each_pair do |k, v|
          unless k.to_s.eql? 'records'
            event["#{k}"] = v
          end
        end

        decoded.each_pair do |k, v|
          unless k.to_s.eql? 'samples' or k.to_s.eql? 'sample_count'
            event["#{k}"] = v
          end
        end
        events.push(event)
      end
    end

    events.each do |event|
      yield event
    end
  end
end # class LogStash::Filters::Sflow
