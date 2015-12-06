# encoding: utf-8

# The "sflow" codec is for decoding sflow v5 flows.
class LogStash::Codecs::Sflow < LogStash::Codecs::Base
  config_name "sflow"

  # Specify which sflow must not be send in the event
  config :removed_field, :validate => :array, :default => ['record_length', 'record_count', 'record_entreprise',
                                                           'record_format', 'sample_entreprise', 'sample_format',
                                                           'sample_length', 'sample_count', 'sflow_version',
                                                           'ip_version']


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
        # Ensure that some data exist for the record
        if record['record_data'].to_s.eql? ''
          next
        end

        # Create the logstash event
        event = {
            LogStash::Event::TIMESTAMP => LogStash::Timestamp.now
        }

        decoded.each_pair do |k, v|
          unless k.to_s.eql? 'samples' or @removed_field.include? k.to_s
            event["#{k}"] = v
          end
        end

        sample.each_pair do |k, v|
          unless k.to_s.eql? 'sample_data' or @removed_field.include? k.to_s
            event["#{k}"] = v
          end
        end

        sample['sample_data'].each_pair do |k, v|
          unless k.to_s.eql? 'records' or @removed_field.include? k.to_s
            event["#{k}"] = v
          end
        end

        record.each_pair do |k, v|
          unless k.to_s.eql? 'record_data' or @removed_field.include? k.to_s
            event["#{k}"] = v
          end
        end

        record['record_data'].each_pair do |k, v|
          event["#{k}"] = v
        end

        events.push(event)
      end
    end

    events.each do |event|
      yield event
    end
  end
end # class LogStash::Filters::Sflow
