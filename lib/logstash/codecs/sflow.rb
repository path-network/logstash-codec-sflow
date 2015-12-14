# encoding: utf-8
require 'logstash/codecs/base'
require 'logstash/namespace'

# The "sflow" codec is for decoding sflow v5 flows.
class LogStash::Codecs::Sflow < LogStash::Codecs::Base
  config_name 'sflow'

  # Specify which sflow must not be send in the event
  config :optional_removed_field, :validate => :array, :default => %w(sflow_version ip_version header_size ip_header_length ip_dscp ip_ecn ip_total_length ip_identification ip_flags ip_fragment_offset ip_ttl ip_checksum ip_options tcp_seq_number tcp_ack_number tcp_header_length tcp_reserved tcp_is_nonce tcp_is_cwr tcp_is_ecn_echo tcp_is_urgent tcp_is_ack tcp_is_push tcp_is_reset tcp_is_syn tcp_is_fin tcp_window_size tcp_checksum tcp_urgent_pointer tcp_options)


  def initialize(params = {})
    super(params)
    @threadsafe = false
    # noinspection RubyResolve
    @removed_field = %w(record_length record_count record_entreprise record_format sample_entreprise sample_format sample_length sample_count sample_header layer3 layer4 layer4_data header udata) | @optional_removed_field
  end

  # def initialize

  public
  def register
    require 'logstash/codecs/sflow/datagram'
  end

  # def register

  public
  def decode(payload)

    decoded = SFlow.read(payload)

    events = []

    decoded['samples'].each do |sample|
      #Treat case with no flow decoded (Unknown flow)
      if sample['sample_data'].to_s.eql? ''
        @logger.warn("Unknown sample entreprise #{sample['sample_entreprise'].to_s} - format #{sample['sample_format'].to_s}")
        next
      end

      #treat sample flow
      if sample['sample_entreprise'] == 0 && sample['sample_format'] == 1
        # Create the logstash event
        event = {
            LogStash::Event::TIMESTAMP => LogStash::Timestamp.now
        }
        sample['sample_data']['records'].each do |record|
          # Ensure that some data exist for the record
          if record['record_data'].to_s.eql? ''
            @logger.warn("Unknown record entreprise #{record['record_entreprise'].to_s}, format #{record['record_format'].to_s}")
            next
          end

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
            unless k.to_s.eql? 'record_data' or @removed_field.include? k.to_s
              event["#{k}"] = v
            end
          end

          unless record['record_data']['sample_header'].to_s.eql? ''
            record['record_data']['sample_header'].each_pair do |k, v|
              unless k.to_s.eql? 'record_data' or @removed_field.include? k.to_s
                event["#{k}"] = v
              end
            end

            if record['record_data']['sample_header'].has_key?('layer3')
              record['record_data']['sample_header']['layer3']['header'].each_pair do |k, v|
                unless k.to_s.eql? 'record_data' or @removed_field.include? k.to_s
                  event["#{k}"] = v
                end
              end

              record['record_data']['sample_header']['layer3']['header']['layer4'].each_pair do |k, v|
                unless k.to_s.eql? 'record_data' or @removed_field.include? k.to_s
                  event["#{k}"] = v
                end
              end
            end
          end

        end
        events.push(event)

        #treat counter flow
      elsif sample['sample_entreprise'] == 0 && sample['sample_format'] == 2
        sample['sample_data']['records'].each do |record|
          # Ensure that some data exist for the record
          if record['record_data'].to_s.eql? ''
            @logger.warn("Unknown record entreprise #{record['record_entreprise'].to_s}, format #{record['record_format'].to_s}")
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
    end

    events.each do |event|
      yield event
    end
  end # def decode
end # class LogStash::Filters::Sflow
