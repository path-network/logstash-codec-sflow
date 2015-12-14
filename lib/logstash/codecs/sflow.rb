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
    @removed_field = %w(records record_data record_length record_count record_entreprise record_format samples sample_data sample_entreprise sample_format sample_length sample_count sample_header layer3 layer4 layer4_data header udata) | @optional_removed_field
  end

  # def initialize

  def assign_key_value(event, bindata_kv)
    bindata_kv.each_pair do |k, v|
      unless @removed_field.include? k.to_s
        event["#{k}"] = v
      end
    end
  end

  def common_sflow(event, decoded, sample, record)
    # Ensure that some data exist for the record
    if record['record_data'].to_s.eql? ''
      @logger.warn("Unknown record entreprise #{record['record_entreprise'].to_s}, format #{record['record_format'].to_s}")
      next
    end

    assign_key_value(event, decoded)
    assign_key_value(event, sample)
    assign_key_value(event, sample['sample_data'])
    assign_key_value(event, record)
    assign_key_value(event, record['record_data'])

  end

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
          common_sflow(event, decoded, sample, record)

          unless record['record_data']['sample_header'].to_s.eql? ''
            assign_key_value(event, record['record_data']['sample_header'])

            if record['record_data']['sample_header'].has_key?('layer3')
              assign_key_value(event, record['record_data']['sample_header']['layer3']['header'])
              assign_key_value(event, record['record_data']['sample_header']['layer3']['header']['layer4'])
            end
          end

        end
        events.push(event)

        #treat counter flow
      elsif sample['sample_entreprise'] == 0 && sample['sample_format'] == 2
        sample['sample_data']['records'].each do |record|
          # Create the logstash event
          event = {
              LogStash::Event::TIMESTAMP => LogStash::Timestamp.now
          }

          common_sflow(event, decoded, sample, record)

          events.push(event)
        end
      end
    end

    events.each do |event|
      yield event
    end
  end # def decode
end # class LogStash::Filters::Sflow
