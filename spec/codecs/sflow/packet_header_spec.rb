# encoding: utf-8

require "logstash/devutils/rspec/spec_helper"
require "logstash/codecs/sflow/packet_header"

describe UdpHeader do
  it "should decode udp header" do
    payload = IO.read(File.join(File.dirname(__FILE__), "udp.dat"), :mode => "rb")
    decoded = UdpHeader.new(:size_header => payload.bytesize * 8).read(payload)

    decoded["src_port"].to_s.should eq("20665")
    decoded["dst_port"].to_s.should eq("514")
    decoded["udp_length"].to_s.should eq("147")
  end
end


describe TcpHeader do
  it "should decode tcp header" do
    payload = IO.read(File.join(File.dirname(__FILE__), "tcp.dat"), :mode => "rb")
    decoded = TcpHeader.new(:size_header => payload.bytesize * 8).read(payload)

    decoded["src_port"].to_s.should eq("5672")
    decoded["dst_port"].to_s.should eq("59451")
    decoded["tcp_seq_number"].to_s.should eq("2671357038")
    decoded["tcp_ack_number"].to_s.should eq("2651945969")
    (decoded["tcp_header_length"].to_i*4).to_s.should eq("32")
    decoded["tcp_is_nonce"].to_s.should eq("0")
    decoded["tcp_is_cwr"].to_s.should eq("0")
    decoded["tcp_is_ecn_echo"].to_s.should eq("0")
    decoded["tcp_is_urgent"].to_s.should eq("0")
    decoded["tcp_is_ack"].to_s.should eq("1")
    decoded["tcp_is_push"].to_s.should eq("1")
    decoded["tcp_is_reset"].to_s.should eq("0")
    decoded["tcp_is_syn"].to_s.should eq("0")
    decoded["tcp_is_fin"].to_s.should eq("0")
    decoded["tcp_window_size"].to_s.should eq("147")
    decoded["tcp_checksum"].to_s.should eq("13042")
    decoded["tcp_urgent_pointer"].to_s.should eq("0")
  end
end


describe IPHeader do
  it "should decode ipv4 over tcp header" do
    payload = IO.read(File.join(File.dirname(__FILE__), "ipv4_over_tcp_header.dat"), :mode => "rb")
    decoded = IPHeader.new(:size_header => payload.bytesize * 8).read(payload)

    decoded["ip_version"].to_s.should eq("4")
    decoded["header"]["ip_header_length"].to_s.should eq("5")
    decoded["header"]["ip_dscp"].to_s.should eq("0")
    decoded["header"]["ip_ecn"].to_s.should eq("0")
    decoded["header"]["ip_total_length"].to_s.should eq("476")
    decoded["header"]["ip_identification"].to_s.should eq("30529")
    decoded["header"]["ip_flags"].to_s.should eq("2")
    decoded["header"]["ip_fragment_offset"].to_s.should eq("0")
    decoded["header"]["ip_ttl"].to_s.should eq("62")
    decoded["header"]["ip_protocol"].to_s.should eq("6")
    decoded["header"]["ip_checksum"].to_s.should eq("37559")
    decoded["header"]["src_ip"].to_s.should eq("10.243.27.17")
    decoded["header"]["dst_ip"].to_s.should eq("10.243.0.45")
    decoded["header"]["layer4"]["src_port"].to_s.should eq("5672")
    decoded["header"]["layer4"]["dst_port"].to_s.should eq("59451")
    decoded["header"]["layer4"]["tcp_seq_number"].to_s.should eq("2671357038")
    decoded["header"]["layer4"]["tcp_ack_number"].to_s.should eq("2651945969")
    (decoded["header"]["layer4"]["tcp_header_length"].to_i*4).to_s.should eq("32")
    decoded["header"]["layer4"]["tcp_is_nonce"].to_s.should eq("0")
    decoded["header"]["layer4"]["tcp_is_cwr"].to_s.should eq("0")
    decoded["header"]["layer4"]["tcp_is_ecn_echo"].to_s.should eq("0")
    decoded["header"]["layer4"]["tcp_is_urgent"].to_s.should eq("0")
    decoded["header"]["layer4"]["tcp_is_ack"].to_s.should eq("1")
    decoded["header"]["layer4"]["tcp_is_push"].to_s.should eq("1")
    decoded["header"]["layer4"]["tcp_is_reset"].to_s.should eq("0")
    decoded["header"]["layer4"]["tcp_is_syn"].to_s.should eq("0")
    decoded["header"]["layer4"]["tcp_is_fin"].to_s.should eq("0")
    decoded["header"]["layer4"]["tcp_window_size"].to_s.should eq("147")
    decoded["header"]["layer4"]["tcp_checksum"].to_s.should eq("13042")
    decoded["header"]["layer4"]["tcp_urgent_pointer"].to_s.should eq("0")
  end
end


describe EthernetHeader do
  it "should decode ipv4 over udp header" do
    payload = IO.read(File.join(File.dirname(__FILE__), "ethernet_ipv4_over_udp_header.dat"), :mode => "rb")
    decoded = EthernetHeader.new(:size_header => payload.bytesize * 8).read(payload)

    decoded["eth_dst"].to_s.should eq("00:23:e9:78:16:c6")
    decoded["eth_src"].to_s.should eq("58:f3:9c:81:4b:81")
    decoded["eth_type"].to_s.should eq("2048")
    decoded["layer3"]["header"]["dst_ip"].to_s.should eq("10.243.27.9")
    decoded["layer3"]["header"]["layer4"]["dst_port"].to_s.should eq("514")
  end
end