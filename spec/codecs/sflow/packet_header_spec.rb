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
  it "should decode ipv4 tcp header" do
    payload = IO.read(File.join(File.dirname(__FILE__), "ipv4_tcp_header.dat"), :mode => "rb")
    decoded = IPHeader.new(:size_header => payload.bytesize * 8).read(payload)

    decoded["ip_version"].to_s.should eq("4")
    decoded["ip_header"]["ip_header_length"].to_s.should eq("5")
    decoded["ip_header"]["ip_dscp"].to_s.should eq("0")
    decoded["ip_header"]["ip_ecn"].to_s.should eq("0")
    decoded["ip_header"]["ip_total_length"].to_s.should eq("476")
    decoded["ip_header"]["ip_identification"].to_s.should eq("30529")
    decoded["ip_header"]["ip_flags"].to_s.should eq("2")
    decoded["ip_header"]["ip_fragment_offset"].to_s.should eq("0")
    decoded["ip_header"]["ip_ttl"].to_s.should eq("62")
    decoded["ip_header"]["ip_protocol"].to_s.should eq("6")
    decoded["ip_header"]["ip_checksum"].to_s.should eq("37559")
    decoded["ip_header"]["src_ip"].to_s.should eq("10.243.27.17")
    decoded["ip_header"]["dst_ip"].to_s.should eq("10.243.0.45")
    decoded["ip_header"]["ip_data"]["src_port"].to_s.should eq("5672")
    decoded["ip_header"]["ip_data"]["dst_port"].to_s.should eq("59451")
    decoded["ip_header"]["ip_data"]["tcp_seq_number"].to_s.should eq("2671357038")
    decoded["ip_header"]["ip_data"]["tcp_ack_number"].to_s.should eq("2651945969")
    (decoded["ip_header"]["ip_data"]["tcp_header_length"].to_i*4).to_s.should eq("32")
    decoded["ip_header"]["ip_data"]["tcp_is_nonce"].to_s.should eq("0")
    decoded["ip_header"]["ip_data"]["tcp_is_cwr"].to_s.should eq("0")
    decoded["ip_header"]["ip_data"]["tcp_is_ecn_echo"].to_s.should eq("0")
    decoded["ip_header"]["ip_data"]["tcp_is_urgent"].to_s.should eq("0")
    decoded["ip_header"]["ip_data"]["tcp_is_ack"].to_s.should eq("1")
    decoded["ip_header"]["ip_data"]["tcp_is_push"].to_s.should eq("1")
    decoded["ip_header"]["ip_data"]["tcp_is_reset"].to_s.should eq("0")
    decoded["ip_header"]["ip_data"]["tcp_is_syn"].to_s.should eq("0")
    decoded["ip_header"]["ip_data"]["tcp_is_fin"].to_s.should eq("0")
    decoded["ip_header"]["ip_data"]["tcp_window_size"].to_s.should eq("147")
    decoded["ip_header"]["ip_data"]["tcp_checksum"].to_s.should eq("13042")
    decoded["ip_header"]["ip_data"]["tcp_urgent_pointer"].to_s.should eq("0")
  end
end


describe EthernetHeader do
  it "should decode ethernet ipv4 udp header" do
    payload = IO.read(File.join(File.dirname(__FILE__), "ethernet_ipv4_udp_header.dat"), :mode => "rb")
    decoded = EthernetHeader.new(:size_header => payload.bytesize * 8).read(payload)

    decoded["eth_dst"].to_s.should eq("00:23:e9:78:16:c6")
    decoded["eth_src"].to_s.should eq("58:f3:9c:81:4b:81")
    decoded["eth_type"].to_s.should eq("2048")
    decoded["eth_data"]["ip_header"]["dst_ip"].to_s.should eq("10.243.27.9")
    decoded["eth_data"]["ip_header"]["ip_data"]["dst_port"].to_s.should eq("514")
  end
end


describe EthernetHeader do
  it "should decode ethernet vlan ipv4 tcp header" do
    payload = IO.read(File.join(File.dirname(__FILE__), "ethernet_vlan_ipv4_tcp_header.dat"), :mode => "rb")
    decoded = EthernetHeader.new(:size_header => payload.bytesize * 8).read(payload)

    decoded["eth_dst"].to_s.should eq("a0:36:9f:71:d2:e0")
    decoded["eth_src"].to_s.should eq("00:09:0f:09:37:1c")
    decoded["eth_type"].to_s.should eq("33024")
    decoded["eth_data"]["vlan_id"].to_s.should eq("2422")
    decoded["eth_data"]["vlan_type"].to_s.should eq("2048")
  end
end