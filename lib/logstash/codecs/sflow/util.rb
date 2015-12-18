# encoding: utf-8

require 'bindata'
require 'ipaddr'

# noinspection RubyResolve
class SflowMacAddress < BinData::Primitive
  array :bytes, :type => :uint8, :initial_length => 6

  def set(val)
    ints = val.split(/:/).collect { |int| int.to_i(16) }
    self.bytes = ints
  end

  def get
    self.bytes.collect { |byte| byte.value.to_s(16).rjust(2, '0') }.join(':')
  end
end

# noinspection RubyResolve,RubyResolve,RubyResolve
class SflowIP4Addr < BinData::Primitive
  endian :big
  uint32 :storage

  def set(val)
    ip = IPAddr.new(val)
    unless ip.ipv4?
      raise ArgumentError, "invalid IPv4 address '#{val}'"
    end
    self.storage = ip.to_i
  end

  def get
    IPAddr.new_ntoh([self.storage].pack('N')).to_s
  end
end

# noinspection RubyResolve
class SflowIP6Addr < BinData::Primitive
  endian :big
  uint128 :storage

  def set(val)
    ip = IPAddr.new(val)
    unless ip.ipv6?
      raise ArgumentError, "invalid IPv6 address `#{val}'"
    end
    self.storage = ip.to_i
  end

  def get
    IPAddr.new_ntoh((0..7).map { |i|
      (self.storage >> (112 - 16 * i)) & 0xffff
    }.pack('n8')).to_s
  end
end
