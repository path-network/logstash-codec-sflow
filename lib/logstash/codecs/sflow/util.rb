require 'bindata'
require 'ipaddr'

class IP4Addr < BinData::Primitive
  endian :big
  uint32 :storage

  def set(val)
    ip = IPAddr.new(val)
    if !ip.ipv4?
      raise ArgumentError, "invalid IPv4 address '#{val}'"
    end
    self.storage = ip.to_i
  end

  def get
    IPAddr.new_ntoh([self.storage].pack('N')).to_s
  end
end

class IP6Addr < BinData::Primitive
  endian :big
  uint128 :storage

  def set(val)
    ip = IPAddr.new(val)
    if !ip.ipv6?
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
