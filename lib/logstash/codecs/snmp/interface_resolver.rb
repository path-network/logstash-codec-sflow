require 'snmp'
require 'lru_redux'

class SNMPInterfaceResolver
  def initialize(community, cache_size, cache_ttl, logger)
    @community = community
    @cacheSnmpInterface = LruRedux::TTL::Cache.new(cache_size, cache_ttl)
    @logger = logger
  end

  def get_interface(host, ifIndex)
    unless @cacheSnmpInterface.key?("#{host}-#{ifIndex}")
      begin
        SNMP::Manager.open(:host => host, :community => @community, :version => :SNMPv2c) do |manager|
          @cacheSnmpInterface["#{host}-#{ifIndex}"] = manager.get_value("ifDescr.#{ifIndex}").to_s
        end
      rescue SNMP::RequestTimeout => e
        # This is not the best but it avoids loosing lots of events when facing
        # request timeout exception with input thread restarting.
        # Then we can easily detect this on the log or on elasticsearch
        # searching for SnmpRequestTimeout descr fields
        @logger.error("Timeout requesting description on #{host} of index #{ifIndex}: #{e.message}")
        return "SnmpRequestTimeout"
      end
    end
    return @cacheSnmpInterface["#{host}-#{ifIndex}"]
  end
end