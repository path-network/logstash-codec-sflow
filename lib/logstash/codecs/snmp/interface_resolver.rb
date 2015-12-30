require 'snmp'
require 'lru_redux'

class SNMPInterfaceResolver
  def initialize(community, cache_size, cache_ttl)
    @community = community
    @cacheSnmpInterface = LruRedux::TTL::Cache.new(cache_size, cache_ttl)
  end

  def get_interface(host, ifIndex)
    unless @cacheSnmpInterface.key?("#{host}-#{ifIndex}")
      SNMP::Manager.open(:host => host, :community => @community, :version => :SNMPv2c) do |manager|
        response = manager.get("ifDescr.#{ifIndex}")
        response.each_varbind do |vb|
          @cacheSnmpInterface["#{host}-#{ifIndex}"] = vb.value.to_s
        end
      end
    end
    return @cacheSnmpInterface["#{host}-#{ifIndex}"]
  end
end