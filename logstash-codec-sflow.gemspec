Gem::Specification.new do |s|

  s.name = 'logstash-codec-sflow'
  s.version = '1.2.0'
  s.licenses = ['Apache License (2.0)']
  s.summary = 'The sflow codec is for decoding SFlow v5 flows.'
  s.description = 'This gem is a logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/plugin install gemname. This gem is not a stand-alone program'
  s.authors = ['Nicolas Fraison']
  s.email = ''
  s.homepage = ''
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*', 'spec/**/*', 'vendor/**/*', '*.gemspec', '*.md', 'CONTRIBUTORS', 'Gemfile', 'LICENSE', 'NOTICE.TXT']

  # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = {'logstash_plugin' => 'true', 'logstash_group' => 'codec'}

  # Gem dependencies
  s.add_runtime_dependency 'logstash-core', '>= 1.4.0', '< 3.0.0'
  s.add_runtime_dependency 'bindata', ['>= 2.3.0']
  s.add_runtime_dependency 'lru_redux', ['>= 1.1.0']
  s.add_runtime_dependency 'snmp', ['>= 1.2.0']
  s.add_development_dependency 'logstash-devutils'
end

