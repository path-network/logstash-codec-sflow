Gem::Specification.new do |s|

  s.name = 'logstash-codec-sflow'
  s.version = '2.1.0'
  s.licenses = ['Apache-2.0']
  s.summary = 'The sflow codec is for decoding SFlow v5 flows.'
  s.description = 'This gem is a logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/plugin install gemname. This gem is not a stand-alone program'
  s.authors = ['Konrad Zemek', 'Nicolas Fraison']
  s.email = 'konrad@path.net'
  s.homepage = 'https://path.net'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*', 'spec/**/*', 'vendor/**/*', '*.gemspec', '*.md', 'CONTRIBUTORS', 'Gemfile', 'LICENSE', 'NOTICE.TXT']

  # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = {'logstash_plugin' => 'true', 'logstash_group' => 'codec'}

  # Gem dependencies
  s.add_runtime_dependency 'logstash-core-plugin-api', '>= 1.60', '<= 2.99'
  s.add_runtime_dependency 'logstash-core', '>= 5.4.0', '<= 7.9.9'
  s.add_runtime_dependency 'bindata', ['~> 2.4']
  s.add_runtime_dependency 'lru_redux', ['~> 1.1']
  s.add_runtime_dependency 'snmp', ['~> 1.2']
  s.add_development_dependency 'logstash-devutils', ['~> 1.3']
end
