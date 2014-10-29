# Make Modsec::VERSION includable
$LOAD_PATH << './lib'
require 'modsec'

Gem::Specification.new do |s|
  s.name              = 'modsec'
  s.version           = Modsec::VERSION
  s.licenses          = 'MIT'
  s.summary           = 'mod_security audit log parser'
  s.description       = 'mod_security audit log parser, parses concurrent logs and inserts them into a Postgres database'
  s.authors           = ['Michael Renner']
  s.email             = ['michael.renner@amd.co.at']
  s.files             =  Dir.glob('**/*.rb')

  s.homepage          = 'https://github.com/ixolit'

  s.extra_rdoc_files  = ['LICENSE'] +  Dir.glob('docs/*')
  s.add_runtime_dependency 'pg'
end