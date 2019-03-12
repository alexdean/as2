# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'as2/version'

Gem::Specification.new do |spec|
  spec.name          = "as2"
  spec.version       = As2::VERSION
  spec.authors       = ["OfficeLuv"]
  spec.email         = ["development@officeluv.com"]

  spec.summary       = %q{Simple AS2 server and client implementation}
  spec.description   = %q{Simple AS2 server and client implementation. Follows the AS2 implementation from http://as2.mendelson-e-c.com}
  spec.homepage      = "https://github.com/officeluv/as2"
  spec.license       = "MIT"

  # Prevent pushing this gem to RubyGems.org by setting 'allowed_push_host', or
  # delete this section to allow pushing this gem to any host.
  if spec.respond_to?(:metadata)
    spec.metadata['allowed_push_host'] = 'https://rubygems.org/'
  else
    raise "RubyGems 2.0 or newer is required to protect against public gem pushes."
  end

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "mail"
  spec.add_dependency "rack"

  spec.add_development_dependency "bundler", "~> 1.10"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "thin"
  spec.add_development_dependency "minitest"
end
