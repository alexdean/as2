require 'as2'
require 'rack'

As2.configure do |conf|
  conf.name = 'MyServer'
  conf.url = 'http://localhost:3000/as2'
  conf.certificate = 'test/certificates/server.crt'
  conf.pkey = 'test/certificates/server.key'
  conf.domain = 'mydomain.com'
  conf.add_partner do |partner|
    partner.name = 'MyClient'
    partner.url = 'http://localhost:8080/as2/HttpReceiver'
    partner.certificate = 'test/certificates/client.crt'
  end
end

handler = As2::Server.new do |filename, body|
  puts "SUCCESSFUL DOWNLOAD"
  puts "FILENAME: #{filename}"
  puts
  puts body
  raise "Test error message" unless filename.end_with?('edi')
end

builder = Rack::Builder.new do
  use Rack::CommonLogger
  map '/as2' do
    run handler
  end
end

puts "As2 version: #{As2::VERSION}"
Rack::Handler::Thin.run builder, Port: 3000
