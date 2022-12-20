# test server receives files & saves them to the local filesystem
#
# `bundle exec ruby examples/server.rb`

require 'as2'
require 'rack'
require 'pathname'

this_dir = Pathname.new(File.expand_path('..', __FILE__))
root_dir = this_dir.join('..')

As2.configure do |conf|
  conf.name = 'SERVER'
  conf.url = 'http://localhost:3000/as2'
  conf.certificate = 'test/certificates/server.crt'
  conf.pkey = 'test/certificates/server.key'
  conf.domain = 'localhost'
  conf.add_partner do |partner|
    partner.name = 'CLIENT'
    partner.url = 'http://localhost:8080/as2/HttpReceiver'
    partner.certificate = 'test/certificates/client.crt'
  end
end

handler = Proc.new do |env|
  transmission_id = "#{Time.now.strftime('%Y%m%d_%H%M%S_%L')}_#{SecureRandom.hex(6)}"

  server_info = As2::Config.server_info

  partner_name = env['HTTP_AS2_FROM']
  partner = As2::Config.partners[partner_name]

  raw_request_body = env['rack.input'].read
  # env['rack.input'].rewind
  # request = Rack::Request.new(env)

  message = As2::Message.new(raw_request_body, server_info.pkey, server_info.certificate)

  partner_dir = root_dir.join('tmp/inbox/', partner_name, "#{transmission_id}_#{message.attachment.filename}")
  if !File.exist?(partner_dir)
    Dir.mkdir(partner_dir)
  end

  filename = message.attachment.filename
  if filename.empty?
    filename = "#{transmission_id}_content"
  end
  basename = partner_dir.join(filename).to_s

  encrypted_filename = "#{basename}.pkcs7"
  File.open(encrypted_filename, 'wb') { |f| f.write(raw_request_body) }
  decrypted_filename = "#{basename}.mime"
  File.open(decrypted_filename, 'wb') { |f| f.write(message.decrypted_message) }
  File.open(basename, 'wb') { |f| f.write(message.attachment.body) }

  prefix_length = root_dir.to_s.length + 1
  puts "#{Time.now.strftime('%F %T')}: received transmission #{transmission_id}"
  puts "     #{encrypted_filename[prefix_length..]}"
  puts "     #{decrypted_filename[prefix_length..]}"
  puts "     #{basename[prefix_length..]}"
  puts "     valid_signature?: #{message.valid_signature?(partner.certificate)}"

  server = As2::Server.new(server_info: server_info, partner: partner)
  server.send_mdn(env, message.mic, message.mic_algorithm)
end

builder = Rack::Builder.new do
  use Rack::CommonLogger
  map '/as2' do
    run handler
  end
end

puts "ruby-as2 version: #{As2::VERSION}"
Rack::Handler::Thin.run builder, Port: 3002
