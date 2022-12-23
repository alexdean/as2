# test server receives files & saves them to the local filesystem
#
# `bundle exec ruby examples/server.rb`

require 'as2'
require 'rackup'
require 'rack/handler/puma'
require 'pathname'
require 'fileutils'

this_dir = Pathname.new(File.expand_path('..', __FILE__))
root_dir = this_dir.join('..')

As2.configure do |conf|
  conf.name = 'RUBYAS2'
  conf.url = 'http://localhost:3000/as2'
  conf.certificate = 'test/certificates/server.crt'
  conf.pkey = 'test/certificates/server.key'
  conf.domain = 'localhost'

  conf.add_partner do |partner|
    partner.name = 'MENDELSON'
    partner.url = 'http://localhost:8080/as2/HttpReceiver'
    partner.certificate = 'test/certificates/client.crt'
  end

  conf.add_partner do |partner|
    partner.name = 'OPENAS2'
    partner.url = 'http://localhost:4088'
    partner.certificate = 'test/certificates/client.crt'
  end
end

def log(message, transmission_id: nil)
  puts "#{Time.now.strftime('%F %T')} [#{transmission_id}] #{message}"
end

# TODO: there are a lot of potential failure cases we're not handling
# (failed decryption, unsigned message, etc), because this script is intended for
# local debugging.
handler = Proc.new do |env|
  transmission_id = "#{Time.now.strftime('%Y%m%d_%H%M%S_%L')}_#{SecureRandom.hex(6)}"
  log("start.", transmission_id: transmission_id)

  server_info = As2::Config.server_info

  partner_name = env['HTTP_AS2_FROM']
  partner = As2::Config.partners[partner_name]

  log("partner:#{partner_name} known_partner?:#{!!partner}", transmission_id: transmission_id)
  partner_dir = root_dir.join('tmp/inbox/', partner_name)
  if !File.exist?(partner_dir)
    FileUtils.mkdir_p(partner_dir)
  end

  raw_request_body = env['rack.input'].read
  message = As2::Message.new(raw_request_body, server_info.pkey, server_info.certificate)

  # do this before writing to disk, in case we have to fix content.
  # @see https://github.com/alexdean/as2/pull/11
  valid_signature = message.valid_signature?(partner.certificate)

  original_filename = message.attachment.filename
  extname = File.extname(original_filename)
  basename = partner_dir.join(File.basename(message.attachment.filename, extname)).to_s
  encrypted_filename = "#{basename}.pkcs7" # exactly what we got on the wire
  decrypted_filename = "#{basename}.mime"  # full message, all parts
  body_filename = "#{basename}#{extname}"  # just the body part, w/o signature

  File.open(encrypted_filename, 'wb') { |f| f.write(raw_request_body) }
  File.open(decrypted_filename, 'wb') { |f| f.write(message.decrypted_message) }
  File.open(body_filename, 'wb') { |f| f.write(message.attachment.raw_source) }

  # filenames are absolute paths to each file.
  # when we print output, nicer to read a path relative to the project's root.
  prefix_length = root_dir.to_s.length + 1

  report = <<~EOF
  filename:#{original_filename}
       #{encrypted_filename[prefix_length..]}
       #{decrypted_filename[prefix_length..]}
       #{body_filename[prefix_length..]}
       valid_signature?:#{valid_signature}, error:#{message.verification_error}
       MIC: '#{message.mic}' (#{message.mic_algorithm})
  EOF
  log(report, transmission_id: transmission_id)

  server = As2::Server.new(server_info: server_info, partner: partner)
  server.send_mdn(env, message.mic, message.mic_algorithm, message.verification_error)
end

builder = Rack::Builder.new do
  # TODO: print a full stacktrace when an error occurs
  map '/as2' do
    run handler
  end
end

puts "ruby-as2 version: #{As2::VERSION}"
Rack::Handler::Puma.run builder, Port: 3002, Host: '0.0.0.0'
