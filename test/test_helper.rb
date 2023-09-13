$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'as2'
require 'pry'

require 'minitest/autorun'
require 'minitest/focus'
require 'webmock/minitest'

WebMock.disable_net_connect!

def private_key(path)
  OpenSSL::PKey.read File.read(path)
end

def public_key(path)
  OpenSSL::X509::Certificate.new File.read(path)
end

def build_partner(name, credentials:, outbound_format: 'v0')
  out = As2::Config::Partner.new
  out.name = name
  out.url = 'https://test.com/as2'
  out.certificate = public_key("test/certificates/#{credentials}.crt")
  out.mdn_format = 'v0'
  out.outbound_format = outbound_format
  out
end

def build_multi_cert_partner(name, credentials:, outbound_format: 'v0')
  out = As2::Config::Partner.new
  out.name = name
  out.url = 'https://test.com/as2'
  out.signing_certificate = public_key("test/certificates/#{credentials}_signing.crt")
  out.encryption_certificate = public_key("test/certificates/#{credentials}_encryption.crt")
  out.mdn_format = 'v0'
  out.outbound_format = outbound_format
  out
end

def build_server_info(name, credentials:)
  out = As2::Config::ServerInfo.new
  out.name = name
  out.domain = 'test.com'
  out.url = 'https://test.com/as2'
  out.certificate = public_key("test/certificates/#{credentials}.crt")
  out.pkey = private_key("test/certificates/#{credentials}.key")
  out
end
