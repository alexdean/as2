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

# https://github.com/alexdean/as2/issues/26#issuecomment-1509278908
def build_concise_asn1(item)
  if item.respond_to?(:value)
    item_value = item.value
  else
    item_value = item
  end

  if item.respond_to?(:each)
    out_value = []
    # OpenSSL::ASN1::Sequence responds to .each
    item.each { |i| out_value << build_concise_asn1(i) }
  elsif item_value.respond_to?(:each)
    out_value = []
    # OpenSSL::ASN1::ASN1Data does not respond to .each
    # but it's .value may be an array so we should recurse
    item_value.each { |i| out_value << build_concise_asn1(i) }
  else
    # when we hit a leaf node
    if item.is_a?(OpenSSL::ASN1::Integer)
      out_value = item_value.to_i
    elsif item.is_a?(OpenSSL::ASN1::ObjectId)
      out_value = {oid:item.oid, value:item_value}
    else
      out_value = item_value
    end
  end

  out_value
end
