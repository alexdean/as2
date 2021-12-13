$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'as2'

require 'minitest/autorun'

def private_key(path)
  OpenSSL::PKey.read File.read(path)
end

def public_key(path)
  OpenSSL::X509::Certificate.new File.read(path)
end
