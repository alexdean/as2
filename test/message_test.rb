require 'test_helper'

class MessageTest < Minitest::Test
  def private_key(path)
    OpenSSL::PKey.read File.read(path)
  end

  def public_key(path)
    OpenSSL::X509::Certificate.new File.read(path)
  end

  def test_base64_encoded_messages
    server_key = private_key('test/certificates/server.key')
    server_crt = public_key('test/certificates/server.crt')
    client_crt = public_key('test/certificates/client.crt')
    message = As2::Message.new(File.read('test/fixtures/hello_message'), server_key, server_crt)
    assert message.valid_signature?(client_crt), "Invalid signature"
    assert_equal "Hello World\n", message.attachment.body.decoded
    assert_equal "hello_world.txt", message.attachment.filename
  end
end
