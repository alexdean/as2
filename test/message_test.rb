require 'test_helper'

class MessageTest < Minitest::Test
  def test_that_message_can_be_decoded
    server_key = OpenSSL::PKey.read File.read('test/certificates/server.key')
    server_crt = OpenSSL::X509::Certificate.new File.read('test/certificates/server.crt')
    client_crt = OpenSSL::X509::Certificate.new File.read('test/certificates/client.crt')
    message = As2::Message.new(File.read('test/fixtures/hello_message'), server_key, server_crt)
    assert message.valid_signature?(client_crt), "Invalid signature"
    assert_equal "Hello World\n", message.attachment.body.decoded
    assert_equal "hello_world.txt", message.attachment.filename
  end
end
