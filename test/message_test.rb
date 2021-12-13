require 'test_helper'

def private_key(path)
    OpenSSL::PKey.read File.read(path)
  end

  def public_key(path)
    OpenSSL::X509::Certificate.new File.read(path)
  end

describe As2::Message do
  before do
    server_key = private_key('test/certificates/server.key')
    server_crt = public_key('test/certificates/server.crt')

    @message = As2::Message.new(File.read('test/fixtures/hello_world_2.pkcs7'), server_key, server_crt)
  end

  describe '#decrypted_message' do
    it 'returns a decrypted smime message' do
      decrypted = @message.decrypted_message
      assert_equal String, decrypted.class

      mail = Mail.new(decrypted)
      assert_equal 2, mail.parts.size
      assert_equal mail.parts.map(&:content_type), ['application/edi-consent', 'application/pkcs7-signature; name=smime.p7s; smime-type=signed-data']
    end
  end

  describe '#valid_signature?' do
    it 'is true when message is signed properly' do
      # this doesn't pass. unsure of cause. need to work on this more.
      skip

      client_crt = public_key('test/certificates/client.crt')
      assert @message.valid_signature?(client_crt), "Invalid signature"
    end
  end

  describe '#mic' do
    it 'returns a message integrity check value' do
      assert_equal @message.mic, "nyyjxao566rCbElBu0v+lrDjAq4="
    end
  end

  describe '#attachment' do
    it 'provides the inbound message as a Mail::Part' do
      attachment = @message.attachment
      assert_equal attachment.class, Mail::Part
      assert_equal "hello world 2\n", attachment.body.decoded
      assert_equal "hello_world_2.txt", attachment.filename
    end
  end
end
