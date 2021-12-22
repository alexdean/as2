require 'test_helper'
require 'base64'

describe As2::Message do
  before do
    @server_key = private_key('test/certificates/server.key')
    @server_crt = public_key('test/certificates/server.crt')
    @client_crt = public_key('test/certificates/client.crt')

    @encrypted_message = File.read('test/fixtures/hello_world_2.pkcs7')
    @correct_cleartext = "hello world 2\n"

    @message = As2::Message.new(@encrypted_message, @server_key, @server_crt)
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
      assert @message.valid_signature?(@client_crt), "Invalid signature"
    end

    it 'is false when message was not signed by given cert' do
      assert !@message.valid_signature?(@server_crt), "Signature should be invalid."
      assert_equal "signer certificate not found", @message.verification_error
    end

    it 'is false when signature does not match content' do
      hacked_payload = 'h4xx0rd'
      encrypted = OpenSSL::PKCS7.new(File.read('test/fixtures/hello_world_2.pkcs7'))
      decrypted = encrypted.decrypt @server_key

      # replace the correct (base64-encoded) payload with our own and re-encrypt
      hacked_cleartext = decrypted.gsub(Base64.strict_encode64(@correct_cleartext), Base64.strict_encode64(hacked_payload))
      cipher = OpenSSL::Cipher::AES.new("128-CBC")
      hacked_encrypted = OpenSSL::PKCS7.encrypt([@server_crt], hacked_cleartext, cipher)

      # build messge with modified payload
      message = As2::Message.new(hacked_encrypted.to_der, @server_key, @server_crt)

      assert !message.valid_signature?(@client_crt)
      assert_equal "digest failure", message.verification_error
      assert_equal hacked_payload, message.attachment.body.to_s
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
      assert_equal @correct_cleartext, attachment.body.decoded
      assert_equal "hello_world_2.txt", attachment.filename
    end
  end
end
