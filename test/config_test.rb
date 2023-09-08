require 'test_helper'

describe As2::Config do
  # before do
  #   server_key = private_key('test/certificates/server.key')
  #   server_crt = public_key('test/certificates/server.crt')
  # end

  describe 'Partner' do
    before do
      @partner_config = As2::Config::Partner.new
    end

    describe '#url=' do
      it 'accepts a string' do
        @partner_config.url = 'http://test.com'
        assert_equal URI('http://test.com'), @partner_config.url
      end

      it 'accepts a URI' do
        @partner_config.url = URI('http://test.com')
        assert_equal URI('http://test.com'), @partner_config.url
      end
    end

    describe '#certificate= is used for both signing and encryption' do
      it 'accepts a file path to a certificate' do
        @partner_config.certificate = 'test/certificates/client.crt'
        expected = OpenSSL::X509::Certificate.new(File.read('test/certificates/client.crt'))
        assert_equal @partner_config.signing_certificate, expected
        assert_equal @partner_config.encryption_certificate, expected
      end

      it 'accepts an OpenSSL::X509::Certificate instance' do
        cert_instance = OpenSSL::X509::Certificate.new(File.read('test/certificates/client.crt'))
        @partner_config.certificate = cert_instance
        assert_equal @partner_config.signing_certificate, cert_instance
        assert_equal @partner_config.encryption_certificate, cert_instance
      end
    end

    describe '#signing_certificate=' do
      it 'accepts a file path to a certificate' do
        @partner_config.signing_certificate = 'test/certificates/client.crt'
        expected = OpenSSL::X509::Certificate.new(File.read('test/certificates/client.crt'))
        assert_equal @partner_config.signing_certificate, expected
        assert_nil @partner_config.encryption_certificate
      end

      it 'accepts an OpenSSL::X509::Certificate instance' do
        cert_instance = OpenSSL::X509::Certificate.new(File.read('test/certificates/client.crt'))
        @partner_config.signing_certificate = cert_instance
        assert_equal @partner_config.signing_certificate, cert_instance
        assert_nil @partner_config.encryption_certificate
      end
    end

    describe '#encryption_certificate=' do
      it 'accepts a file path to a certificate' do
        @partner_config.encryption_certificate = 'test/certificates/client.crt'
        expected = OpenSSL::X509::Certificate.new(File.read('test/certificates/client.crt'))
        assert_nil @partner_config.signing_certificate
        assert_equal @partner_config.encryption_certificate, expected
      end

      it 'accepts an OpenSSL::X509::Certificate instance' do
        cert_instance = OpenSSL::X509::Certificate.new(File.read('test/certificates/client.crt'))
        @partner_config.encryption_certificate = cert_instance
        assert_nil @partner_config.signing_certificate
        assert_equal @partner_config.encryption_certificate, cert_instance
      end
    end

    describe '#outbound_format=' do
      it 'accepts a valid format value' do
        assert_nil @partner_config.outbound_format

        @partner_config.outbound_format = 'v1'

        assert_equal 'v1', @partner_config.outbound_format
      end

      it 'raises if given an invalid format value' do
        error = assert_raises(ArgumentError) do
                  @partner_config.outbound_format = 'invalid'
                end
        assert_equal "outbound_format 'invalid' must be one of [\"v0\", \"v1\"]", error.message
      end
    end

    describe '#tls_verify_mode=' do
      it 'accepts an OpenSSL::SSL::VERIFY_* constant' do
        @partner_config.tls_verify_mode = OpenSSL::SSL::VERIFY_PEER
        assert_equal OpenSSL::SSL::VERIFY_PEER, @partner_config.tls_verify_mode

        @partner_config.tls_verify_mode = OpenSSL::SSL::VERIFY_NONE
        assert_equal OpenSSL::SSL::VERIFY_NONE, @partner_config.tls_verify_mode
      end

      it 'accepts nil' do
        @partner_config.tls_verify_mode = nil
        assert_nil @partner_config.tls_verify_mode
      end

      it 'raises if given an invalid value' do
        assert_raises(ArgumentError) do
          @partner_config.tls_verify_mode = 'invalid'
        end
      end
    end
  end

  describe 'ServerInfo' do
    before do
      @server_info = As2::Config::ServerInfo.new
    end

    describe '#url=' do
      it 'accepts a string' do
        @server_info.url = 'http://test.com'
        assert_equal URI('http://test.com'), @server_info.url
      end

      it 'accepts a URI' do
        @server_info.url = URI('http://test.com')
        assert_equal URI('http://test.com'), @server_info.url
      end
    end

    describe '#certificate=' do
      it 'accepts a file path to a certificate' do
        @server_info.certificate = 'test/certificates/server.crt'
        assert_equal @server_info.certificate, OpenSSL::X509::Certificate.new(File.read('test/certificates/server.crt'))
      end

      it 'accepts an OpenSSL::X509::Certificate instance' do
        cert_instance = OpenSSL::X509::Certificate.new(File.read('test/certificates/server.crt'))
        @server_info.certificate = cert_instance
        assert_equal @server_info.certificate, cert_instance
      end
    end

    describe '#pkey=' do
      it 'accepts a file path to a private key' do
        @server_info.pkey = 'test/certificates/server.key'
        assert_equal @server_info.pkey.to_pem, OpenSSL::PKey.read(File.read('test/certificates/server.key')).to_pem
      end

      it 'accepts an OpenSSL::PKey instance' do
        key_instance = OpenSSL::PKey.read(File.read('test/certificates/server.key'))
        @server_info.pkey = key_instance
        assert_equal @server_info.pkey, key_instance
      end
    end
  end
end
