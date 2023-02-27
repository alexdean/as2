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

  describe '.choose_attachment' do
    it 'returns nil if no parts are given' do
      assert_nil As2::Message.choose_attachment(nil)
      assert_nil As2::Message.choose_attachment([])
    end

    it 'does not break if parts do not have content types' do
      decrypted_message = <<~EOF
      Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha1; boundary="1660166778989-boundary"

      --1660166778989-boundary

      This is text content.


      --1660166778989-boundary

      ISA*TOTALLY*LEGAL*EDI~

      --1660166778989-boundary

      blah blah blah blah
      --1660166778989-boundary
      EOF

      mail = Mail.new(decrypted_message)
      chosen = As2::Message.choose_attachment(mail.parts)
      assert "This is text content.\n\n", chosen.body.to_s
    end

    it 'chooses an EDI part if available' do
      decrypted_message = <<~EOF
      Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha1; boundary="1660166778989-boundary"

      --1660166778989-boundary
      Content-Type: application/octet-stream

      This is text content.


      --1660166778989-boundary
      Content-Type: application/edi-x12

      ISA*TOTALLY*LEGAL*EDI~

      --1660166778989-boundary
      Content-Type: application/pkcs7-signature

      blah blah blah blah
      --1660166778989-boundary
      EOF

      mail = Mail.new(decrypted_message)
      chosen = As2::Message.choose_attachment(mail.parts)

      assert_equal "ISA*TOTALLY*LEGAL*EDI~\n", chosen.body.to_s

      ## reversing order of EDI & text parts, to make sure we have sorting right.
      ## also ensuring case-insensitive matching.
      decrypted_message = <<~EOF
      Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha1; boundary="1660166778989-boundary"

      --1660166778989-boundary
      Content-Type: application/EDI-X12

      ISA*TOTALLY*LEGAL*EDI~

      --1660166778989-boundary
      Content-Type: application/octet-stream

      This is text content.


      --1660166778989-boundary
      Content-Type: application/pkcs7-signature

      blah blah blah blah
      --1660166778989-boundary
      EOF

      mail = Mail.new(decrypted_message)
      chosen = As2::Message.choose_attachment(mail.parts)

      assert_equal "ISA*TOTALLY*LEGAL*EDI~\n", chosen.body.to_s
    end

    it 'chooses a non-EDI part if no EDI parts are available' do
      decrypted_message = <<~EOF
      Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha1; boundary="1660166778989-boundary"

      --1660166778989-boundary
      Content-Type: application/octet-stream

      This is text content.


      --1660166778989-boundary
      Content-Type: application/pkcs7-signature

      blah blah blah blah
      --1660166778989-boundary
      EOF

      mail = Mail.new(decrypted_message)
      chosen = As2::Message.choose_attachment(mail.parts)

      assert_equal "This is text content.\n\n", chosen.body.to_s
    end

    it 'returns nil if no non-signature parts are available' do
      decrypted_message = <<~EOF
      Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha1; boundary="1660166778989-boundary"

      --1660166778989-boundary
      Content-Type: application/pkcs7-signature

      blah blah blah blah
      --1660166778989-boundary
      EOF

      mail = Mail.new(decrypted_message)
      chosen = As2::Message.choose_attachment(mail.parts)

      assert_nil chosen
    end

    it 'skips x-pkcs7-signature also' do
      decrypted_message = <<~EOF
      Content-Type: multipart/signed; protocol="application/x-pkcs7-signature"; micalg="sha-256"; \tboundary="----855604ACC1530DC371EC9487F598CF78"

      ------855604ACC1530DC371EC9487F598CF78
      Content-Type: application/octet-stream

      This is text content.
      ------855604ACC1530DC371EC9487F598CF78
      Content-Type: application/x-pkcs7-signature; name="smime.p7s"
      Content-Transfer-Encoding: base64
      Content-Disposition: attachment; filename="smime.p7s"

      blah blah blah blah
      ------855604ACC1530DC371EC9487F598CF78--
      EOF

      mail = Mail.new(decrypted_message)
      chosen = As2::Message.choose_attachment(mail.parts)

      assert_equal "This is text content.", chosen.body.to_s
    end
  end

  describe '.choose_signature' do
    it 'returns nil if no parts are given' do
      assert_nil As2::Message.choose_signature(nil)
      assert_nil As2::Message.choose_signature([])
    end

    it 'finds the pkcs7-signature part of the message' do
      decrypted_message = <<~EOF
      Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg="sha-256"; \tboundary="----855604ACC1530DC371EC9487F598CF78"

      ------855604ACC1530DC371EC9487F598CF78
      Content-Type: application/octet-stream

      This is text content.
      ------855604ACC1530DC371EC9487F598CF78
      Content-Type: application/pkcs7-signature; name="smime.p7s"
      Content-Transfer-Encoding: base64
      Content-Disposition: attachment; filename="smime.p7s"

      #{Base64.encode64('sig-sig-sig')}
      ------855604ACC1530DC371EC9487F598CF78--
      EOF

      mail = Mail.new(decrypted_message)

      signature = As2::Message.choose_signature(mail.parts)
      assert_equal "sig-sig-sig", signature.body.to_s
    end

    it 'finds the x-pkcs7-signature part of the message' do
      decrypted_message = <<~EOF
      Content-Type: multipart/signed; protocol="application/x-pkcs7-signature"; micalg="sha-256"; \tboundary="----855604ACC1530DC371EC9487F598CF78"

      ------855604ACC1530DC371EC9487F598CF78
      Content-Type: application/octet-stream

      This is text content.
      ------855604ACC1530DC371EC9487F598CF78
      Content-Type: application/x-pkcs7-signature; name="smime.p7s"
      Content-Transfer-Encoding: base64
      Content-Disposition: attachment; filename="smime.p7s"

      #{Base64.encode64('sig-sig-sig')}
      ------855604ACC1530DC371EC9487F598CF78--
      EOF

      mail = Mail.new(decrypted_message)

      signature = As2::Message.choose_signature(mail.parts)
      assert_equal "sig-sig-sig", signature.body.to_s
    end

    it 'returns nil if message is unsigned' do
      decrypted_message = <<~EOF
      "blah blah blah"
      EOF

      mail = Mail.new(decrypted_message)

      signature = As2::Message.choose_signature(mail.parts)
      assert_nil signature
    end
  end

  # most testing of `.verify` is via #valid_signature? tests below.
  describe '.verify' do
    it 'handles an invalid signature text' do
      result = As2::Message.verify(
                 content: 'this is a message',
                 signature_text: '--invalid--',
                 certificate: OpenSSL::X509::Certificate.new
               )

      assert_equal false, result[:valid]
      assert_equal "ArgumentError: Could not parse the PKCS7: not enough data", result[:error]
    end
  end

  describe '.mic' do
    # expected MIC values collected by running OpenAS2 locally & examining logs
    #
    #  1. these refer to using (for example) `<attribute name="content_transfer_encoding" value="binary"/>`
    #     in the OpenAS2 partnership configuration. the Content-Transfer-Encoding here is only specified in
    #     the S/MIME part. The HTTP body is always binary and no HTTP Content-Transfer-Encoding header is set.
    #  2. examples were run with OpenAS2 configuration `<attribute name="prevent_canonicalization_for_mic" value="false"/>`
    describe 'with OpenAS2' do
      it 'creates correct MIC value when partner is using "Content-Transfer-Encoding: binary"' do
        raw_source = "\r\nContent-Type: application/EDI-X12\r\nContent-Transfer-Encoding: binary\r\nContent-Disposition: Attachment; filename=\"message.txt\"\r\n\r\nhi\n"
        mail_part = Mail::Part.new(raw_source)
        assert_equal 'JhDUnVTSRY5N+kvBbZwVxTbw+CGjHWPIFkse+CpT/2M=', As2::Message.mic(mail_part, 'sha256')

        raw_source = "\r\nContent-Type: application/EDI-X12\r\nContent-Transfer-Encoding: binary\r\nContent-Disposition: Attachment; filename=\"message.txt\"\r\n\r\nmessage\nwith\nnewlines\n"
        mail_part = Mail::Part.new(raw_source)
        assert_equal 'F0BUXjqg/awvPSIvSshQLSJyZaPg9G+z/0cEwufIb0E=', As2::Message.mic(mail_part, 'sha256')

        raw_source = "\r\nContent-Type: application/EDI-X12\r\nContent-Transfer-Encoding: binary\r\nContent-Disposition: Attachment; filename=\"blues_brothers.txt\"\r\n\r\n106 miles to Chicago\n"
        mail_part = Mail::Part.new(raw_source)
        assert_equal 'S1wmuKWg6c18/oAvu2joa42lHHI=', As2::Message.mic(mail_part, 'sha1')
      end

      it 'creates correct MIC value when partner is using "Content-Transfer-Encoding: base64"' do
        raw_source = "\r\nContent-Type: application/EDI-X12\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: Attachment; filename=\"message.txt\"\r\n\r\naGkK"
        mail_part = Mail::Part.new(raw_source)
        assert_equal 'lmB+692bTgwxwuaaf6ObFx7w0DdVKYXJmr14RUO5/l8=', As2::Message.mic(mail_part, 'sha256')
      end
    end

    describe 'with Mendelson' do
      # as with OpenAS2, "Content-Transfer-Encoding: base64" refers only to the S/MIME message part
      # Menedelson server sends a binary HTTP body with no HTTP Content-Transfer-Encoding header
      it 'creates correct MIC value when partner is using "Content-Transfer-Encoding: base64"' do
        raw_source = "\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=message.txt\r\n\r\naGVsbG8K"
        mail_part = Mail::Part.new(raw_source)
        assert_equal '2l+fd1V8RsWLn6d27QVskwTc7AM=', As2::Message.mic(mail_part, 'sha1')

        raw_source = "\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=message.txt\r\n\r\ndGhpcwptZXNzYWdlCmhhcwptYW55Cm5ld2xpbmVzCmluZGVlZAo="
        mail_part = Mail::Part.new(raw_source)
        assert_equal 'iW+hN8iJrfkyplf2/8wpRtGsH+rg11o12XwTFruiUWw=', As2::Message.mic(mail_part, 'sha256')
      end

      it 'creates correct MIC value when partner is using "Content-Transfer-Encoding: binary"' do
        raw_source = "\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\nContent-Disposition: attachment; filename=n_padded.txt\r\n\r\n\na test message\nseparated by\nsingle newline char\n"
        mail_part = Mail::Part.new(raw_source)
        assert_equal 'HFxKApuTnevgyutbKWWfOc2sUh+yKpoQyIoOr00IFmI=', As2::Message.mic(mail_part, 'sha256')
      end
    end
  end

  describe '#initialize' do
    it 'allows specification of a mic_algorithm' do
      message = As2::Message.new(@encrypted_message, @server_key, @server_crt,
                  mic_algorithm: 'sha1'
                )
      assert_equal 'sha1', message.mic_algorithm
    end

    it 'defaults mic_algorithm to sha256' do
      message = As2::Message.new(@encrypted_message, @server_key, @server_crt)
      assert_equal 'sha256', message.mic_algorithm
    end

    it 'raises if given mic algorithm is unrecognized' do
      assert_raises(ArgumentError) {
        As2::Message.new(@encrypted_message, @server_key, @server_crt,
          mic_algorithm: 'wat'
        )
      }
    end
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
      decrypted = encrypted.decrypt @server_key, @server_crt

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

    # MIC values described in comments were confirmed to be correct for OpenAS2
    # by examining OpenAS2 server logs at time of transmission.
    describe 'with OpenAS2' do
      describe 'using Content-Transfer-Encoding: base64' do
        it 'can verify a message with \n line endings' do
          # echo -n "\nencoding:binary\nline-ending:newline\n" > base64_newline.txt
          # MIC: 'BPd3v8Q+vdx13PEe/K0egVMiJfi6DBSgmyo4mKgM5bU=' (sha256)
          encrypted = File.read('test/fixtures/from_openas2/base64_newline.pkcs7')
          message = As2::Message.new(encrypted, @server_key, @server_crt)
          assert message.valid_signature?(@client_crt)
        end

        it 'can verify a message with \r\n line endings' do # base64_crlf
          # echo -n "\r\nencoding:binary\r\nline-ending:crlf\r\n" > base64_crlf.txt
          # MIC: 'CFv2BSzsV6zLv44PD2UBeASAjg5bL1L3DHZnJrsRUAI=' (sha256)
          encrypted = File.read('test/fixtures/from_openas2/base64_crlf.pkcs7')
          message = As2::Message.new(encrypted, @server_key, @server_crt)
          assert message.valid_signature?(@client_crt)
        end
      end

      describe 'using Content-Transfer-Encoding: binary' do
        it 'can verify a message starting with \n\n' do
          # echo -n "\n\nencoding:binary\nline-ending:newline\n" > binary_initial_double_newline.txt
          # MIC: 'O0pF3FMeakUSGbKNmD0rushtjWNfLO29eDvdOiwKoqs=' (sha256)
          encrypted = File.read('test/fixtures/from_openas2/binary_initial_double_newline.pkcs7')
          message = As2::Message.new(encrypted, @server_key, @server_crt)
          assert message.valid_signature?(@client_crt)
        end

        it 'can verify a message with \n line endings' do
          # echo -n "encoding:binary\nline-ending:newline\nmore text\nis good text\ndon't you think?" > binary_newlines.txt
          # MIC: 'RX+gWZEQOkou02/9eOPCbtUNYxTJXZbGXtslssIezaY=' (sha256)
          encrypted = File.read('test/fixtures/from_openas2/binary_newlines.pkcs7')
          message = As2::Message.new(encrypted, @server_key, @server_crt)
          assert message.valid_signature?(@client_crt)
        end

        it 'can verify a message ending with \n\n' do
          # echo -n "encoding:binary\nline-ending:newline\nmore text\nis good text\ndon't you think?\n\n" > binary_trailing_double_newline.txt
          # MIC: 'lGv3z+A33GjNFox7Yzkn+PTNNPbZ19JRhMOvXgp2zSk=' (sha256)
          encrypted = File.read('test/fixtures/from_openas2/binary_trailing_double_newline.pkcs7')
          message = As2::Message.new(encrypted, @server_key, @server_crt)
          assert message.valid_signature?(@client_crt)
        end

        it 'can verify a message starting with \r\n\r\n' do
          # echo -n "\r\n\r\nencoding:binary\nline-ending:crlf\r\nmore text\r\n" > binary_initial_double_crlf.txt
          # MIC: 'dICWO5M3qSfVmyvDHXnVyKGLxkuTlIb4DInirNKBRT0=' (sha256)
          encrypted = File.read('test/fixtures/from_openas2/binary_initial_double_crlf.pkcs7')
          message = As2::Message.new(encrypted, @server_key, @server_crt)
          assert message.valid_signature?(@client_crt)
        end

        it 'can verify a message with \r\n line endings' do
          # echo -n "encoding:binary\r\nline-ending:crlf\r\nmore text\r\n" > binary_crlf_lines.txt
          # MIC: 'P2Ox0s8iJBd3TcNyYfv4IHO1LfkS32U8sdoT/axPjio=' (sha256)
          encrypted = File.read('test/fixtures/from_openas2/binary_crlf_lines.pkcs7')
          message = As2::Message.new(encrypted, @server_key, @server_crt)
          assert message.valid_signature?(@client_crt)
        end

        it 'can verify a message ending with \r\n\r\n' do
          # echo -n "encoding:binary\r\nline-ending:crlf\r\nmore text\r\n\r\n" > binary_trailing_double_crlf.txt
          # MIC: '4FuEDJ+N581GkvjZV4BT7iFsC4JRqGC2pLP2IIuOd1c=' (sha256)
          encrypted = File.read('test/fixtures/from_openas2/binary_trailing_double_crlf.pkcs7')
          message = As2::Message.new(encrypted, @server_key, @server_crt)
          assert message.valid_signature?(@client_crt)
        end
      end
    end

    describe 'with Mendelson' do
      describe 'using Content-Transfer-Encoding: base64' do
        it 'can verify a message with \n line endings' do
          # echo -n "\nencoding:binary\nline-ending:newline\n" > base64_newline.txt
          # MIC: 'WA7oyN5wqF15kPR65fIn+V4yzvsDnpFc025+mSgt0hI=' (sha256)
          encrypted = File.read('test/fixtures/from_mendelson/base64_newline.pkcs7')
          message = As2::Message.new(encrypted, @server_key, @server_crt)
          assert message.valid_signature?(@client_crt)
        end

        it 'can verify a message with \r\n line endings' do  # base64_crlf
          # echo -n "\r\nencoding:binary\r\nline-ending:crlf\r\n" > base64_crlf.txt
          # MIC: '4ZkgJXocVDxYRtaitolX29rY9yAWLfmht8NGLCWQtnc=' (sha256)
          encrypted = File.read('test/fixtures/from_mendelson/base64_crlf.pkcs7')
          message = As2::Message.new(encrypted, @server_key, @server_crt)
          assert message.valid_signature?(@client_crt)
        end
      end

      describe 'using Content-Transfer-Encoding: binary' do
        it 'can verify a message starting with \n\n' do
          # echo -n "\n\nencoding:binary\nline-ending:newline\n" > binary_initial_double_newline.txt
          # MIC: '1a+TLiA2JUtdqd+CVAGbZnRUhSltx5I2nuK3ZaPswB4=' (sha256)
          encrypted = File.read('test/fixtures/from_mendelson/binary_initial_double_newline.pkcs7')
          message = As2::Message.new(encrypted, @server_key, @server_crt)
          assert message.valid_signature?(@client_crt)
        end

        it 'can verify a message with \n line endings' do
          # echo -n "encoding:binary\nline-ending:newline\nmore text\nis good text\ndon't you think?" > binary_newlines.txt
          # MIC: 'eYfOn1VkdCfSQf7trg6Jy8qj7CqMACXtLFY4XSfXyFs=' (sha256)
          encrypted = File.read('test/fixtures/from_mendelson/binary_newlines.pkcs7')
          message = As2::Message.new(encrypted, @server_key, @server_crt)
          assert message.valid_signature?(@client_crt)
        end

        it 'can verify a message ending with \n\n' do
          # echo -n "encoding:binary\nline-ending:newline\nmore text\nis good text\ndon't you think?\n\n" > binary_trailing_double_newline.txt
          # MIC: 'WB54rweCaTk5PkPJApqhks/8wYrN2FhFYJwdwHr4wcY=' (sha256)
          encrypted = File.read('test/fixtures/from_mendelson/binary_trailing_double_newline.pkcs7')
          message = As2::Message.new(encrypted, @server_key, @server_crt)
          assert message.valid_signature?(@client_crt)
        end

        it 'can verify a message starting with \r\n\r\n' do
          # echo -n "\r\n\r\nencoding:binary\r\nline-ending:crlf\r\nmore text\r\n" > binary_initial_double_crlf.txt
          # MIC: '46chrZzSsA18bQCAFG9I+UGndcj7QPO5FH6ESccX79U=' (sha256)
          encrypted = File.read('test/fixtures/from_mendelson/binary_initial_double_crlf.pkcs7')
          message = As2::Message.new(encrypted, @server_key, @server_crt)
          assert message.valid_signature?(@client_crt)
        end

        it 'can verify a message with \r\n line endings' do
          # echo -n "encoding:binary\r\nline-ending:crlf\r\nmore text\r\n" > binary_crlf_lines.txt
          # MIC: 'vcqn9ReBEUyJLEe1A0l8L+aVqXGaOLgKTP0us9PgLOw=' (sha256)
          encrypted = File.read('test/fixtures/from_mendelson/binary_crlf_lines.pkcs7')
          message = As2::Message.new(encrypted, @server_key, @server_crt)
          assert message.valid_signature?(@client_crt)
        end

        it 'can verify a message ending with \r\n\r\n' do
          # echo -n "encoding:binary\r\nline-ending:crlf\r\nmore text\r\n\r\n" > binary_trailing_double_crlf.txt
          # MIC: 'cToHc8OeBOqEuuowBfXWYmMb0ZKTa51LfOa13aK1i6Q=' (sha256)
          encrypted = File.read('test/fixtures/from_mendelson/binary_trailing_double_crlf.pkcs7')
          message = As2::Message.new(encrypted, @server_key, @server_crt)
          assert message.valid_signature?(@client_crt)
        end
      end
    end
  end

  # this test will fail (& can be removed) when mail bug is resolved.
  # https://github.com/mikel/mail/pull/1511
  describe 'workaround for \r\n mail bug' do
    describe 'when main signature verification fails and fallback verification succeeds' do
      # send a binary payload which fails original signature verification, but works during fallback
      # then make assertion on the MIC which is calculated.
      it 'updates attachment to be correct' do
        encrypted = File.read('test/fixtures/from_mendelson/binary_trailing_double_newline.pkcs7')
        message = As2::Message.new(encrypted, @server_key, @server_crt)

        # this is invalid, "\n" replaced with "\r\n"
        original_attachment_raw_source = message.attachment.raw_source
        original_mic = message.mic

        # here we use fallback code to correct `message.attachment`
        assert message.valid_signature?(@client_crt)

        refute_equal original_attachment_raw_source, message.attachment.raw_source
        refute_equal original_mic, message.mic
        assert_equal 'WB54rweCaTk5PkPJApqhks/8wYrN2FhFYJwdwHr4wcY=', message.mic
      end
    end
  end

  describe '#mic' do
    it 'returns a message integrity check value' do
      assert_equal @message.mic, "7S8fpWpx+ASDj0sCAIfS64Q+sm0ezIpDLhPs9wIEy8I="
    end
  end

  describe '#mic_algorithm' do
    it 'returns a string describing the algorithm used for MIC calculation' do
      assert_equal @message.mic_algorithm, 'sha256'
    end

    it 'preserves formatting of mic algorithm string' do
      expected_sha1_mic = 'nyyjxao566rCbElBu0v+lrDjAq4='

      # this shouldn't matter, but just in case it does...
      # make sure we send back exactly what we got.
      message = As2::Message.new(@encrypted_message, @server_key, @server_crt,
                  mic_algorithm: 'sha1'
                )
      assert_equal expected_sha1_mic, message.mic
      assert_equal 'sha1', message.mic_algorithm

      message = As2::Message.new(@encrypted_message, @server_key, @server_crt,
                  mic_algorithm: 'SHA1'
                )
      assert_equal expected_sha1_mic, message.mic
      assert_equal 'SHA1', message.mic_algorithm

      message = As2::Message.new(@encrypted_message, @server_key, @server_crt,
                  mic_algorithm: 'sha-1'
                )
      assert_equal expected_sha1_mic, message.mic
      assert_equal 'sha-1', message.mic_algorithm

      message = As2::Message.new(@encrypted_message, @server_key, @server_crt,
                  mic_algorithm: 'SHA-1'
                )
      assert_equal expected_sha1_mic, message.mic
      assert_equal 'SHA-1', message.mic_algorithm

    end
  end

  describe '#attachment' do
    it 'provides the inbound message as a Mail::Part' do
      attachment = @message.attachment
      assert_equal attachment.class, Mail::Part
      assert_equal attachment.content_type, 'application/edi-consent'
      assert_equal @correct_cleartext, attachment.body.decoded
      assert_equal "hello_world_2.txt", attachment.filename
    end

    it 'chooses a non-edi part if no edi parts are available' do
      encrypted_message = File.read('test/fixtures/non_edi_content.pkcs7')
      correct_cleartext = "this is a message\n\n"

      message = As2::Message.new(encrypted_message, @server_key, @server_crt)
      attachment = message.attachment

      assert_equal attachment.class, Mail::Part
      assert_equal attachment.content_type, 'application/octet-stream'
      assert_equal correct_cleartext, attachment.body.to_s
      assert_nil attachment.filename
    end
  end

  describe '#signature' do
    it 'provides the signature as a Mail::Part' do
      signature = @message.signature
      assert_equal signature.class, Mail::Part
      assert_equal signature.content_type, 'application/pkcs7-signature; name=smime.p7s; smime-type=signed-data'
    end
  end
end
