require 'net/http'

module As2
  class Client
    attr_reader :partner, :server_info

    def self.valid_outbound_formats
      ['v0', 'v1']
    end

    def self.valid_encryption_ciphers
      OpenSSL::Cipher.ciphers
    end

    # @param [As2::Config::Partner,String] partner The partner to send a message to.
    #   If a string is given, it should be a partner name which has been registered
    #   via a call to #add_partner.
    # @param [As2::Config::ServerInfo,nil] server_info The server info used to identify
    #   this client to the partner. If omitted, the main As2::Config.server_info will be used.
    # @param [Logger, nil] logger If supplied, some additional information about how
    #   messages are processed will be written here.
    def initialize(partner, server_info: nil, logger: nil)
      @logger = logger || Logger.new('/dev/null')

      if partner.is_a?(As2::Config::Partner)
        @partner = partner
      else
        @partner = Config.partners[partner]
        unless @partner
          raise "Partner #{partner} is not registered"
        end
      end

      @server_info = server_info || Config.server_info
    end

    def as2_to
      @partner.name
    end

    def as2_from
      @server_info.name
    end

    # Send a file to a partner
    #
    #   * If the content parameter is omitted, then `file_name` must be a path
    #     to a local file, whose contents will be sent to the partner.
    #   * If content parameter is specified, file_name is only used to tell the
    #     partner the original name of the file.
    #
    # TODO: refactor to separate "build an outbound message" from "send an outbound message"
    # main benefit would be allowing the test suite to be more straightforward.
    # (wouldn't need webmock just to verify what kind of message we built...)
    #
    # @param [String] file_name
    # @param [String] content
    # @param [String] content_type This is the MIME Content-Type describing the `content` param,
    #   and will be included in the SMIME payload. It is not the HTTP Content-Type.
    # @return [As2::Client::Result]
    def send_file(file_name, content: nil, content_type: 'application/EDI-Consent')
      outbound_mic_algorithm = 'sha256'
      outbound_message_id = As2.generate_message_id(@server_info)

      req = Net::HTTP::Post.new @partner.url.path
      req['AS2-Version'] = '1.0' # 1.1 includes compression support, which we dont implement.
      req['AS2-From'] = As2.quoted_system_identifier(as2_from)
      req['AS2-To'] = As2.quoted_system_identifier(as2_to)
      req['Subject'] = 'AS2 Transaction'
      req['Content-Type'] = 'application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m'
      req['Date'] = Time.now.rfc2822
      req['Disposition-Notification-To'] = @server_info.url.to_s
      req['Disposition-Notification-Options'] = "signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, #{outbound_mic_algorithm}"
      req['Content-Disposition'] = 'attachment; filename="smime.p7m"'
      req['Recipient-Address'] = @partner.url.to_s
      req['Message-ID'] = outbound_message_id

      document_content = content || File.read(file_name)
      outbound_format = @partner&.outbound_format || 'v0'

      if outbound_format == 'v1'
        format_method = :format_body_v1
      else
        format_method = :format_body_v0
      end

      document_payload, request_body = send(format_method,
                                         document_content,
                                         content_type: content_type,
                                         file_name: file_name
                                       )

      encrypted = OpenSSL::PKCS7.encrypt(
                    [@partner.encryption_certificate],
                    request_body,
                    @partner.encryption_cipher_instance
                  )

      # > HTTP can handle binary data and so there is no need to use the
      # > content transfer encodings of MIME
      #
      # https://datatracker.ietf.org/doc/html/rfc4130#section-5.2.1
      req.body = encrypted.to_der

      resp = nil
      exception = nil
      mdn_report = {}

      begin
        # note: to pass this traffic through a debugging proxy (like Charles)
        # set ENV['http_proxy'].
        http = Net::HTTP.new(@partner.url.host, @partner.url.port)

        use_ssl = @partner.url.scheme == 'https'
        http.use_ssl = use_ssl
        if use_ssl
          if @partner.tls_verify_mode
            http.verify_mode = @partner.tls_verify_mode
          end
        end

        # http.set_debug_output $stderr

        http.start do
          resp = http.request(req)
        end

        if resp && resp.code.start_with?('2')
          mdn_report = evaluate_mdn(
                         mdn_content_type: resp['Content-Type'],
                         mdn_body: resp.body,
                         original_message_id: req['Message-ID'],
                         original_body: document_payload
                       )
        end
      rescue => e
        exception = e
      end

      Result.new(
        request: req,
        response: resp,
        mic_matched: mdn_report[:mic_matched],
        mid_matched: mdn_report[:mid_matched],
        body: mdn_report[:plain_text_body],
        disposition: mdn_report[:disposition],
        signature_verification_error: mdn_report[:signature_verification_error],
        exception: exception,
        outbound_message_id: outbound_message_id
      )
    end

    # 'original' body formatting
    #
    # 1. uses OpenSSL::PKCS7.write_smime to build MIME body
    #   * includes plain-text "this is an S/MIME message" note prior to initial
    #     MIME boundary
    # 2. uses non-standard application/x-pkcs7-* content types
    # 3. MIME boundaries and signature have \n line endings
    #
    # this format is understood by Mendelson, OpenAS2, and several commercial
    # products (GoAnywhere MFT). it is not understood by IBM Sterling B2B Integrator.
    #
    # @param [String] document_content the content to be transmitted
    # @param [String] content_type the MIME type for document_content
    # @param [String] file_name The filename to be transmitted to the partner
    # @return [Array]
    #   first item is the full document part of the transmission (including) MIME headers.
    #   second item is the complete HTTP body.
    def format_body_v0(document_content, content_type:, file_name:)
      document_payload =  "Content-Type: #{content_type}\r\n"
      document_payload << "Content-Transfer-Encoding: base64\r\n"
      document_payload << "Content-Disposition: attachment; filename=#{file_name}\r\n"
      document_payload << "\r\n"
      document_payload << Base64.strict_encode64(document_content)

      signature = OpenSSL::PKCS7.sign(@server_info.certificate, @server_info.pkey, document_payload)
      signature.detached = true

      [document_payload, OpenSSL::PKCS7.write_smime(signature, document_payload)]
    end

    # updated body formatting
    #
    # 1. no content before the first MIME boundary
    # 2. uses standard application/pkcs7-* content types
    # 3. MIME boundaries and signature have \r\n line endings
    # 4. adds parameter smime-type=signed-data to the signature's Content-Type
    #
    # this format is understood by Mendelson, OpenAS2, and several commercial
    # products (GoAnywhere MFT) and IBM Sterling B2B Integrator.
    #
    # @param [String] document_content the content to be transmitted
    # @param [String] content_type the MIME type for document_content
    # @param [String] file_name The filename to be transmitted to the partner
    # @return [Array]
    #   first item is the full document part of the transmission (including) MIME headers.
    #   second item is the complete HTTP body.
    def format_body_v1(document_content, content_type:, file_name:)
      document_payload =  "Content-Type: #{content_type}\r\n"
      document_payload << "Content-Transfer-Encoding: base64\r\n"
      document_payload << "Content-Disposition: attachment; filename=#{file_name}\r\n"
      document_payload << "\r\n"
      document_payload << Base64.encode64(document_content)

      signature = OpenSSL::PKCS7.sign(@server_info.certificate, @server_info.pkey, document_payload)
      signature.detached = true

      # PEM (base64-encoded) signature
      bare_pem_signature = signature.to_pem
      # strip off the '-----BEGIN PKCS7-----' / '-----END PKCS7-----' delimiters
      bare_pem_signature.gsub!(/^-----[^\n]+\n/, '')
      # and update to canonical \r\n line endings
      bare_pem_signature.gsub!(/(?<!\r)\n/, "\r\n")

      # this is a hack until i can determine a better way to get the micalg parameter
      # from the pkcs7 signature generated above...
      # https://stackoverflow.com/questions/75934159/how-does-openssl-smime-determine-micalg-parameter
      #
      # also tried approach outlined in https://stackoverflow.com/questions/53044007/how-to-use-sha1-digest-during-signing-with-opensslpkcs7-sign-when-creating-smi
      # but the signature generated by that method lacks some essential data. verifying those
      # signatures results in an openssl error "unable to find message digest"
      smime_body = OpenSSL::PKCS7.write_smime(signature, document_payload)
      micalg = smime_body[/^Content-Type: multipart\/signed.*micalg=\"([^"]+)/m, 1]

      # generate a MIME part boundary
      #
      # > A good strategy is to choose a boundary that includes
      # > a character sequence such as "=_" which can never appear in a
      # > quoted-printable body.
      #
      # https://www.rfc-editor.org/rfc/rfc2045#page-21
      boundary = "----=_#{SecureRandom.hex(16).upcase}"
      body_boundary = "--#{boundary}"

      # body's mime headers
      body = "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=#{micalg};  boundary=\"#{boundary}\"\r\n"
      body += "\r\n"

      # first body part: the document
      body += body_boundary + "\r\n"
      body += document_payload + "\r\n"

      # second body part: the signature
      body += body_boundary + "\r\n"
      body += "Content-Type: application/pkcs7-signature; name=smime.p7s; smime-type=signed-data\r\n"
      body += "Content-Transfer-Encoding: base64\r\n"
      body += "Content-Disposition: attachment; filename=\"smime.p7s\"\r\n"
      body += "\r\n"
      body += bare_pem_signature
      body += body_boundary + "--\r\n"

      [document_payload, body]
    end

    def evaluate_mdn(mdn_body:, mdn_content_type:, original_message_id:, original_body:)
      report = {
        signature_verification_error: :not_checked,
        mic_matched: nil,
        mid_matched: nil,
        disposition: nil,
        plain_text_body: nil
      }

      # MDN bodies we've seen so far don't include Content-Type, which causes `read_smime` to fail.
      response_content = "Content-Type: #{mdn_content_type.to_s.strip}\r\n\r\n#{mdn_body}"

      if mdn_content_type.start_with?('multipart/signed')
        result = parse_signed_mdn(
                                   multipart_signed_message: response_content,
                                   signing_certificate: @partner.signing_certificate
                                 )
        mdn_report = result[:mdn_report]
        report[:signature_verification_error] = result[:signature_verification_error]
      else
        # MDN may be unsigned if an error occurred, like if we sent an unrecognized As2-From header.
        mdn_report = Mail.new(response_content)
      end

      mdn_report.parts.each do |part|
        if part.content_type.start_with?('text/plain')
          report[:plain_text_body] = part.body.to_s.strip
        elsif part.content_type.start_with?('message/disposition-notification')
          # "The rules for constructing the AS2-disposition-notification content..."
          # https://datatracker.ietf.org/doc/html/rfc4130#section-7.4.3

          options = {}
          # TODO: can we use Mail built-ins for this?
          part.body.to_s.lines.each do |line|
            if line =~ /^([^:]+): (.+)$/
              # downcase because we've seen both 'Disposition' and 'disposition'
              options[$1.to_s.downcase] = $2
            end
          end

          report[:disposition] = options['disposition'].strip
          report[:mid_matched] = original_message_id == options['original-message-id'].strip

          if options['received-content-mic']
            # do mic calc using the algorithm specified by server.
            # (even if we specify sha1, server may send back MIC using a different algo.)
            received_mic, micalg = options['received-content-mic'].split(',').map(&:strip)

            # if they don't specify, we'll use the algorithm we specified in the outbound transmission.
            # but it's only a guess & may fail.
            micalg ||= outbound_mic_algorithm

            mic = As2::DigestSelector.for_code(micalg).base64digest(original_body)
            report[:mic_matched] = received_mic == mic
          end
        end
      end
      report
    end

    private

    # extract the MDN body from a multipart/signed wrapper & attempt to verify
    # the signature
    #
    # @param [String] multipart_signed_message The 'outer' MDN body, containing MIME header,
    #   MDN body (which itself is likely a multi-part object) and a signature.
    # @param [OpenSSL::X509::Certificate] verify that the MDN body was signed using this certificate
    # @return [Hash] results of the check
    #   * :mdn_mime_body [Mail::Message] The 'inner' MDN body, with signature removed
    #   * :signature_verification_error [String] Any error which resulted when checking the
    #     signature. If this is empty it means the signature was valid.
    def parse_signed_mdn(multipart_signed_message:, signing_certificate:)
      smime = nil

      begin
        # This will fail if the signature is binary-encoded. In that case
        # we rescue so we can continue to extract other data from the MDN.
        # User can decide how to proceed after the signature verification failure.
        #
        # > The parser assumes that the PKCS7 structure is always base64 encoded
        # > and will not handle the case where it is in binary format or uses quoted
        # > printable format.
        #
        # https://www.openssl.org/docs/man3.1/man3/SMIME_read_PKCS7.html
        #
        # Likely we can resolve this by building a PKCS7 manually from the MDN
        # payload, rather than using `read_smime`.
        #
        # An aside: manually base64-encoding the binary signature allows the MDN
        # to be parsed & verified via `read_smime`, so that could also be an option.
        smime = OpenSSL::PKCS7.read_smime(multipart_signed_message)
      rescue => e
        @logger.warn "error checking signature using read_smime. #{e.message}"
        signature_verification_error = e.message
      end

      if smime
        # create mail instance before #verify call.
        # `smime.data` is emptied if verification fails, which means we wouldn't know disposition & other details.
        mdn_report = Mail.new(smime.data)

        # based on As2::Message version
        # TODO: test cases based on valid/invalid responses. (response signed with wrong certificate, etc.)
        # See notes in As2::Message.verify for reasoning on flag usage
        smime.verify [signing_certificate], OpenSSL::X509::Store.new, nil, OpenSSL::PKCS7::NOVERIFY | OpenSSL::PKCS7::NOINTERN

        signature_verification_error = smime.error_string
      else
        @logger.info "trying fallback sigature verification."
        # read_smime will fail on binary-encoded MDNs. in this case, we can attempt
        # to parse the structure using Mail and do signature verification
        # slightly differently.
        #
        # what follows is the same process applied in As2::Message#valid_signature?.
        # see notes there for more info on "multipart/signed" MIME messages.
        #
        #   1. maybe unify these at some point?
        #   2. maybe always use this process, and drop initial attempt at
        #      `OpenSSL::PKCS7.read_smime` above.
        #
        # refactoring to allow using As2::Message#valid_signature? here
        # would also allow us to utilize the line-ending fixup code there

        # this should have 2 parts. the MDN report (parts[0]) and the signature (parts[1])
        #
        #  * https://datatracker.ietf.org/doc/html/rfc3851#section-3.4.3
        #  * see also https://datatracker.ietf.org/doc/html/rfc1847#section-2.1
        outer_mail = Mail.new(multipart_signed_message)

        mdn_report = outer_mail.parts[0]

        content = mdn_report.raw_source
        content = content.gsub(/\A\s+/, '')

        signature = outer_mail.parts[1]
        signature_text = signature.body.to_s

        result = As2::Message.verify(
                   content: content,
                   signature_text: signature_text,
                   signing_certificate: signing_certificate
                 )

        signature_verification_error = result[:error]
      end

      {
        mdn_report: mdn_report,
        signature_verification_error: signature_verification_error
      }
    end
  end
end
