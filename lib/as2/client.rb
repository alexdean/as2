require 'net/http'

module As2
  class Client
    attr_reader :partner, :server_info

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
      req['AS2-From'] = as2_from
      req['AS2-To'] = as2_to
      req['Subject'] = 'AS2 Transaction'
      req['Content-Type'] = 'application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m'
      req['Date'] = Time.now.rfc2822
      req['Disposition-Notification-To'] = @server_info.url.to_s
      req['Disposition-Notification-Options'] = "signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, #{outbound_mic_algorithm}"
      req['Content-Disposition'] = 'attachment; filename="smime.p7m"'
      req['Recipient-Address'] = @partner.url.to_s
      req['Message-ID'] = outbound_message_id

      document_content = content || File.read(file_name)

      document_payload =  "Content-Type: #{content_type}\r\n"
      document_payload << "Content-Transfer-Encoding: base64\r\n"
      document_payload << "Content-Disposition: attachment; filename=#{file_name}\r\n"
      document_payload << "\r\n"
      document_payload << Base64.strict_encode64(document_content)

      signature = OpenSSL::PKCS7.sign @server_info.certificate, @server_info.pkey, document_payload
      signature.detached = true
      container = OpenSSL::PKCS7.write_smime signature, document_payload
      cipher = OpenSSL::Cipher::AES256.new(:CBC) # default, but we might have to make this configurable
      encrypted = OpenSSL::PKCS7.encrypt [@partner.certificate], container, cipher

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
        http.use_ssl = @partner.url.scheme == 'https'
        # http.set_debug_output $stderr
        # http.verify_mode = OpenSSL::SSL::VERIFY_NONE

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
                                   certificate: @partner.certificate
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
    def parse_signed_mdn(multipart_signed_message:, certificate:)
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
        smime.verify [certificate], OpenSSL::X509::Store.new, nil, OpenSSL::PKCS7::NOVERIFY | OpenSSL::PKCS7::NOINTERN

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
                   certificate: @partner.certificate
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
