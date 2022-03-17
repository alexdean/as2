require 'net/http'

module As2
  class Client
    attr_reader :partner, :server_info

    # @param [As2::Config::Partner,String] partner The partner to send a message to.
    #   If a string is given, it should be a partner name which has been registered
    #   via a call to #add_partner.
    # @param [As2::Config::ServerInfo,nil] server_info The server info used to identify
    #   this client to the partner. If omitted, the main As2::Config.server_info will be used.
    def initialize(partner, server_info: nil)
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

    # Send a file to a partner
    #
    #   * If the content parameter is omitted, then `file_name` must be a path
    #     to a local file, whose contents will be sent to the partner.
    #   * If content parameter is specified, file_name is only used to tell the
    #     partner the original name of the file.
    #
    # @param [String] file_name
    # @param [String] content
    # @return [As2::Client::Result]
    def send_file(file_name, content: nil)
      supported_mic_algorithms = ['sha256', 'sha1']
      outbound_message_id = As2.generate_message_id(@server_info)

      req = Net::HTTP::Post.new @partner.url.path
      req['AS2-Version'] = '1.2'
      req['AS2-From'] = @server_info.name
      req['AS2-To'] = @partner.name
      req['Subject'] = 'AS2 EDI Transaction'
      req['Content-Type'] = 'application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m'
      req['Disposition-Notification-To'] = @server_info.url.to_s
      req['Disposition-Notification-Options'] = "signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional,#{supported_mic_algorithms.join(',')}"
      req['Content-Disposition'] = 'attachment; filename="smime.p7m"'
      req['Recipient-Address'] = @server_info.url.to_s
      req['Message-ID'] = outbound_message_id

      document_content = content || File.read(file_name)

      document_payload =  "Content-Type: application/EDI-Consent\r\n"
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
      signature_verification_error = :not_checked
      exception = nil
      mic_matched = nil
      mid_matched = nil
      disposition = nil
      plain_text_body = nil

      begin
        http = Net::HTTP.new(@partner.url.host, @partner.url.port)
        http.use_ssl = @partner.url.scheme == 'https'
        # http.set_debug_output $stderr
        http.start do
          resp = http.request(req)
        end

        if resp.code == '200'
          response_content = "Content-Type: #{resp['Content-Type']}\r\n#{resp.body}"
          smime = OpenSSL::PKCS7.read_smime response_content
          # based on As2::Message version
          # TODO: test cases based on valid/invalid responses. (response signed with wrong certificate, etc.)
          smime.verify [@partner.certificate], OpenSSL::X509::Store.new, nil, OpenSSL::PKCS7::NOVERIFY | OpenSSL::PKCS7::NOINTERN
          signature_verification_error = smime.error_string

          mail = Mail.new smime.data
          mail.parts.each do |part|
            case part.content_type
            when 'text/plain'
              plain_text_body = part.body
            when 'message/disposition-notification'
              # "The rules for constructing the AS2-disposition-notification content..."
              # https://datatracker.ietf.org/doc/html/rfc4130#section-7.4.3

              options = {}
              # TODO: can we use Mail built-ins for this?
              part.body.to_s.lines.each do |line|
                if line =~ /^([^:]+): (.+)$/
                  options[$1] = $2
                end
              end

              disposition = options['Disposition']
              mid_matched = req['Message-ID'] == options['Original-Message-ID']

              # do mic calc using the algorithm specified by server.
              # (even if we specify sha1, server may send back MIC using a different algo.)
              received_mic, micalg = options['Received-Content-MIC'].split(',').map(&:strip)
              # if they don't specify, we'll use a default but it's only a guess & will likely fail.
              micalg ||= supported_mic_algorithms.first
              mic = As2::DigestSelector.for_code(micalg).base64digest(document_payload)
              mic_matched = received_mic == mic
            end
          end
        end
      rescue => e
        exception = e
      end

      Result.new(
        response: resp,
        mic_matched: mic_matched,
        mid_matched: mid_matched,
        body: plain_text_body,
        disposition: disposition,
        signature_verification_error: signature_verification_error,
        exception: exception,
        outbound_message_id: outbound_message_id
      )
    end
  end
end
