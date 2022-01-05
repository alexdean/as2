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

    Result = Struct.new :success, :response, :mic_matched, :mid_matched, :body, :disp_code

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
      http = Net::HTTP.new(@partner.url.host, @partner.url.port)
      http.use_ssl = @partner.url.scheme == 'https'
      # http.set_debug_output $stderr
      http.start do
        req = Net::HTTP::Post.new @partner.url.path
        req['AS2-Version'] = '1.2'
        req['AS2-From'] = @server_info.name
        req['AS2-To'] = @partner.name
        req['Subject'] = 'AS2 EDI Transaction'
        req['Content-Type'] = 'application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m'
        req['Disposition-Notification-To'] = @server_info.url.to_s
        req['Disposition-Notification-Options'] = 'signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, sha1'
        req['Content-Disposition'] = 'attachment; filename="smime.p7m"'
        req['Recipient-Address'] = @server_info.url.to_s
        req['Content-Transfer-Encoding'] = 'base64'
        req['Message-ID'] = "<#{@server_info.name}-#{Time.now.strftime('%Y%m%d%H%M%S')}@#{@server_info.url.host}>"

        document_content = content || File.read(file_name)

        document_payload =  "Content-Type: application/EDI-Consent\r\n"
        document_payload << "Content-Transfer-Encoding: base64\r\n"
        document_payload << "Content-Disposition: attachment; filename=#{file_name}\r\n"
        document_payload << "\r\n"
        document_payload << Base64.strict_encode64(document_content)

        signature = OpenSSL::PKCS7.sign @server_info.certificate, @server_info.pkey, document_payload
        signature.detached = true
        container = OpenSSL::PKCS7.write_smime signature, document_payload
        encrypted = OpenSSL::PKCS7.encrypt [@partner.certificate], container
        smime_encrypted = OpenSSL::PKCS7.write_smime encrypted

        # w/o the `#sub` call, we get this:
        # ArgumentError: Could not parse the PKCS7: not enough data
        #   lib/as2/message.rb:7:in `initialize'
        #   lib/as2/message.rb:7:in `new'
        #   lib/as2/message.rb:7:in `initialize'
        #   lib/as2/server.rb:36:in `new'
        #   lib/as2/server.rb:36:in `call'
        #   test/client_test.rb:78:in `block (4 levels) in <top (required)>'
        req.body = smime_encrypted.sub(/^.+?\n\n/m, '')

        resp = http.request(req)
        success = resp.code == '200'
        mic_matched = false
        mid_matched = false
        disp_code = nil
        plain_text_body = nil

        if success
          resp_body = resp.body

          smime = OpenSSL::PKCS7.read_smime "Content-Type: #{resp['Content-Type']}\r\n#{resp_body}"

          # based on As2::Message version
          # TODO: test cases based on valid/invalid responses. (response signed with wrong certificate, etc.)
          smime.verify [@partner.certificate], OpenSSL::X509::Store.new, nil, OpenSSL::PKCS7::NOVERIFY | OpenSSL::PKCS7::NOINTERN

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

              if req['Message-ID'] == options['Original-Message-ID']
                mid_matched = true
              else
                success = false
              end

              # do mic calc using the algorithm specified by server.
              # (even if we specify sha1, server may send back MIC using a different algo.)
              received_mic, micalg = options['Received-Content-MIC'].split(',').map(&:strip)
              micalg ||= 'sha1'
              mic = As2::DigestSelector.for_code(micalg).base64digest(document_payload)

              if received_mic == mic
                mic_matched = true
              else
                success = false
              end

              disp_code = options['Disposition']
              success = disp_code.end_with?('processed')
            end
          end
        end

        Result.new success, resp, mic_matched, mid_matched, plain_text_body, disp_code
      end
    end
  end
end
