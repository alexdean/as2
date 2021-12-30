require 'net/http'

module As2
  class Client
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

        body_content = content || File.read(file_name)

        body = StringIO.new
        body.puts "Content-Type: application/EDI-Consent"
        body.puts "Content-Transfer-Encoding: base64"
        body.puts "Content-Disposition: attachment; filename=#{file_name}"
        body.puts
        body.puts [body_content].pack("m*")

        mic = OpenSSL::Digest::SHA1.base64digest(body.string)

        pkcs7 = OpenSSL::PKCS7.sign @server_info.certificate, @server_info.pkey, body.string
        pkcs7.detached = true
        smime_signed = OpenSSL::PKCS7.write_smime pkcs7, body.string
        pkcs7 = OpenSSL::PKCS7.encrypt [@partner.certificate], smime_signed
        smime_encrypted = OpenSSL::PKCS7.write_smime pkcs7

        req.body = smime_encrypted.sub(/^.+?\n\n/m, '')

        resp = http.request(req)
        success = resp.code == '200'
        mic_matched = false
        mid_matched = false
        disp_code = nil
        body = nil
        if success
          body = resp.body

          smime = OpenSSL::PKCS7.read_smime "Content-Type: #{resp['Content-Type']}\r\n#{body}"
          smime.verify [@partner.certificate], Config.store

          mail = Mail.new smime.data
          mail.parts.each do |part|
            case part.content_type
            when 'text/plain'
              body = part.body
            when 'message/disposition-notification'
              options = {}
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

              if options['Received-Content-MIC'].start_with?(mic)
                mic_matched = true
              else
                success = false
              end

              disp_code = options['Disposition']
              success = disp_code.end_with?('processed')
            end
          end
        end
        Result.new success, resp, mic_matched, mid_matched, body, disp_code
      end
    end
  end
end
