require 'rack'
require 'logger'
require 'stringio'
require 'as2/mime_generator'
require 'as2/message'

module As2
  class Server
    attr_accessor :logger

    # @param [As2::Config::ServerInfo] server_info Config used for naming of this
    #   server and key/certificate selection. If omitted, the main As2::Config.server_info is used.
    # @param [As2::Config::Partner] partner Which partner to receive messages from.
    #   If omitted, the partner is determined by incoming HTTP headers.
    # @param [Proc] on_signature_failure A proc which will be called if signature verification fails.
    # @param [Proc] block A proc which will be called with file_name and file content.
    def initialize(server_info: nil, partner: nil, on_signature_failure: nil, &block)
      @block = block
      @server_info = server_info || Config.server_info
      @partner = partner
      @signature_failure_handler = on_signature_failure
    end

    def call(env)
      if env['HTTP_AS2_TO'] != @server_info.name
        return send_error(env, "Invalid destination name #{env['HTTP_AS2_TO']}")
      end

      partner = @partner || Config.partners[env['HTTP_AS2_FROM']]

      if !partner || env['HTTP_AS2_FROM'] != partner.name
        return send_error(env, "Invalid partner name #{env['HTTP_AS2_FROM']}")
      end

      request = Rack::Request.new(env)
      message = Message.new(request.body.read, @server_info.pkey, @server_info.certificate)

      unless message.valid_signature?(partner.certificate)
        if @signature_failure_handler
          @signature_failure_handler.call({
            env: env,
            smime_string: message.decrypted_message,
            verification_error: message.verification_error
          })
        else
          raise "Could not verify signature"
        end
      end

      if @block
        begin
          @block.call message.attachment.filename, message.attachment.body
        rescue Exception => e
          return send_error(env, e.message)
        end
      end

      send_mdn(env, message.mic, message.mic_algorithm)
    end

    def send_mdn(env, mic, mic_algorithm, failed = nil)
      # rules for MDN construction are covered in
      # https://datatracker.ietf.org/doc/html/rfc4130#section-7.4.2

      options = {
        'Reporting-UA' => @server_info.name,
        'Original-Recipient' => "rfc822; #{@server_info.name}",
        'Final-Recipient' => "rfc822; #{@server_info.name}",
        'Original-Message-ID' => env['HTTP_MESSAGE_ID']
      }
      if failed
        options['Disposition'] = 'automatic-action/MDN-sent-automatically; failed'
        options['Failure'] = failed
        text_body = "There was an error with the AS2 transmission.\r\n\r\n#{failed}"
      else
        options['Disposition'] = 'automatic-action/MDN-sent-automatically; processed'
        text_body = "The AS2 message has been received successfully"
      end
      options['Received-Content-MIC'] = "#{mic}, #{mic_algorithm}" if mic

      report = MimeGenerator::Part.new
      report['Content-Type'] = 'multipart/report; report-type=disposition-notification'

      text = MimeGenerator::Part.new
      text['Content-Type'] = 'text/plain'
      text['Content-Transfer-Encoding'] = '7bit'
      text.body = text_body
      report.add_part text

      notification = MimeGenerator::Part.new
      notification['Content-Type'] = 'message/disposition-notification'
      notification['Content-Transfer-Encoding'] = '7bit'
      notification.body = options.map{|n, v| "#{n}: #{v}"}.join("\r\n")
      report.add_part notification

      msg_out = StringIO.new

      report.write msg_out

      pkcs7 = OpenSSL::PKCS7.sign @server_info.certificate, @server_info.pkey, msg_out.string
      pkcs7.detached = true
      smime_signed = OpenSSL::PKCS7.write_smime pkcs7, msg_out.string

      content_type = smime_signed[/^Content-Type: (.+?)$/m, 1]
      # smime_signed.sub!(/\A.+?^(?=---)/m, '')

      # some partners don't understand.
      # i think newer openssl will use just pkcs7-signature.
      if @partner&.server_mdn_normalize_x_pkcs7_signature
        content_type.sub!('x-pkcs7-signature', 'pkcs7-signature')
        smime_signed.gsub!('x-pkcs7-signature', 'pkcs7-signature')
      end

      headers = {}
      headers['Content-Type'] = content_type
      # TODO: if MIME-Version header is actually needed, should extract it out of smime_signed.
      headers['MIME-Version'] = '1.0'
      headers['Message-ID'] = As2.generate_message_id(@server_info)
      headers['AS2-From'] = @server_info.name
      headers['AS2-To'] = env['HTTP_AS2_FROM']
      headers['AS2-Version'] = '1.0'
      headers['Connection'] = 'close'

      [200, headers, ["\r\n" + smime_signed]]
    end

    private

    def logger(env)
      @logger ||= Logger.new env['rack.errors']
    end

    def send_error(env, msg)
      logger(env).error msg
      send_mdn env, nil, 'sha1', msg
    end
  end
end
