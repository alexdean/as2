require 'rack'
require 'logger'
require 'stringio'
require 'as2/mime_generator'
require 'as2/base64_helper'
require 'as2/message'

module As2
  class Server
    HEADER_MAP = {
      'To' => 'HTTP_AS2_TO',
      'From' => 'HTTP_AS2_FROM',
      'Subject' => 'HTTP_SUBJECT',
      'MIME-Version' => 'HTTP_MIME_VERSION',
      'Content-Disposition' => 'HTTP_CONTENT_DISPOSITION',
      'Content-Type' => 'CONTENT_TYPE',
    }

    attr_accessor :logger

    def initialize(options = {}, &block)
      @block = block
      @info = Config.server_info
      @options = options
    end

    def call(env)
      if env['HTTP_AS2_TO'] != @info.name
        return send_error(env, "Invalid destination name #{env['HTTP_AS2_TO']}")
      end

      partner = Config.partners[env['HTTP_AS2_FROM']]
      unless partner
        return send_error(env, "Invalid partner name #{env['HTTP_AS2_FROM']}")
      end

      smime_string = build_smime_text(env)
      message = Message.new(smime_string, @info.pkey, @info.certificate)
      unless message.valid_signature?(partner.certificate)
        if @options[:on_signature_failure]
          @options[:on_signature_failure].call({env: env, smime_string: smime_string})
        else
          raise "Could not verify signature"
        end
      end

      mic = OpenSSL::Digest::SHA1.base64digest(message.decrypted_message)

      if @block
        begin
          @block.call message.attachment.filename, message.attachment.body
        rescue Exception => e
          return send_error(env, e.message)
        end
      end

      send_mdn(env, mic)
    end

    private
    def build_smime_text(env)
      request = Rack::Request.new(env)
      smime_data = StringIO.new

      HEADER_MAP.each do |name, value|
        smime_data.puts "#{name}: #{env[value]}"
      end

      smime_data.puts 'Content-Transfer-Encoding: base64'
      smime_data.puts
      smime_data.puts Base64Helper.ensure_base64(request.body.read)

      return smime_data.string
    end

    def logger(env)
      @logger ||= Logger.new env['rack.errors']
    end

    def send_error(env, msg)
      logger(env).error msg
      send_mdn env, nil, msg
    end

    def send_mdn(env, mic, failed = nil)
      report = MimeGenerator::Part.new
      report['Content-Type'] = 'multipart/report; report-type=disposition-notification'

      text = MimeGenerator::Part.new
      text['Content-Type'] = 'text/plain'
      text['Content-Transfer-Encoding'] = '7bit'
      text.body = "The AS2 message has been received successfully"

      report.add_part text

      notification = MimeGenerator::Part.new
      notification['Content-Type'] = 'message/disposition-notification'
      notification['Content-Transfer-Encoding'] = '7bit'

      options = {
        'Reporting-UA' => @info.name,
        'Original-Recipient' => "rfc822; #{@info.name}",
        'Final-Recipient' => "rfc822; #{@info.name}",
        'Original-Message-ID' => env['HTTP_MESSAGE_ID']
      }
      if failed
        options['Disposition'] = 'automatic-action/MDN-sent-automatically; failed'
        options['Failure'] = failed
      else
        options['Disposition'] = 'automatic-action/MDN-sent-automatically; processed'
      end
      options['Received-Content-MIC'] = "#{mic}, sha1" if mic
      notification.body = options.map{|n, v| "#{n}: #{v}"}.join("\r\n")
      report.add_part notification

      msg_out = StringIO.new

      report.write msg_out

      pkcs7 = OpenSSL::PKCS7.sign @info.certificate, @info.pkey, msg_out.string
      pkcs7.detached = true
      smime_signed = OpenSSL::PKCS7.write_smime pkcs7, msg_out.string

      content_type = smime_signed[/^Content-Type: (.+?)$/m, 1]
      smime_signed.sub!(/\A.+?^(?=---)/m, '')

      headers = {}
      headers['Content-Type'] = content_type
      headers['MIME-Version'] = '1.0'
      headers['Message-ID'] = "<#{@info.name}-#{Time.now.strftime('%Y%m%d%H%M%S')}@#{@info.domain}>"
      headers['AS2-From'] = @info.name
      headers['AS2-To'] = env['HTTP_AS2_FROM']
      headers['AS2-Version'] = '1.2'
      headers['Connection'] = 'close'

      [200, headers, ["\r\n" + smime_signed]]
    end
  end
end
