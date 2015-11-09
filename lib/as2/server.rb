require 'rack'
require 'logger'
require 'stringio'
require 'base64'

module As2
  class MimeGenerator
    class Part
      def initialize
        @parts = []
        @body = ""
        @headers = {}
      end

      def [](name)
        @headers[name]
      end

      def []=(name, value)
        @headers[name] = value
      end

      def body
        @body
      end

      def body=(body)
        unless @parts.empty?
          raise "Cannot add plain budy to multipart"
        end
        @body = body
      end

      def add_part(part)
        gen_id unless @id
        @parts << part
        @body = nil
      end

      def multipart?
        ! @parts.empty?
      end

      def write(io)
        @headers.each do |name, value|
          if multipart? && name =~ /content-type/i
            io.print "#{name}: #{value}; \r\n"
            io.print "\tboundary=\"----=_Part_#{@id}\"\r\n"
          else
            io.print "#{name}: #{value}\r\n"
          end
        end
        io.print "\r\n"
        if @parts.empty?
          io.print @body, "\r\n"
        else
          @parts.each do|p|
            io.print "------=_Part_#{@id}\r\n"
            p.write(io)
          end
          io.print "------=_Part_#{@id}--\r\n"
        end
        io.print "\r\n"
      end

      private

      @@counter = 0
      def gen_id
        @@counter += 1
        @id = "#{@@counter}_#{Time.now.strftime('%Y%m%d%H%M%S%L')}"
      end
    end
  end

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

    def initialize(&block)
      @block = block
      @info = Config.server_info
    end

    def call(env)
      if env['HTTP_AS2_TO'] != @info.name
        return send_error(env, "Invalid destination name #{env['HTTP_AS2_TO']}")
      end

      log = {}

      partner = Config.partners[env['HTTP_AS2_FROM']]
      unless partner
        return send_error(env, "Invalid partner name #{env['HTTP_AS2_FROM']}")
      end

      smime_string = build_smime_text(env, log)

      message = decrypt_smime(smime_string)
      verified_message = verify_signature(message, partner)

      mic = OpenSSL::Digest::SHA1.base64digest(verified_message.data)
      mail = Mail.new(verified_message.data)

      part = if mail.has_attachments?
               mail.attachments.find{|a| a.content_type == "application/edi-consent"}
             else
               mail
             end
      if @block
        begin
          @block.call part.filename, part.body
        rescue
          return send_error(env, $!.message)
        end
      end
      send_mdn(env, mic)
    end

    private
    def build_smime_text(env, log)
      request = Rack::Request.new(env)
      smime_data = StringIO.new

      HEADER_MAP.each do |name, value|
        smime_data.puts "#{name}: #{env[value]}"
      end

      body = request.body.read
      log[:body] = body

      smime_data.puts 'Content-Transfer-Encoding: base64'
      smime_data.puts
      smime_data.puts ensure_base64(body)

      log[:smime_data_string] = smime_data.string
      return smime_data.string
    end

    def read_smime(smime)
      OpenSSL::PKCS7.read_smime(smime)
    end

    def decrypt_smime(smime)
      message = read_smime(smime)
      message.decrypt @info.pkey, @info.certificate
    end

    def verify_signature(message, partner)
      smime = ensure_body_base64(message)
      message = read_smime(smime)
      message.verify [partner.certificate], Config.store
    end

    # Will base64 encoded string, unless it already is base64 encoded
    def ensure_base64(string)
      begin
        # If string is not base64 encoded, this will raise an ArgumentError
        Base64.strict_decode64(string.gsub("\n",""))
        return string
      rescue ArgumentError
        # The string is not yet base64 encoded
        return Base64.encode64(string)
      end
    end

    def ensure_body_base64(multipart)
      boundary = multipart.scan(/boundary="([^"]*)"/)[0][0]
      boundary_split = Regexp.escape("--#{boundary}")
      parts = multipart.split(/^#{boundary_split}-*\s*$/)
      signature = parts[2]
      transfer_encoding = signature.scan(/Content-Transfer-Encoding: (.*)/)[0][0].strip
      if transfer_encoding == 'binary'
        header, body = signature.split(/^\s*$/,2).map(&:lstrip)
        body_base64 = Base64.encode64(body)
        new_header = header.sub('Content-Transfer-Encoding: binary', 'Content-Transfer-Encoding: base64')
        parts[2] = new_header + "\r\n" + body_base64
        new_multipart = parts.join("--#{boundary}\r\n") + "--#{boundary}--\r\n"
        return new_multipart
      else
        return multipart
      end
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
