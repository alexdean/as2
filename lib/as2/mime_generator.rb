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
end
