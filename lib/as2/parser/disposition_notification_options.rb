module As2
  module Parser
    # parse an AS2 HTTP Content-Disposition-Options header
    # Structure is described in https://datatracker.ietf.org/doc/html/rfc4130#section-7.3
    #
    # don't use this directly. use As2.choose_mic_algorithm instead.
    #
    # @api private
    class DispositionNotificationOptions
      Result = Struct.new(:value, :attributes, :raw, keyword_init: true) do
               def [](key)
                 normalized = As2::Parser::DispositionNotificationOptions.normalize_key(key)
                 attributes[normalized]
               end

               def to_s
                 raw.to_s
               end
             end

      def self.normalize_key(raw)
        raw.to_s.downcase
      end

      # parse a single header body (without the name)
      #
      # @example parse('signed-receipt-protocol=required, pkcs7-signature; signed-receipt-micalg=optional, sha1')
      # @return [As2::Parser::DispositionNotificationOptions::Result]
      def self.parse(raw_body)
        value = nil
        attributes = {}

        body_parts = raw_body.to_s.split(';').map(&:strip)

        body_parts.each do |part|
          if part.include?('=')
            part_key, _, part_value = part.partition('=')
            part_value = split_part(part_value)

            # force lower-case to make access more reliable
            part_key = normalize_key(part_key)

            attributes[part_key] = part_value
          else
            value = split_part(part)
          end
        end

        Result.new(raw: raw_body, value: value, attributes: attributes)
      end

      private

      # convert CSV to array
      # remove quotes
      # single value returned as scalar not array
      def self.split_part(part)
        part_value = part.split(',').map do |value|
                           out = value.strip
                           # remove quotes
                           if out[0] == out[-1] && (out[0] == "'" || out[0] == '"')
                             out = out[1..-2]
                           end
                           out
                         end

        part_value
      end
    end
  end
end
