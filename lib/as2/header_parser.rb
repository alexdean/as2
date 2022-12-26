module As2
  class HeaderParser
    Result = Struct.new(:name, :body, :raw, keyword_init: true) do
               def to_s
                 raw.to_s
               end

               def value
                 body&.value
               end

               def [](key)
                 body[key]
               end
             end

    Body = Struct.new(:value, :attributes, :raw, keyword_init: true) do
             def [](key)
               attributes[key]
             end

             def to_s
               raw.to_s
             end
           end


    # parse a full header line, including header name & body
    #
    # @example parse(Disposition-Notification-Options: signed-receipt-protocol=required, pkcs7-signature; signed-receipt-micalg=optional, sha1')
    def self.parse(raw)
      name, _, raw_body = raw.partition(':').map(&:strip)
      parsed_body = parse_body(raw_body)
      Result.new(raw: raw, name: name, body: parsed_body)
    end

    # parse a single header body (without the name)
    #
    # @example parse_body('signed-receipt-protocol=required, pkcs7-signature; signed-receipt-micalg=optional, sha1')
    def self.parse_body(raw_body)
      value = nil
      attributes = {}

      body_parts = raw_body.to_s.split(';').map(&:strip)

      body_parts.each do |part|
        if part.include?('=')
          part_key, _, part_value = part.partition('=')
          part_value = split_part(part_value)

          # force lower-case to make access more reliable
          part_key.downcase!

          # TODO: make this part represent itself as CSV when used in string context
          # most of the time there will only be 1 value. so make that the common access pattern
          # but make it possible to retrieve repeated values if necessary
          # attributes[part_key] ||= []
          # attributes[part_key] += part_value
          attributes[part_key] = part_value
        else
          # values << part
          value = split_part(part)
        end
      end

      Body.new(raw: raw_body, value: value, attributes: attributes)
    end

    private

    # convert CSV to array
    # remove quotes
    # single value returned as scalar not array
    def self.split_part(part)
      part_value = part.split(',').map do |value|
                         out = value.strip
                         # remove quotes
                         if out[0] == out[-1] && out[0] == "'" || out[0] == '"'
                           out = out[1..-2]
                         end
                         out
                       end

      # single values as scalars not array
      if part_value.size == 1
        part_value = part_value[0]
      end

      part_value
    end
  end
end

