module As2
  class Client
    class Result
      attr_reader :response, :mic_matched, :mid_matched, :body, :disposition, :verification_error, :exception

      def initialize(response, mic_matched, mid_matched, body, disposition, verification_error, exception)
        @response = response
        @mic_matched = mic_matched
        @mid_matched = mid_matched
        @body = body
        @disposition = disposition
        @verification_error = verification_error
        @exception = exception
      end

      def verified?
        self.verification_error.nil?
      end

      # legacy name. accessor for backwards-compatibility.
      def disp_code
        self.disposition
      end

      def success
        # TODO: we'll never have success if MDN is unsigned.
        self.verified? && self.mic_matched && self.mid_matched && self.disposition&.end_with?('processed')
      end
    end
  end
end
