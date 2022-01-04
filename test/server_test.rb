require 'test_helper'

describe As2::Server do
  it 'accepts server_info as a config param'
  it 'uses global server config if server_info is nil'

  describe '#call' do
    describe 'when partner is given to constructor' do
      it 'returns an error if As2-From value does not match configured partner name'
    end

    describe 'when partner is not given to constructor' do
      it 'returns an error if As2-From value is not found in global partner config'
    end
  end
end
