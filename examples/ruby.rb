require 'openssl'
require 'base64'

class Vk
  def self.auth?(request_headers_authorization, secret_key)
    query_params = request_headers_authorization.split('Bearer ')[1].split('&').inject({}) do |res, ampersand|
      equally = ampersand.split('=')
      res.merge!(equally[0] => equally[1])
    end

    query_string = query_params.inject('') do |res, param|
      break res if param[0] == 'sign'
      res += "#{param[0]}=#{param[1]}&"
    end[0..-2]

    OpenSSL::HMAC.base64digest(
      OpenSSL::Digest.new('sha256'),
      secret_key,
      query_string
    ).gsub('+', '-').gsub('/', '_').gsub('=', '') == query_params['sign']
  end
end