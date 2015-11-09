require 'as2'
# require 'pry'

As2.configure do |conf|
  conf.name = 'MyClient'
  conf.url = 'http://localhost:8080/as2/HttpReceiver'
  conf.certificate = 'test/certificates/client.crt'
  conf.pkey = 'test/certificates/client.key'
  conf.domain = 'mydomain.com'
  conf.add_partner do |partner|
    partner.name = 'MyServer'
    partner.url = 'http://localhost:3000/as2'
    partner.certificate = 'test/certificates/server.crt'
  end
end

client = As2::Client.new 'MyServer'
result = client.send_file(ARGV.first)
p result
