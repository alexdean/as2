# Test Setup

Generating certificates and fixture data is a little involved.


## regenerate test client/server certificates

WARNING: Messages in `test/fixures` will need to be updated if these certificates are changed.

```
openssl req -x509 -newkey rsa:2048 -keyout test/certificates/client.key -out test/certificates/client.crt -days 1825 -passin pass: -nodes
Generating a 2048 bit RSA private key
.............................+++
..+++
writing new private key to 'test/certificates/client.key'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) []:
State or Province Name (full name) []:
Locality Name (eg, city) []:
Organization Name (eg, company) []:Ruby AS2 Test Client
Organizational Unit Name (eg, section) []:
Common Name (eg, fully qualified host name) []:client.test-ruby-as2.com
Email Address []:

openssl req -x509 -newkey rsa:2048 -keyout test/certificates/server.key -out test/certificates/server.crt -days 1825 -passin pass: -nodes
Generating a 2048 bit RSA private key
...................................................................................+++
.................+++
writing new private key to 'test/certificates/server.key'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) []:
State or Province Name (full name) []:
Locality Name (eg, city) []:
Organization Name (eg, company) []:Ruby AS2 Test Server
Organizational Unit Name (eg, section) []:
Common Name (eg, fully qualified host name) []:server.test-ruby-as2.com
Email Address []:
```

## generating sample messages

  1. start mendelson AS2 server
  2. create a new local station using `test/fixtures/client.key` for inbound data decryption
     and outbound signature generation.
  3. create a new remote station using `test/fixtures/server.crt` for outbound data encryption
     and inbound signature verification.
  4. start a test server (using this ruby as2). write any inbound messages to a local file in binary mode.
  5. send a message from mendelson server to ruby server
  6. verify that transmission was successful. (Mendelson should report signatures are OK & MIC matches.)

ruby server should

```ruby
filename = "tmp/as2-receive-#{Time.now.to_i}"
File.open(filename, 'wb') { |f| f.write(request.body.read) }
```

The resulting files can be moved to `test/fixtures` and used in tests.
