# warning: do not use the certificates produced by this tool in production.
# This is for testing purposes only
set -e

rm -rf generated
mkdir generated
cd generated

echo "GENERATED CERTIFICATES FOR TESTING ONLY." >> ./README.txt
echo "DO NOT USE THESE CERTIFICATES IN PRODUCTION" >> ./README.txt

# certificate authority
openssl genrsa -out root.key 4096
openssl req -new -x509 -days 1826 -extensions ca -key root.key -out root.crt -subj "/C=LS/ST=NA/L=Http Input/O=Logstash/CN=root" -config ../openssl.cnf

# server certificate from root
openssl genrsa -out server_from_root.key 4096
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in server_from_root.key -out server_from_root.pkcs8.key
openssl req -new -key server_from_root.key -out server_from_root.csr -subj "/C=LS/ST=NA/L=Http Input/O=Logstash/CN=server" -config ../openssl.cnf
openssl x509 -req -extensions server_cert -extfile ../openssl.cnf -days 1096 -in server_from_root.csr -CA root.crt -CAkey root.key -set_serial 03 -out server_from_root.crt

# client certificate from root
openssl genrsa -out client_from_root.key 4096
openssl req -new -key client_from_root.key -out client_from_root.csr -subj "/C=LS/ST=NA/L=Http Input/O=Logstash/CN=client" -config ../openssl.cnf
openssl x509 -req -extensions client_cert -extfile ../openssl.cnf -days 1096 -in client_from_root.csr -CA root.crt -CAkey root.key -set_serial 04 -out client_from_root.crt

# self-signed for testing
openssl req -newkey rsa:4096 -nodes -keyout client_self_signed.key -x509 -days 365 -out client_self_signed.crt -subj "/C=LS/ST=NA/L=Http Input/O=Logstash/CN=self"
#openssl genrsa -out client_self_signed.key 4096
#openssl req -new -x509 -days 1826 -extensions client_cert -key client_self_signed.key -out client_self_signed.crt -subj "/C=LS/ST=NA/L=Http Input/O=Logstash/CN=self" -config ../openssl.cnf

## client with invalid subject
openssl genrsa -out client_invalid_subject.key 4096
openssl req -new -key client_invalid_subject.key -out client_invalid_subject.csr -subj "/C=LS/ST=NA/L=Http Input/O=Logstash/CN=client_invalid_subject" -config ../openssl.cnf
openssl x509 -req -extensions client_cert_invalid_subject -extfile ../openssl.cnf -days 1096 -in client_invalid_subject.csr -CA root.crt -CAkey root.key -set_serial 04 -out client_invalid_subject.crt

# verify :allthethings
openssl verify -CAfile root.crt server_from_root.crt
openssl verify -CAfile root.crt client_from_root.crt
openssl verify -CAfile root.crt client_invalid_subject.crt

! openssl verify -CAfile root.crt client_self_signed.crt > /dev/null
openssl verify -CAfile client_self_signed.crt client_self_signed.crt

# create pkcs8 versions of all keys
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in client_from_root.key -out client_from_root.key.pkcs8
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in server_from_root.key -out server_from_root.key.pkcs8

# create pkcs12 keystores (pass:12345678)
openssl pkcs12 -export -in client_from_root.crt -inkey client_from_root.key -out client_from_root.p12 -name "client_from_root" -passout 'pass:12345678'
openssl pkcs12 -export -in client_self_signed.crt -inkey client_self_signed.key -out client_self_signed.p12 -name "client_from_root" -passout 'pass:12345678'
openssl pkcs12 -export -in client_invalid_subject.crt -inkey client_invalid_subject.key -out client_invalid_subject.p12 -name "client_invalid_subject" -passout 'pass:12345678'

# use java keytool to convert all pkcs12 keystores to jks-format keystores (pass:12345678)
keytool -importkeystore -srckeystore client_from_root.p12 -srcstoretype pkcs12 -srcstorepass 12345678 -destkeystore client_from_root.jks -deststorepass 12345678 -alias client_from_root

# cleanup csr, we don't need them
rm -rf *.csr
