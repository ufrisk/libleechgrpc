These certificates are only for use in testing mTLS connections with the leechgrpc_test_server & leechgrpc_test_client projects.

Do not under any circumstances use these certificates / keys in any production environment!

Password to the .pfx files: test

Generated with commands:
openssl req -x509 -newkey rsa:2048 -keyout client-tls.key -out client-tls.crt -days 365 -nodes -subj "/CN=localhost"
openssl pkcs12 -export -out client-tls.p12 -inkey client-tls.key -in client-tls.crt -password pass:test
