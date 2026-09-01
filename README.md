# go-authorizer-v2
go-authorizer-v2


## Keys

```sh
# Create a private key .pem
openssl genrsa -out rsa_private_key.pem 3072

# Createa a public key .pem
openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem

```