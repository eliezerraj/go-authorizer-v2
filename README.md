# go-authorizer-v2
go-authorizer-v2


## Keys

```sh
# Create a private key .pem
openssl genrsa -out rsa_private_key.pem 3072

# Createa a public key .pem
openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem
```


grant_type = WHAT the client wants
client_assertion = WHO the client is

```
Claim       Purpose

iss         Token issuer
sub         User or workload identity
aud         MCP resource identifier
client_id   A2A client identity
roles       Roles used by Cedar
tenant      Multi-tenant isolation
act         Acting service (delegation)
iat         Issued at
exp         Expiration
jti         Unique token id
```