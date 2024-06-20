#https://docs.github.com/en/rest/users/gpg-keys?apiVersion=2022-11-28#list-gpg-keys-for-the-authenticated-user

pk = "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n\r\nmDMEZiqgmRYJKwYBBAHaRw8BAQdAhx5sqXtm1+1OWAmXEOL7T4DbZgd6ZjZ/vvdy\r\nz4UwLTa0JWpvbmFzIHBhdWxpIDxqb25hc3BhdWxpMDg5QGdtYWlsLmNvbT6IkwQT\r\nFgoAOxYhBMJZzcZV2gVQjHyudDAn2VHrUBxUBQJmKqCZAhsDBQsJCAcCAiICBhUK\r\nCQgLAgQWAgMBAh4HAheAAAoJEDAn2VHrUBxUow8BAJGt0XMqudPxp2FYq8+fhevo\r\nMQfMyVWoDiUCz3dqewQ7AP9PbDk2LfDGXlat3Ce2WxWodYejfIJuYJcMkcBT5Q4b\r\nCA==\r\n=5JnY\r\n-----END PGP PUBLIC KEY BLOCK-----"

import gnupg

# Initialize the GPG interface
gpg = gnupg.GPG()

# Define the message you want to sign
message = "This is a message to sign."

# Sign the message using yourv private key
signed_message = gpg.sign(message, keyid='C259CDC655DA05508C7CAE743027D951EB501C54')

# Print the signed messageg
print(str(signed_message))

import_result = gpg.import_keys(pk)
key_id = import_result.results[0]['fingerprint']



# Verify the signature
verification = gpg.verify(str(signed_message))

# Check if the signature is valid
if verification.valid:
    print("Signature is valid.")
else:
    print("Signature is NOT valid.")

# Optionally, you can also print more details about the verification
print("Signature Details:")
print(verification)
