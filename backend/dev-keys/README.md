# Development JWT keys

Throwaway RSA-2048 pair used by the `dev` profile to sign and verify access tokens.

These keys are committed to a public repository. They are public by definition and protect
nothing. Never copy them into a deployment: production reads its own pair through
`SMALLRYE_JWT_SIGN_KEY_LOCATION` and `MP_JWT_VERIFY_PUBLICKEY_LOCATION`, and this directory sits
outside `src/main/resources` precisely so that it cannot be packaged into the jar or the image.

Regenerate with:

    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out privateKey.pem
    openssl rsa -pubout -in privateKey.pem -out publicKey.pem
