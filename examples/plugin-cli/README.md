# plugin-cli

An example CLI that demonstrates how to incorporate a pluginized Wrapper into
an application via [go-plugin](https://github.com/hashicorp/go-plugin). In this
example, we'll compile and use the Transit engine wrapper as a plugin, but you
could use any.

Why would you want to use a wrapper via
[go-plugin](https://github.com/hashicorp/go-plugin) vs. just including the
wrapper dependency directly into your application? Well, let's say you wanted
to allow users to configure a variety of KMS wrappers within your application,
but you didn't want to include every possible KMS wrapper dependency into your
application. Using go-plugin wrappers allows you to build a set of KMS wrappers
as plugins and load them dynamically. Then your app has no direct dependencies
on the KMSes you wish to support.

Running this example will:

- Initialize an OpenBao Transit engine plugin.
- Encrypt a plaintext secret using the Transit wrapper.
- Decrypt the resulting ciphertext using the Transit wrapper.
- Validate that the decrypted plaintext matches the original plaintext.

Expected output from a successful execution:

```
$ go run . --plaintext "test secret"
initializing the transit plugin wrapper...
encrypting the plaintext...
decrypting the ciphertext...
successfully encrypted/decrypted "test secret" using the transit plugin!
```

Before running the example, you must first start OpenBao via `docker compose` or
equivalent:

```
$ docker compose up -d
```

Once done playing around, don't forget to clean up:

```
$ docker compose down
```
