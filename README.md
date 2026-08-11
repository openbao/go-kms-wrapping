# go-kms-wrapping

This repository holds glue for OpenBao to integrate with external KMS providers,
including modules consumed directly by [the main repository] and ones consumed
by [the plugin repository]. OpenBao integrates with external KMS providers to
implement the [Auto-Unseal] and [External Keys] features.

> [!NOTE]
> This repository is maintained with OpenBao's requirements in mind only. We do
> not aim to provide a generic library of KMS packages that other projects can
> incorporate. Use at your own risk!

## Code organization

Code is organized into several Go modules and packages:

- `github.com/openbao/go-kms-wrapping/v2`
    - `/` - Defines the [`Wrapper`] interface which is the backbone of OpenBao's
      [Auto-Unseal]. This interface encapsulates an opaque keyring that can
      encrypt and decrypt arbitrary blobs. To implement a KMS plugin that
      supports [Auto-Unseal], implement this interface.
    - `/aead` - An implementation of [`Wrapper`] that uses no external KMS
      and performs in-memory crypto. Shamir seals in OpenBao delegate to this
      wrapper once key shares have been combined.
    - `/kms` - Defines the [`KMS` and `Key`] interfaces which are the backbone
      of OpenBao's [External Keys]. These interfaces are newer than (but do not
      supersede) the [`Wrapper`] interface and define semantics not only around
      encryption and decryption, but signing and verification, too. To implement
      a KMS plugin that supports [External Keys], implement these interfaces.

- `github.com/openbao/go-kms-wrapping/plugin/v2` - A plugin server/client
  SDK that is used to build standalone KMS plugins for OpenBao, supporting
  both [`Wrapper`] and [`KMS` and `Key`]. Note that `main.go` entrypoints for
  official KMS plugins are not present in this repository, but in [the plugin
  repository].

- `github.com/openbao/go-kms-wrapping/wrappers/*/v2` - Various
  implementations of the [`Wrapper`] interface (such as ones based
  on AWS, Azure, ...), each in their own Go module. [See the full
  list](https://github.com/openbao/go-kms-wrapping/tree/main/wrappers).

- `github.com/openbao/go-kms-wrapping/kms/*/v2` - Various implementations of
  the [`KMS` and `Key`] interfaces, each in their own Go module. [See the full
  list](https://github.com/openbao/go-kms-wrapping/tree/main/kms).

  When implementing both [`Wrapper`] and [`KMS` and `Key`] on top of a shared
  set of internal code, prefer placing all implementations within a single
  module under `kms/` instead of creating both `wrappers/*` and `kms/*`. See the
  [`kms/pkcs11`](https://github.com/openbao/go-kms-wrapping/tree/main/kms/pkcs11)
  module as an example of this pattern.

## Contributing

Contributions to this repository follow the same policies on
licensing, DCO and LLM usage as defined in [the main repository]'s
[`CONTRIBUTING.md`](https://github.com/openbao/openbao/blob/main/CONTRIBUTING.md).

Given OpenBao's KMS plugins can be built and distributed as standalone
binaries via the plugin SDK available in this repository, note that it is
**not necessary** to upstream your provider-specific implementation into this
repository such that you can use it with a recent release of OpenBao.

We do however welcome upstream contributions around KMS providers that may be
of interest to the broader OpenBao community, especially if globally relevant
(e.g., AWS), of great relevance to a particular region (e.g., Naver in South
Korea) or standards-based (e.g., PKCS#11, KMIP).

To get started with new plugin implementations (upstreamed or not), it is
recommended to review the following package documentation:

- https://pkg.go.dev/github.com/openbao/go-kms-wrapping/v2
- https://pkg.go.dev/github.com/openbao/go-kms-wrapping/v2/kms
- https://pkg.go.dev/github.com/openbao/go-kms-wrapping/plugin/v2

Additionally, interface implementations available in this repository may serve
as reference implementations to base your plugin on.

[the main repository]: https://github.com/openbao/openbao
[the plugin repository]: https://github.com/openbao/openbao-plugins
[Auto-Unseal]: https://openbao.org/docs/concepts/seal/#auto-unseal
[External Keys]: https://openbao.org/community/rfcs/external-keys
[`Wrapper`]: https://github.com/openbao/go-kms-wrapping/blob/main/wrapper.go
[`KMS` and `Key`]: https://github.com/openbao/go-kms-wrapping/blob/main/kms/kms.go
