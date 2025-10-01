// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kms

// Random number generation is not to be used in the first pass.
/*
// RandomGenerator interface represents a random number generator (true-random or pseudo-random)
type RandomGenerator interface {

	// Close terminates the random generator
	Close(ctx context.Context) error

	// Login logs in to the underlying random provider
	Login(ctx context.Context, credentials *Credentials) error

	// IsTrueRandomGenerator returns true if the underlying provider is a TRG
	IsTrueRandomGenerator() bool

	// SeedRandom adds seed material to the random generator
	SeedRandom(ctx context.Context, seed []byte) error

	// GenerateRandom generates random or pseudo-random data
	GenerateRandom(ctx context.Context, length uint32) ([]byte, error)
}

// RandomGeneratorFactory creates RandomGenerator instances
type RandomGeneratorFactory interface {
	// NewRandomGenerator creates a new RandomGenerator instance
	NewRandomGenerator(ctx context.Context, provider *CryptoProviderParameters) (RandomGenerator, error)
}*/
