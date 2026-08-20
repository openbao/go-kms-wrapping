// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package tpm

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// parameter names used in configuration file
const (
	tpmPath               = "tpm_path"
	pcrValues             = "tpm_pcrvalues"
	userAuth              = "tpm_userauth"
	hierarchyuAuth        = "tpm_hierarchyauth"
	sessionEncryptionName = "tpm_session_encryption_name"
)

// struct used to encode the TPM sealing key and specifications about it
type Secret struct {
	PCRs   map[int32]string `json:"pcrs"`
	TPMKey string           `json:"tpmKey"`
}

const (
	TPMSeal   = iota
	TPMImport // not used now, maybe later if duplication is supported
)

func openTPM(path string) (io.ReadWriteCloser, error) {
	// first check if we're dealing with a device.  If not, try a socket
	_, err := os.Stat(path)
	if err == nil {
		return tpmutil.OpenTPM(path)
	}
	return net.Dial("tcp", path)
}

// parses the pcr [index:sha256_hex_value] string array for the PCRs to bind to.
// each pcr bank must comma separated and formatted as int(index):hex(sha256_pcr_value)
//
//	so to bind to pcrs 15, 23 for the following:
//
// $ tpm2_pcrread sha256:15,23
// sha256:
//
//	15: 0x0000000000000000000000000000000000000000000000000000000000000000
//	23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
//
// the expectedPCRMap would be
// 15:0000000000000000000000000000000000000000000000000000000000000000,23:F5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
//
// the return value is
//  1. map of pcr_bank and its value (map[uint][]byte)
//  2. list of the pcr_banks alone ([]uint)
//  3. the hash of the pcrs taken together in order ([]byte);  This value is used when defining a PolicyPCR
//     https://github.com/tpm2-software/tpm2-tools/blob/83f6f8ac5de5a989d447d8791525eb6b6472e6ac/lib/tpm2_openssl.c#L206
func getPCRMap(algo tpm2.TPMAlgID, expectedPCRMap string) (map[uint][]byte, []uint, []byte, error) {

	pcrMap := make(map[uint][]byte)

	if expectedPCRMap == "" {
		return pcrMap, nil, nil, nil
	}
	var hsh hash.Hash
	switch algo {
	case tpm2.TPMAlgSHA1:
		hsh = sha1.New()
	case tpm2.TPMAlgSHA256:
		hsh = sha256.New()
	default:
		return nil, nil, nil, fmt.Errorf("unknown Hash Algorithm for TPM PCRs %v", algo)
	}

	if algo == tpm2.TPMAlgSHA1 || algo == tpm2.TPMAlgSHA256 {
		for _, v := range strings.Split(expectedPCRMap, ",") {
			entry := strings.Split(v, ":")
			if len(entry) == 2 {
				uv, err := strconv.ParseUint(entry[0], 10, 32)
				if err != nil {
					return nil, nil, nil, fmt.Errorf(" PCR key:value is invalid in parsing %s", v)
				}
				hexEncodedPCR, err := hex.DecodeString(strings.ToLower(entry[1]))
				if err != nil {
					return nil, nil, nil, fmt.Errorf(" PCR key:value is invalid in encoding %s", v)
				}
				pcrMap[uint(uv)] = hexEncodedPCR
				hsh.Write(hexEncodedPCR)
			} else {
				return nil, nil, nil, fmt.Errorf(" PCR key:value is invalid %s", v)
			}
		}
	} else {
		return nil, nil, nil, fmt.Errorf("unknown Hash Algorithm for TPM PCRs %v", algo)
	}

	pcrs := make([]uint, 0, len(pcrMap))
	for k := range pcrMap {
		pcrs = append(pcrs, k)
	}

	return pcrMap, pcrs, hsh.Sum(nil), nil
}
