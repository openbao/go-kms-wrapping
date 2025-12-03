// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package helpers

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/openbao/go-kms-wrapping/v2/kms"
)

//type approval struct {
//	TypeOfKey string  `json:"type"`
//	Name      *string `json:"name"`
//	Value     *string `json:"value"`
//}
//type group struct {
//	Name      string     `json:"name"`
//	Quorum    int        `json:"quorum"`
//	Approvals []approval `json:"approvals"`
//}
//type token struct {
//	Name     string  `json:"name"`
//	Timelock int     `json:"timelock"`
//	Timeout  int     `json:"timeout"`
//	Groups   []group `json:"groups"`
//}
//type rule struct {
//	Tokens []token `json:"tokens"`
//}
//type keyStatus struct {
//	Blocked bool `json:"blocked"`
//}
//
//// Policy structure for rules use, block, unblock, modify
//type Policy struct {
//	RuleUse     rule       `json:"ruleUse"`
//	RuleBlock   *rule      `json:"ruleBlock,omitempty"`
//	RuleUnBlock *rule      `json:"ruleUnblock,omitempty"`
//	RuleModify  *rule      `json:"ruleModify,omitempty"`
//	KeyStatus   *keyStatus `json:"keyStatus,omitempty"`
//}

// Function converts string into char array
func StringToCharArray(text string) []string {
	var array []string = make([]string, 0)
	for i := 0; i < len(text); i++ {
		array = append(array, string(text[i]))
	}
	return array
}

// Function that helps fill a policy structure
func PreparePolicy(policyString string, simplified bool) (*Policy, error) {
	return PrepareFullPolicy(policyString, simplified, true)
}

// Function that checking if key exists in map
func ContainsKey(m, k interface{}) bool {
	v := reflect.ValueOf(m).MapIndex(reflect.ValueOf(k))
	return v != reflect.Value{}
}
func ParsePublicKeyString(publicKey string) (crypto.PublicKey, error) {
	var pkForImportingKey crypto.PublicKey
	spkiBlock, _ := pem.Decode(WrapPublicKeyWithHeaders(publicKey))
	if spkiBlock == nil {
		return nil, fmt.Errorf("Cannot parse public key")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(spkiBlock.Bytes)
	if err != nil {
		return nil, err
	}
	pkForImportingKey = pubInterface
	return pkForImportingKey, nil
}
func WrapPublicKeyWithHeaders(publicKey string) []byte {
	return []byte("-----BEGIN PUBLIC KEY-----\n" + publicKey + "\n-----END PUBLIC KEY-----")
}

// This function preparing Policy structure for generating asynchronous keys
func PrepareFullPolicy(policyString string, simplified bool, addKeyStatus bool) (*Policy, error) {
	var PolicyObj Policy
	if simplified == true {

		var simplePolicy map[string]string
		err := json.Unmarshal([]byte(policyString), &simplePolicy)
		if err == nil {
			token := PreparePolicyTokens(simplePolicy)
			PolicyObj.RuleUse.Tokens = append(PolicyObj.RuleUse.Tokens, token)
			PolicyObj.RuleBlock = new(Rule)
			PolicyObj.RuleBlock.Tokens = append(PolicyObj.RuleBlock.Tokens, token)
			PolicyObj.RuleUnBlock = new(Rule)
			PolicyObj.RuleUnBlock.Tokens = append(PolicyObj.RuleUnBlock.Tokens, token)
			PolicyObj.RuleModify = new(Rule)
			PolicyObj.RuleModify.Tokens = append(PolicyObj.RuleModify.Tokens, token)
			if addKeyStatus == true {
				PolicyObj.KeyStatus = new(KeyStatus)
				PolicyObj.KeyStatus.Blocked = false
			}
		} else {
			var simplePolicy map[string]map[string]string
			err := json.Unmarshal([]byte(policyString), &simplePolicy)
			if err != nil {
				return nil, err
			}
			if simplePolicy["use"] != nil {
				token := PreparePolicyTokens(simplePolicy["use"])
				PolicyObj.RuleUse.Tokens = append(PolicyObj.RuleUse.Tokens, token)
			} else {
				token := PreparePolicyTokens(make(map[string]string))
				PolicyObj.RuleUse.Tokens = append(PolicyObj.RuleUse.Tokens, token)
			}
			if simplePolicy["block"] != nil {
				token := PreparePolicyTokens(simplePolicy["block"])
				PolicyObj.RuleBlock.Tokens = append(PolicyObj.RuleBlock.Tokens, token)
			} else {
				token := PreparePolicyTokens(make(map[string]string))
				PolicyObj.RuleBlock.Tokens = append(PolicyObj.RuleBlock.Tokens, token)
			}
			if simplePolicy["unblock"] != nil {
				token := PreparePolicyTokens(simplePolicy["unblock"])
				PolicyObj.RuleUnBlock.Tokens = append(PolicyObj.RuleUnBlock.Tokens, token)
			} else {
				token := PreparePolicyTokens(make(map[string]string))
				PolicyObj.RuleUnBlock.Tokens = append(PolicyObj.RuleUnBlock.Tokens, token)
			}
			if simplePolicy["modify"] != nil {
				token := PreparePolicyTokens(simplePolicy["modify"])
				PolicyObj.RuleModify.Tokens = append(PolicyObj.RuleModify.Tokens, token)
			} else {
				token := PreparePolicyTokens(make(map[string]string))
				PolicyObj.RuleModify.Tokens = append(PolicyObj.RuleModify.Tokens, token)
			}

			if addKeyStatus == true {
				PolicyObj.KeyStatus = new(KeyStatus)
				PolicyObj.KeyStatus.Blocked = false
			}

		}
	} else {
		err := json.Unmarshal([]byte(policyString), &PolicyObj)
		if err != nil {
			return nil, err
		}
		if addKeyStatus == false {
			PolicyObj.KeyStatus = nil
		}

	}
	return &PolicyObj, nil
}

// This function groups from simplePolicy parameter sended with keys

func PreparePolicyTokens(policy map[string]string) Token {
	var group Group
	group.Name = "main"
	group.Quorum = len(policy)
	for name, element := range policy {
		var approval Approval
		clonedName := name
		clonedElement := element
		_, err := ReadCertificate(element)
		if err == nil {
			approval.TypeOfKey = "certificate"
			approval.Value = &clonedElement
		} else {
			_, err := ParsePublicKeyString(element)
			if err == nil {
				approval.TypeOfKey = "public_key"
				approval.Name = &clonedName
				approval.Value = &clonedElement
			} else {
				approval.TypeOfKey = "onboarded_approver_certificate"
				approval.Name = &clonedElement
			}
		}

		group.Approvals = append(group.Approvals, approval)
	}

	var token Token
	token.Name = "main"
	token.Timeout = 0
	token.Timelock = 0
	if len(policy) == 0 {
		token.Groups = nil
	} else {
		token.Groups = append(token.Groups, group)

	}

	return token

}

// Function converts attributes map into a json
func PrepareAttributes(attributes map[string]bool) string {
	json, _ := json.Marshal(attributes)
	return string(json)

}

// Function checking if string exits in string array
func Contains(s []string, str string) bool {
	for _, v := range s {
		if strings.ToLower(v) == strings.ToLower(str) {
			return true
		}
	}

	return false
}

// Function returns new version of key
func GetNewVersion(version string) string {
	versionString := strings.Replace(version, "v", "", 1)
	versionInt, _ := strconv.Atoi(versionString)
	newVersion := "v" + strconv.Itoa(versionInt+1)
	return newVersion
}
func GetVersionNumber(version string) int {
	versionString := strings.Replace(version, "v", "", 1)
	versionInt, _ := strconv.Atoi(versionString)
	return versionInt
}
func GetVersionString(version string) string {
	return strings.Replace(version, "v", "", 1)
}

// Function preparing MetaData, which We are send with all asynchronous requests
func PrepareMetaData(requestType string, additionalMetaData map[string]string, customMetaData map[string]string) (string, string, error) {
	now := time.Now().UTC()
	var metaData map[string]string = make(map[string]string)
	metaData["time"] = fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
	metaData["app"] = "Hashicorp Vault - Securosys HSM Secrets Engine"
	metaData["type"] = requestType
	for key, value := range additionalMetaData {
		metaData[key] = value
	}
	for key, value := range customMetaData {
		metaData[key] = value
	}
	metaJsonStr, errMarshal := json.Marshal(metaData)
	if errMarshal != nil {
		return "", "", errMarshal
	}
	h := sha256.New()
	h.Write(metaJsonStr)
	bs := h.Sum(nil)
	return b64.StdEncoding.EncodeToString(metaJsonStr),
		b64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(bs))), nil
}

const (
	letterBytes     = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	specialBytes    = "!@#$%^&*()_+-=[]{}\\|;':\",.<>/?`~"
	numBytes        = "0123456789"
	hexDecimalBytes = "0123456789ABCDEF"
)

func MinifyJson(requestData string) string {
	dst := &bytes.Buffer{}
	if err := json.Compact(dst, []byte(requestData)); err != nil {
		panic(err)
	}
	return dst.String()

}

func GeneratePassword(length int, useLetters bool, useSpecial bool, useNum bool, useHexadecimal bool) string {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, length)
	arrayForRandom := make([]byte, 0)
	if useLetters {
		arrayForRandom = append(arrayForRandom, letterBytes...)
	}
	if useSpecial {
		arrayForRandom = append(arrayForRandom, specialBytes...)
	}
	if useNum {
		arrayForRandom = append(arrayForRandom, numBytes...)
	}
	if useHexadecimal {
		arrayForRandom = append(arrayForRandom, hexDecimalBytes...)

	}

	for i := range b {
		b[i] = arrayForRandom[rand.Intn(len(arrayForRandom))]
	}
	return string(b)
}
func ReadCertificate(possibleCertificate string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte("-----BEGIN CERTIFICATE-----\n" + possibleCertificate + "\n-----END CERTIFICATE-----\n"))
	if block == nil {
		return nil, fmt.Errorf("Cannot read certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
func BytesToPublicKey(pub []byte) any {
	block, _ := pem.Decode(pub)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil
		}
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil
	}
	return ifc
}
func MapStringCurverToCurve(curveString string) kms.Curve {
	switch curveString {
	case "1.2.840.10045.3.1.7":
		return kms.Curve_P256
	case "1.3.132.0.34":
		return kms.Curve_P384
	case "1.3.132.0.35":
		return kms.Curve_P521

	}
	return kms.Curve_None
}

func MapCurveToStringCurve(curve kms.Curve) string {
	switch curve {
	case kms.Curve_P256:
		return "1.2.840.10045.3.1.7"
	case kms.Curve_P384:
		return "1.3.132.0.34"
	case kms.Curve_P521:
		return "1.3.132.0.35"

	}
	return ""
}
func MapSignAlgorithm(alg kms.SignAlgorithm, digest bool) (string, error) {
	if digest {
		switch alg {
		case kms.SignAlgo_RSA_PKCS1_PSS_SHA_256:
			return "NONE_WITH_RSA", nil
		case kms.SignAlgo_RSA_PKCS1_PSS_SHA_384:
			return "NONE_WITH_RSA", nil
		case kms.SignAlgo_RSA_PKCS1_PSS_SHA_512:
			return "NONE_WITH_RSA", nil
		case kms.SignAlgo_EC_P256:
			return "NONE_WITH_ECDSA", nil
		case kms.SignAlgo_EC_P384:
			return "NONE_WITH_ECDSA", nil
		case kms.SignAlgo_EC_P521:
			return "NONE_WITH_ECDSA", nil
		case kms.SignAlgo_ED:
			return "EDDSA", nil
		}

	} else {
		switch alg {
		case kms.SignAlgo_RSA_PKCS1_PSS_SHA_256:
			return "SHA256_WITH_RSA", nil
		case kms.SignAlgo_RSA_PKCS1_PSS_SHA_384:
			return "SHA384_WITH_RSA", nil
		case kms.SignAlgo_RSA_PKCS1_PSS_SHA_512:
			return "SHA512_WITH_RSA", nil
		case kms.SignAlgo_EC_P256:
			return "SHA256_WITH_ECDSA", nil
		case kms.SignAlgo_EC_P384:
			return "SHA384_WITH_ECDSA", nil
		case kms.SignAlgo_EC_P521:
			return "SHA512_WITH_ECDSA", nil
		case kms.SignAlgo_ED:
			return "EDDSA", nil
		}
		//case kms.Sign_SHA224_RSA_PKCS1_PSS:
		//	return "SHA224_WITH_RSA_PSS", nil
		//case kms.Sign_SHA256_RSA_PKCS1_PSS:
		//	return "SHA256_WITH_RSA_PSS", nil
		//case kms.Sign_SHA384_RSA_PKCS1_PSS:
		//	return "SHA384_WITH_RSA_PSS", nil
		//case kms.Sign_SHA512_RSA_PKCS1_PSS:
		//	return "SHA512_WITH_RSA_PSS", nil
		//case kms.Sign_SHA224_RSA:
		//	return "SHA224_WITH_RSA", nil
		//case kms.Sign_SHA256_RSA:
		//	return "SHA256_WITH_RSA", nil
		//case kms.Sign_SHA384_RSA:
		//	return "SHA384_WITH_RSA", nil
		//case kms.Sign_SHA512_RSA:
		//	return "SHA512_WITH_RSA", nil
		//
		//case kms.Sign_SHA1_ECDSA:
		//	return "SHA1_WITH_ECDSA", nil
		//case kms.Sign_SHA224_ECDSA:
		//	return "SHA224_WITH_ECDSA", nil
		//case kms.Sign_SHA256_ECDSA:
		//	return "SHA256_WITH_ECDSA", nil
		//case kms.Sign_SHA384_ECDSA:
		//	return "SHA384_WITH_ECDSA", nil
		//case kms.Sign_SHA512_ECDSA:
		//	return "SHA512_WITH_ECDSA", nil
		//case kms.Sign_SHA3224_ECDSA:
		//	return "SHA3224_WITH_ECDSA", nil
		//case kms.Sign_SHA3256_ECDSA:
		//	return "SHA3256_WITH_ECDSA", nil
		//case kms.Sign_SHA3384_ECDSA:
		//	return "SHA3384_WITH_ECDSA", nil
		//case kms.Sign_SHA3512_ECDSA:
		//	return "SHA3512_WITH_ECDSA", nil

	}
	return "", errors.New("unknown cipher algorithm")

}
func MapCipherAlgorithm(alg kms.CipherAlgorithmMode) (string, error) {
	switch alg {
	case kms.CipherMode_AES_GCM:
		return "AES_GCM", nil
	//case kms.Cipher_AES_CBC:
	//	return "AES_CBC_NO_PADDING", nil
	//case kms.Cipher_AES_ECB:
	//	return "AES_ECB", nil
	//case kms.Cipher_AES_CTR:
	//	return "AES_CTR", nil
	//case kms.Cipher_RSA_MODE:
	//	return "RSA", nil
	//case kms.Cipher_RSA_PADDING_OAEP:
	//	return "RSA_PADDING_OAEP", nil
	//case kms.Cipher_RSA_PADDING_OAEP_SHA1:
	//	return "RSA_PADDING_OAEP_WITH_SHA1", nil
	//case kms.Cipher_RSA_PADDING_OAEP_SHA224:
	//	return "RSA_PADDING_OAEP_WITH_SHA224", nil
	case kms.CipherMode_RSA_OAEP_SHA256:
		return "RSA_PADDING_OAEP_WITH_SHA256", nil
	case kms.CipherMode_RSA_OAEP_SHA384:
		return "RSA_PADDING_OAEP_WITH_SHA384", nil
	case kms.CipherMode_RSA_OAEP_SHA512:
		return "RSA_PADDING_OAEP_WITH_SHA512", nil

	}
	return "", errors.New("unknown cipher algorithm")

}
