package simple_auth_sign_go

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

func sha256hex(s string) string {
	b := sha256.Sum256([]byte(s))
	return hex.EncodeToString(b[:])
}

func hmacsha256(s, key string) string {
	hashed := hmac.New(sha256.New, []byte(key))
	hashed.Write([]byte(s))
	return string(hashed.Sum(nil))
}

func Sign(secretId, secretKey, host string, timestamp, expireTimestamp int64) string {
	service := "clbia"
	method := "POST"
	contentType := "application/json"
	canonicalUri := "/"
	canonicalQuerystring := ""
	canonicalHeaders := fmt.Sprintf("content-type:%s\nhost:%s\n", contentType, host)
	signedHeaders := "content-type;host"
	emptyBody := ""
	payloadHash := sha256hex(emptyBody)
	algorithm := "TC3-HMAC-SHA256"
	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		method, canonicalUri, canonicalQuerystring, canonicalHeaders, signedHeaders, payloadHash)
	digest := sha256hex(canonicalRequest)
	date := time.Unix(timestamp, 0).UTC().Format("2006-01-02")
	credentialScope := date + "/" + service + "/tc3_request"
	string2sign := fmt.Sprintf("%s\n%d\n%s\n%s", algorithm,
		timestamp,
		credentialScope,
		digest)

	kDate := hmacsha256(date, "TC3"+secretKey)
	kService := hmacsha256(service, kDate)
	kSigning := hmacsha256("tc3_request", kService)

	signature := hex.EncodeToString([]byte(hmacsha256(string2sign, kSigning)))
	authorization := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, SignTime=%d, ExpireTime=%d, Signature=%s",
		algorithm,
		secretId,
		credentialScope,
		signedHeaders,
		timestamp,
		expireTimestamp,
		signature)
	return authorization
}
