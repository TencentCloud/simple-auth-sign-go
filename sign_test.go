package simple_auth_sign_go

import (
	"testing"
)

func TestSign(t *testing.T) {
	var expiration int64 = 3600 * 2
	var now int64 = 1727685604
	secretId := "test_secret_id"
	secretKey := "test_secret_key"
	serviceHost := "service-1.test.com"
	sig := Sign(secretId, secretKey, "", serviceHost, now, now+expiration)
	sigExpected := "TC3-HMAC-SHA256 Credential=test_secret_id/2024-09-30/clbia/tc3_request, SignedHeaders=content-type;host, SignTime=1727685604, ExpireTime=1727692804, Signature=f974c5e4f168d9bd170b6580d573a506ce0acd446e8d71000110269b614e38df"
	if sig != sigExpected {
		t.Fail()
	}
}

func TestSignWithToken(t *testing.T) {
	var expiration int64 = 3600 * 2
	var now int64 = 1727685604
	secretId := "test_secret_id"
	secretKey := "test_secret_key"
	serviceHost := "service-1.test.com"
	token := "test_token"
	sig := Sign(secretId, secretKey, token, serviceHost, now, now+expiration)
	sigExpected := "TC3-HMAC-SHA256 Credential=test_secret_id/2024-09-30/clbia/tc3_request, SignedHeaders=content-type;host, SignTime=1727685604, ExpireTime=1727692804, Signature=f974c5e4f168d9bd170b6580d573a506ce0acd446e8d71000110269b614e38df, Token=test_token"
	if sig != sigExpected {
		t.Fail()
	}
}
