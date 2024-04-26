package rego

import (
	"crypto/tls"
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/externaldata/unversioned"
)

const (
	validCABundle = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUIwekNDQVgyZ0F3SUJBZ0lKQUkvTTdCWWp3Qit1TUEwR0NTcUdTSWIzRFFFQkJRVUFNRVV4Q3pBSkJnTlYKQkFZVEFrRlZNUk13RVFZRFZRUUlEQXBUYjIxbExWTjBZWFJsTVNFd0h3WURWUVFLREJoSmJuUmxjbTVsZENCWAphV1JuYVhSeklGQjBlU0JNZEdRd0hoY05NVEl3T1RFeU1qRTFNakF5V2hjTk1UVXdPVEV5TWpFMU1qQXlXakJGCk1Rc3dDUVlEVlFRR0V3SkJWVEVUTUJFR0ExVUVDQXdLVTI5dFpTMVRkR0YwWlRFaE1COEdBMVVFQ2d3WVNXNTAKWlhKdVpYUWdWMmxrWjJsMGN5QlFkSGtnVEhSa01Gd3dEUVlKS29aSWh2Y05BUUVCQlFBRFN3QXdTQUpCQU5MSgpoUEhoSVRxUWJQa2xHM2liQ1Z4d0dNUmZwL3Y0WHFoZmRRSGRjVmZIYXA2TlE1V29rLzR4SUErdWkzNS9NbU5hCnJ0TnVDK0JkWjF0TXVWQ1BGWmNDQXdFQUFhTlFNRTR3SFFZRFZSME9CQllFRkp2S3M4UmZKYVhUSDA4VytTR3YKelF5S24wSDhNQjhHQTFVZEl3UVlNQmFBRkp2S3M4UmZKYVhUSDA4VytTR3Z6UXlLbjBIOE1Bd0dBMVVkRXdRRgpNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUZCUUFEUVFCSmxmZkpIeWJqREd4Uk1xYVJtRGhYMCs2djAyVFVLWnNXCnI1UXVWYnBRaEg2dSswVWdjVzBqcDlRd3B4b1BUTFRXR1hFV0JCQnVyeEZ3aUNCaGtRK1YKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
	badCABundle   = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmhlbGxvCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"
)

func Test_getClient(t *testing.T) {
	type args struct {
		provider   *unversioned.Provider
		clientCert *tls.Certificate
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "invalid http url",
			args: args{
				provider: &unversioned.Provider{
					Spec: unversioned.ProviderSpec{
						URL: "http://foo",
					},
				},
				clientCert: nil,
			},
			wantErr: true,
		},
		{
			name: "no CA bundle",
			args: args{
				provider: &unversioned.Provider{
					Spec: unversioned.ProviderSpec{
						URL: "https://foo",
					},
				},
				clientCert: nil,
			},
			wantErr: true,
		},
		{
			name: "invalid CA bundle",
			args: args{
				provider: &unversioned.Provider{
					Spec: unversioned.ProviderSpec{
						URL:      "https://foo",
						CABundle: badCABundle,
					},
				},
				clientCert: nil,
			},
			wantErr: true,
		},
		{
			name: "valid CA bundle",
			args: args{
				provider: &unversioned.Provider{
					Spec: unversioned.ProviderSpec{
						URL:      "https://foo",
						CABundle: validCABundle,
					},
				},
				clientCert: nil,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := getClient(tt.args.provider, tt.args.clientCert)
			if (err != nil) != tt.wantErr {
				t.Errorf("getClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
