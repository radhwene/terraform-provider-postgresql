package postgresql

import (
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/blang/semver"
)

func TestSanitizeConnError(t *testing.T) {
	specialPassword := "my@pass!"
	// url.PathEscape encodes '@' but leaves RFC 3986 sub-delimiters like '!' unencoded.
	encodedSpecialPassword := url.PathEscape(specialPassword)

	tests := []struct {
		name     string
		errMsg   string
		password string
		want     string
	}{
		{
			name:     "replaces plaintext password",
			errMsg:   "dial tcp: connection refused (password=secret123)",
			password: "secret123",
			want:     "dial tcp: connection refused (password=XXXX)",
		},
		{
			name:     "replaces URL-encoded password with special chars",
			errMsg:   fmt.Sprintf("failed to connect: postgres://user:%s@host/db", encodedSpecialPassword),
			password: specialPassword,
			want:     "failed to connect: postgres://user:XXXX@host/db",
		},
		{
			name:     "replaces both raw and encoded occurrences",
			errMsg:   fmt.Sprintf("error: %s and %s", specialPassword, encodedSpecialPassword),
			password: specialPassword,
			want:     "error: XXXX and XXXX",
		},
		{
			name:     "empty password leaves message unchanged",
			errMsg:   "some error without credentials",
			password: "",
			want:     "some error without credentials",
		},
		{
			name:     "no match leaves message unchanged",
			errMsg:   "role does not exist",
			password: "secret",
			want:     "role does not exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeConnError(tt.errMsg, tt.password)
			if got != tt.want {
				t.Errorf("sanitizeConnError() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDsnRegistryKey(t *testing.T) {
	dsn1 := "postgres://user:secret@host:5432/db"
	dsn2 := "postgres://user:other@host:5432/db"

	key1a := dsnRegistryKey(dsn1)
	key1b := dsnRegistryKey(dsn1)
	key2 := dsnRegistryKey(dsn2)

	if key1a != key1b {
		t.Errorf("dsnRegistryKey is not deterministic: %q != %q", key1a, key1b)
	}
	if key1a == key2 {
		t.Error("different DSNs produced the same registry key")
	}
	if strings.Contains(key1a, "secret") || strings.Contains(key1a, "user") {
		t.Errorf("registry key contains credentials: %q", key1a)
	}
}

func TestConfigConnParams(t *testing.T) {
	var tests = []struct {
		input *Config
		want  []string
	}{
		{&Config{Scheme: "postgres", SSLMode: "require", ConnectTimeoutSec: 10}, []string{"connect_timeout=10", "sslmode=require"}},
		{&Config{Scheme: "postgres", SSLMode: "disable"}, []string{"connect_timeout=0", "sslmode=disable"}},
		{&Config{Scheme: "awspostgres", ConnectTimeoutSec: 10}, []string{}},
		{&Config{Scheme: "awspostgres", SSLMode: "disable"}, []string{}},
		{&Config{ExpectedVersion: semver.MustParse("9.0.0"), ApplicationName: "Terraform provider"}, []string{"fallback_application_name=Terraform+provider"}},
		{&Config{ExpectedVersion: semver.MustParse("8.0.0"), ApplicationName: "Terraform provider"}, []string{}},
		{&Config{SSLClientCert: &ClientCertificateConfig{CertificatePath: "/path/to/public-certificate.pem", KeyPath: "/path/to/private-key.pem"}}, []string{"sslcert=%2Fpath%2Fto%2Fpublic-certificate.pem", "sslkey=%2Fpath%2Fto%2Fprivate-key.pem"}},
		{&Config{SSLRootCertPath: "/path/to/root.pem"}, []string{"sslrootcert=%2Fpath%2Fto%2Froot.pem"}},
	}

	for _, test := range tests {

		connParams := test.input.connParams()

		sort.Strings(connParams)
		sort.Strings(test.want)

		if !reflect.DeepEqual(connParams, test.want) {
			t.Errorf("Config.connParams(%+v) returned %#v, want %#v", test.input, connParams, test.want)
		}

	}
}

func TestConfigConnStr(t *testing.T) {
	var tests = []struct {
		input        *Config
		wantDbURL    string
		wantDbParams []string
	}{
		{&Config{Scheme: "postgres", Host: "localhost", Port: 5432, Username: "postgres_user", Password: "postgres_password", SSLMode: "disable"}, "postgres://postgres_user:postgres_password@localhost:5432/postgres", []string{"connect_timeout=0", "sslmode=disable"}},
		{&Config{Scheme: "postgres", Host: "localhost", Port: 5432, Username: "spaced user", Password: "spaced password", SSLMode: "disable"}, "postgres://spaced%20user:spaced%20password@localhost:5432/postgres", []string{"connect_timeout=0", "sslmode=disable"}},
	}

	for _, test := range tests {

		connStr := test.input.connStr("postgres")

		splitConnStr := strings.Split(connStr, "?")

		if splitConnStr[0] != test.wantDbURL {
			t.Errorf("Config.connStr(%+v) returned %#v, want %#v", test.input, splitConnStr[0], test.wantDbURL)
		}

		connParams := strings.Split(splitConnStr[1], "&")

		sort.Strings(connParams)
		sort.Strings(test.wantDbParams)

		if !reflect.DeepEqual(connParams, test.wantDbParams) {
			t.Errorf("Config.connStr(%+v) returned %#v, want %#v", test.input, connParams, test.wantDbParams)
		}

	}
}
