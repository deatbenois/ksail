package sopsutil_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/devantler-tech/ksail/v7/pkg/apis/cluster/v1alpha1"
	"github.com/devantler-tech/ksail/v7/pkg/svc/installer/internal/sopsutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// ExtractAllAgeKeys
// ---------------------------------------------------------------------------

func TestExtractAllAgeKeys(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "single key",
			input: "AGE-SECRET-KEY-1ABCDEF0000000000000000000000000000000000000000000000000",
			want:  []string{"AGE-SECRET-KEY-1ABCDEF0000000000000000000000000000000000000000000000000"},
		},
		{
			name: "multiple keys with metadata",
			input: "# created: 2024-01-01T00:00:00Z\n# public key: age1abc\n" +
				"AGE-SECRET-KEY-FIRST000000000000000000000000000000000000000000000000\n" +
				"# created: 2024-06-01T00:00:00Z\n# public key: age1def\n" +
				"AGE-SECRET-KEY-SECOND00000000000000000000000000000000000000000000000\n",
			want: []string{
				"AGE-SECRET-KEY-FIRST000000000000000000000000000000000000000000000000",
				"AGE-SECRET-KEY-SECOND00000000000000000000000000000000000000000000000",
			},
		},
		{
			name: "three keys",
			input: "AGE-SECRET-KEY-FIRST000000000000000000000000000000000000000000000000\n" +
				"AGE-SECRET-KEY-SECOND00000000000000000000000000000000000000000000000\n" +
				"AGE-SECRET-KEY-THIRD000000000000000000000000000000000000000000000000\n",
			want: []string{
				"AGE-SECRET-KEY-FIRST000000000000000000000000000000000000000000000000",
				"AGE-SECRET-KEY-SECOND00000000000000000000000000000000000000000000000",
				"AGE-SECRET-KEY-THIRD000000000000000000000000000000000000000000000000",
			},
		},
		{
			name:  "empty input",
			input: "",
			want:  nil,
		},
		{
			name:  "no keys",
			input: "# just comments\n# nothing here",
			want:  nil,
		},
		{
			name:  "key with whitespace trimmed",
			input: "  AGE-SECRET-KEY-1ABCDEF0000000000000000000000000000000000000000000000000  ",
			want:  []string{"AGE-SECRET-KEY-1ABCDEF0000000000000000000000000000000000000000000000000"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := sopsutil.ExtractAllAgeKeys(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// FilterKeysByPublicKeys
// ---------------------------------------------------------------------------

func TestFilterKeysByPublicKeys(t *testing.T) {
	t.Parallel()

	// Generate a real age identity to get a valid private/public key pair.
	// We use known test keys that are syntactically valid but not real secrets.
	// For FilterKeysByPublicKeys, the keys must be parseable by age.ParseX25519Identity.
	// We test with real age key generation instead.

	t.Run("empty private keys returns empty", func(t *testing.T) {
		t.Parallel()

		result, err := sopsutil.FilterKeysByPublicKeys(nil, []string{"age1test"})
		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("empty public keys returns empty", func(t *testing.T) {
		t.Parallel()

		result, err := sopsutil.FilterKeysByPublicKeys(
			[]string{"AGE-SECRET-KEY-1ABCDEF0000000000000000000000000000000000000000000000000"},
			nil,
		)
		require.NoError(t, err)
		assert.Empty(t, result)
	})
}

// ---------------------------------------------------------------------------
// ResolveAgeKey: env.var override
// ---------------------------------------------------------------------------

//nolint:paralleltest // Uses t.Setenv
func TestResolveAgeKey_EnvVarOverride(t *testing.T) {
	const testKey = "AGE-SECRET-KEY-1ENVVAR00000000000000000000000000000000000000000000000000"

	t.Run("env.var takes priority over ageKeyEnvVar", func(t *testing.T) {
		t.Setenv("TEST_SOPSUTIL_ENV_VAR_NEW", testKey)
		t.Setenv("TEST_SOPSUTIL_ENV_VAR_OLD", "AGE-SECRET-KEY-1OLDVAR00000000000000000000000000000000000000000000000000")
		noKeyFileEnv(t)

		sops := v1alpha1.SOPS{
			AgeKeyEnvVar: "TEST_SOPSUTIL_ENV_VAR_OLD",
			Env:          v1alpha1.SOPSEnv{Var: "TEST_SOPSUTIL_ENV_VAR_NEW"},
		}
		got, err := sopsutil.ResolveAgeKey(sops)
		require.NoError(t, err)
		assert.Equal(t, testKey, got)
	})

	t.Run("falls back to ageKeyEnvVar when env.var empty", func(t *testing.T) {
		t.Setenv("TEST_SOPSUTIL_ENV_VAR_FALLBACK", testKey)
		noKeyFileEnv(t)

		sops := v1alpha1.SOPS{
			AgeKeyEnvVar: "TEST_SOPSUTIL_ENV_VAR_FALLBACK",
		}
		got, err := sopsutil.ResolveAgeKey(sops)
		require.NoError(t, err)
		assert.Equal(t, testKey, got)
	})
}

// ---------------------------------------------------------------------------
// ResolveAgeKey: extract.file override
// ---------------------------------------------------------------------------

//nolint:paralleltest // Uses t.Setenv
func TestResolveAgeKey_ExtractFileOverride(t *testing.T) {
	const testKey = "AGE-SECRET-KEY-1CUSTOM00000000000000000000000000000000000000000000000000"

	t.Run("extract.file specifies custom key file", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "custom-keys.txt")
		err := os.WriteFile(keyPath, []byte("# custom\n"+testKey+"\n"), 0o600)
		require.NoError(t, err)

		// Set env var to empty to skip env var lookup
		t.Setenv("TEST_SOPSUTIL_EXTRACT_EMPTY", "")

		sops := v1alpha1.SOPS{
			AgeKeyEnvVar: "TEST_SOPSUTIL_EXTRACT_EMPTY",
			Extract:      v1alpha1.SOPSExtract{File: keyPath},
		}
		got, err := sopsutil.ResolveAgeKey(sops)
		require.NoError(t, err)
		assert.Equal(t, testKey, got)
	})
}

// ---------------------------------------------------------------------------
// ResolveAgeKey: multi-key file returns all keys
// ---------------------------------------------------------------------------

//nolint:paralleltest // Uses t.Setenv
func TestResolveAgeKey_MultiKeyFileReturnsAll(t *testing.T) {
	const (
		key1 = "AGE-SECRET-KEY-FIRST000000000000000000000000000000000000000000000000"
		key2 = "AGE-SECRET-KEY-SECOND00000000000000000000000000000000000000000000000"
	)

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "keys.txt")
	err := os.WriteFile(keyPath, []byte(
		"# key 1\n"+key1+"\n# key 2\n"+key2+"\n",
	), 0o600)
	require.NoError(t, err)

	t.Setenv("TEST_SOPSUTIL_MULTI_EMPTY", "")

	sops := v1alpha1.SOPS{
		AgeKeyEnvVar: "TEST_SOPSUTIL_MULTI_EMPTY",
		Extract:      v1alpha1.SOPSExtract{File: keyPath},
	}
	got, err := sopsutil.ResolveAgeKey(sops)
	require.NoError(t, err)
	assert.Equal(t, key1+"\n"+key2, got)
}
