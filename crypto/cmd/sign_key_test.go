// (C) 1f349 2025 - BSD-3-Clause License

package cmd

import (
	"crypto/sha256"
	"github.com/1f349/handshake/crypto"
	"github.com/1f349/handshake/crypto/cmd"
	pqc_crypto "github.com/1f349/pqc-handshake/crypto"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/stretchr/testify/assert"
	"hash"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestMainSignKey(t *testing.T) {
	dir := t.TempDir()
	kemScheme := pqc_crypto.WrapKem(mlkem768.Scheme())
	ekp, _, err := kemScheme.GenerateKeyPair()
	assert.NoError(t, err)
	ekpBts, err := ekp.MarshalBinary()
	assert.NoError(t, err)
	assert.NoError(t, os.WriteFile(dir+"/epubkey", ekpBts, 0644))
	sigScheme := pqc_crypto.WrapSig(mldsa44.Scheme())
	kp, k, err := sigScheme.GenerateKeyPair()
	assert.NoError(t, err)
	kBts, err := k.MarshalBinary()
	assert.NoError(t, err)
	assert.NoError(t, os.WriteFile(dir+"/privkey", kBts, 0600))
	tHash := sha256.New()
	var oargs = os.Args
	defer func() {
		os.Args = oargs
	}()
	var tFunc = func(code int) {
		if code != 0 {
			t.Log(code)
			t.FailNow()
		}
	}
	var uFunc = func(code int) {
		if code != 1 {
			t.Log(code)
			t.FailNow()
		}
	}
	t.Run("command privkey epubkey sig", func(t *testing.T) {
		os.Args = []string{"testing", dir + "/privkey", dir + "/epubkey", dir + "/sig"}
		testMainSignKey(t, dir, sigScheme, tHash, ekpBts, kp, time.Time{}, time.Time{}, tFunc, nil, nil, 0, false)
	})
	t.Run("command privkey epubkey -", func(t *testing.T) {
		os.Args = []string{"testing", dir + "/privkey", dir + "/epubkey", "-"}
		stdout := getStdOut(dir)
		testMainSignKey(t, dir, sigScheme, tHash, ekpBts, kp, time.Time{}, time.Time{}, tFunc, stdout, nil, 0, false)
	})
	t.Run("command - epubkey sig Now()+1h", func(t *testing.T) {
		exp := time.Now().Add(time.Hour)
		os.Args = []string{"testing", "-", dir + "/epubkey", dir + "/sig", exp.Format(cmd.RFC3339Milli)}
		assert.NoError(t, writeStdIn(dir, kBts))
		stdin := getStdIn(dir)
		testMainSignKey(t, dir, sigScheme, tHash, ekpBts, kp, time.Time{}, exp, tFunc, nil, stdin, 0, false)
	})
	t.Run("command privkey - sig 1h", func(t *testing.T) {
		os.Args = []string{"testing", dir + "/privkey", "-", dir + "/sig", "1h"}
		assert.NoError(t, writeStdIn(dir, ekpBts))
		stdin := getStdIn(dir)
		testMainSignKey(t, dir, sigScheme, tHash, ekpBts, kp, time.Time{}, time.Time{}, tFunc, nil, stdin, 0, false)
	})
	t.Run("command - epubkey - UnixMilli(Now()+1h)", func(t *testing.T) {
		exp := time.Now().Add(time.Hour)
		os.Args = []string{"testing", "-", dir + "/epubkey", "-", strconv.FormatInt(exp.UnixMilli(), 10)}
		assert.NoError(t, writeStdIn(dir, kBts))
		stdin := getStdIn(dir)
		stdout := getStdOut(dir)
		testMainSignKey(t, dir, sigScheme, tHash, ekpBts, kp, time.Time{}, exp, tFunc, stdout, stdin, 0, false)
	})
	t.Run("command privkey - - 1h Now()+10ms", func(t *testing.T) {
		iss := time.Now().Add(10 * time.Millisecond)
		exp := iss.Add(time.Hour)
		os.Args = []string{"testing", dir + "/privkey", "-", "-", "1h", iss.Format(cmd.RFC3339Milli)}
		assert.NoError(t, writeStdIn(dir, ekpBts))
		stdin := getStdIn(dir)
		stdout := getStdOut(dir)
		testMainSignKey(t, dir, sigScheme, tHash, ekpBts, kp, iss, exp, tFunc, stdout, stdin, 50*time.Millisecond, false)
	})
	t.Run("fail-verify privkey - - 1h Now()+1s", func(t *testing.T) {
		iss := time.Now().Add(time.Second)
		exp := iss.Add(time.Hour)
		os.Args = []string{"testing", dir + "/privkey", "-", "-", "1h", iss.Format(cmd.RFC3339Milli)}
		assert.NoError(t, writeStdIn(dir, ekpBts))
		stdin := getStdIn(dir)
		stdout := getStdOut(dir)
		testMainSignKey(t, dir, sigScheme, tHash, ekpBts, kp, iss, exp, tFunc, stdout, stdin, 0, true)
	})
	t.Run("command privkey - - Now()+1m UnixMilli(Now()+25ms)", func(t *testing.T) {
		iss := time.Now().Add(25 * time.Millisecond)
		exp := iss.Add(time.Minute)
		os.Args = []string{"testing", dir + "/privkey", "-", "-", exp.Format(cmd.RFC3339Milli), strconv.FormatInt(iss.UnixMilli(), 10)}
		assert.NoError(t, writeStdIn(dir, ekpBts))
		stdin := getStdIn(dir)
		stdout := getStdOut(dir)
		testMainSignKey(t, dir, sigScheme, tHash, ekpBts, kp, iss, exp, tFunc, stdout, stdin, 100*time.Millisecond, false)
	})
	t.Run("Usage", func(t *testing.T) {
		os.Args = []string{"testing"}
		cmd.TestingMainSignKey(sigScheme, tHash, "a", "b", "c", "d", "e", uFunc, nil, nil)
	})
	t.Run("Double stdin", func(t *testing.T) {
		os.Args = []string{"testing", "-", "-", "-"}
		cmd.TestingMainSignKey(sigScheme, tHash, "a", "b", "c", "d", "e", uFunc, nil, nil)
	})
}

func testMainSignKey(t *testing.T, dir string, sigScheme crypto.SigScheme, hashScheme hash.Hash,
	ekp []byte, kp crypto.SigPublicKey, issue, expiry time.Time, close func(code int), stdout, stdin *os.File, delay time.Duration, failing bool) {
	cmd.TestingMainSignKey(sigScheme, hashScheme, "a", "b", "c", "d", "e", close, stdout, stdin)
	if delay > 0 {
		time.Sleep(delay)
	}
	var err error
	var bts []byte
	if stdout == nil {
		bts, err = os.ReadFile(dir + "/sig")
	} else {
		bts, err = os.ReadFile(dir + "/stdout")
	}
	assert.NoError(t, err)
	sd, err := crypto.UnmarshalSigData(bts, ekp)
	assert.NoError(t, err)
	if !issue.IsZero() {
		assert.Equal(t, time.UnixMilli(issue.UnixMilli()), sd.IssueTime)
	}
	if !expiry.IsZero() {
		assert.Equal(t, time.UnixMilli(expiry.UnixMilli()), sd.ExpiryTime)
	}
	v := sd.Verify(hashScheme, kp)
	assert.Equal(t, !failing, v)
}
