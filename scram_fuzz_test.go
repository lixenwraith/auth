package auth

import (
	"encoding/base64"
	"testing"
)

func FuzzScramServerMessages(f *testing.F) {
	s := NewScramServer()
	f.Cleanup(s.Stop)
	f.Add("unknown", "nonce", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	f.Add("", "", "")
	f.Add("a,n=b", "nonce", "!!!")
	f.Fuzz(func(t *testing.T, username, nonce, proof string) {
		first, err := s.ProcessClientFirstMessage(username, nonce)
		if err != nil {
			return
		}
		// No credential is registered, so even syntactically valid proofs fail.
		_, err = s.ProcessClientFinalMessage(first.FullNonce, proof)
		if err == nil {
			t.Fatal("unknown account authenticated")
		}
		_, err = s.ProcessClientFinalMessage(first.FullNonce, proof)
		errIs(t, err, ErrSCRAMInvalidNonce, "failed proof consumed")
		if handshakeCount(s) != 0 {
			t.Fatal("handshake leaked")
		}
	})
}

func FuzzScramClientMessages(f *testing.F) {
	f.Add("server", base64.StdEncoding.EncodeToString(make([]byte, 16)), uint32(1), uint32(8), uint8(1), "")
	f.Add("", "!!!", uint32(0), uint32(0), uint8(0), "!!!")
	f.Add("server", "", uint32(16), uint32(MaxVerifyArgonMemory), uint8(16), "")
	f.Fuzz(func(t *testing.T, suffix, salt string, iterations, memory uint32, threads uint8, signature string) {
		// Invalid costs exercise production rejection. Valid costs are restricted
		// to tiny test profiles so fuzzing cannot multiply expensive KDF work.
		if checkScramCost(memory, iterations, threads) == nil && (memory > 64 || iterations > 2 || threads > 2) {
			return
		}
		c := NewScramClient("u", "password123", WithMinArgonCost(1, 8))
		first, err := c.StartAuthentication()
		noErr(t, err, "start")
		msg := ServerFirstMessage{FullNonce: first.ClientNonce + suffix, Salt: salt, ArgonTime: iterations, ArgonMemory: memory, ArgonThreads: threads}
		proof, err := c.ProcessServerFirstMessage(msg)
		if err != nil {
			if proof.FullNonce != "" || proof.ClientProof != "" || c.serverKey != nil {
				t.Fatal("state/values survived error")
			}
			return
		}
		if proof.FullNonce != msg.FullNonce {
			t.Fatal("nonce not bound")
		}
		_ = c.VerifyServerFinalMessage(ServerFinalMessage{ServerSignature: signature})
		errIs(t, c.VerifyServerFinalMessage(ServerFinalMessage{ServerSignature: signature}), ErrSCRAMInvalidState, "final consumed")
		if c.serverKey != nil {
			t.Fatal("server key survived final")
		}
	})
}
