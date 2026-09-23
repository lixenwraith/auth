package auth_test

import (
	"fmt"
	"log"

	"github.com/lixenwraith/auth"
)

func ExampleNewCredential() {
	credential, err := auth.NewCredential("alice", "a-long-example-password")
	if err != nil {
		log.Fatal(err)
	}
	// For this local example only. Services should persist a random decoy key
	// and use NewScramServerWithDecoyKey, plus authenticated TLS for transport.
	server := auth.NewScramServer()
	defer server.Stop()
	if err := server.AddCredential(credential); err != nil {
		log.Fatal(err)
	}
	client := auth.NewScramClient("alice", "a-long-example-password")
	first, err := client.StartAuthentication()
	if err != nil {
		log.Fatal(err)
	}
	challenge, err := server.ProcessClientFirstMessage(first.Username, first.ClientNonce)
	if err != nil {
		log.Fatal(err)
	}
	proof, err := client.ProcessServerFirstMessage(challenge)
	if err != nil {
		log.Fatal(err)
	}
	final, err := server.ProcessClientFinalMessage(proof.FullNonce, proof.ClientProof)
	if err != nil {
		log.Fatal(err)
	}
	if err := client.VerifyServerFinalMessage(final); err != nil {
		log.Fatal(err)
	}
	fmt.Println(final.Username)
	// Output: alice
}
