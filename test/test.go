package main

import "fmt"
import "math/rand"
import "curve25519-go/axlsign"
import b64 "encoding/base64"
import "time"

func randomBytes(size int) []uint8 {
	rand.Seed(time.Now().UTC().UnixNano())
	var High int = 255
	var seed = make([]uint8, size ) 
	for i := 0; i < len(seed); i++ { 
		seed[i] = uint8(rand.Int() % (High + 1))
	}
	return seed
}

func main() {
    fmt.Println("\nHello, curve25519\n")
     	
	// random seed
	var seed = randomBytes(32)

	// generate key pair
	var keys = axlsign.GenerateKeyPair(seed)	
	
	var texto = "¡ lo esencial es invisible a los ojos !..."	
	var rnd = randomBytes(64)
	var msg = []uint8( texto )
	var sig = axlsign.Sign(keys.PrivateKey, msg, rnd) // firmar
	var res = axlsign.Verify(keys.PublicKey, msg, sig) // control ok
	var res1 = axlsign.Verify(keys.PrivateKey, msg, sig) // control error
		
	var sigmsg = axlsign.SignMessage(keys.PrivateKey, msg, rnd)
	// var msg2 = axlsign.OpenMessage(keys.PublicKey, sigmsg)
	var smsg = axlsign.OpenMessageStr(keys.PublicKey, sigmsg)
	
	// controles
	
	fmt.Printf("Res: %d\nRes2: %d\n", res, res1)
	fmt.Println(texto)
	fmt.Println(smsg)
		
	// Control 
	
	var b64sk, _ = b64.StdEncoding.DecodeString( "QEK6Xm/ourxQVlBzaOdVxYBeew8dlQ7dYrqEI60ksmo=" )
	var b64pk, _ = b64.StdEncoding.DecodeString( "yScViZr67HSpb5mWG/Ij0yCFAmwCqdYB9nxLasej/0g=" )
	
	var sk = []uint8( b64sk ) // privada
	var pk = []uint8( b64pk ) // publica
	var shared = axlsign.SharedKey(sk, pk)

	texto = "PRUEBA FIRMA"	
	
	rnd = []uint8( "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" )
	msg = []uint8( texto )
	sig = axlsign.Sign(sk, msg, rnd) // firmar
	seed = []uint8( "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ) // 32
	
	keys = axlsign.GenerateKeyPair(seed)		
	sigmsg = axlsign.SignMessage(keys.PrivateKey, msg, rnd)
	smsg = axlsign.OpenMessageStr(keys.PublicKey, sigmsg)

	// LOG
	fmt.Println("sk: " + b64.StdEncoding.EncodeToString(sk) )
	fmt.Println("pk: " + b64.StdEncoding.EncodeToString(pk) )
	fmt.Println("shared: " + b64.StdEncoding.EncodeToString(shared) )
	fmt.Println("sig: " + b64.StdEncoding.EncodeToString(sig) )		
	fmt.Println("sig+msg: " + b64.StdEncoding.EncodeToString(sigmsg) )		
	fmt.Println("msg: " + smsg )
	
}
