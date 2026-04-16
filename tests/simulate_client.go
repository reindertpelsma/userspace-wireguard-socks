package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const API_BASE = "http://127.0.0.1:8080"

func main() {
	// 1. Generate KeyPair
	priv, _ := wgtypes.GeneratePrivateKey()
	pub := priv.PublicKey()

	// 2. Login
	token := login("admin", "admin")
	fmt.Printf("Logged in: %s\n", token)

	// 3. Nonce Blessing
	nonce := make([]byte, 12)
	rand.Read(nonce)
	nonceHex := hex.EncodeToString(nonce)
	
	aesKeyHex := hmacBlessing(token, nonceHex)
	aesKey, _ := hex.DecodeString(aesKeyHex)

	// 4. Encrypt Private Key (AES-GCM)
	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)
	encrypted := gcm.Seal(nil, nonce, priv[:], nil)
	encryptedB64 := base64.StdEncoding.EncodeToString(encrypted)

	h := sha256.New()
	h.Write([]byte(nonceHex))
	nonceHash := hex.EncodeToString(h.Sum(nil))

	// 5. Create Peer
	peerID, assignedIP := createPeer(token, "Test Device", pub.String(), nonceHash, encryptedB64)
	fmt.Printf("Peer Created! ID: %d, IP: %s\n", peerID, assignedIP)

	// 6. Get Private Data
	privateData := getPrivate(token, peerID, nonceHash)
	
	// 7. Decrypt Private Key
	encPriv, _ := base64.StdEncoding.DecodeString(privateData.EncryptedPrivateKey)
	decryptedPriv, _ := gcm.Open(nil, nonce, encPriv, nil)
	
	// 8. Generate Client YAML
	var ipsArr []string
	for _, ip := range strings.Split(assignedIP, ",") {
		ipsArr = append(ipsArr, fmt.Sprintf("%q", strings.TrimSpace(ip)))
	}
	yaml := fmt.Sprintf(`
wireguard:
  private_key: %s
  addresses: [%s]
  mtu: 1420
  peers:
    - public_key: %s
      endpoint: 127.0.0.1:51820
      allowed_ips: ["0.0.0.0/0", "::/0"]
      persistent_keepalive: 25
      preshared_key: %s

proxy:
  socks5: 127.0.0.1:1081
`, base64.StdEncoding.EncodeToString(decryptedPriv), strings.Join(ipsArr, ", "), getPublicConfig(token)["server_pubkey"], privateData.PresharedKey)

	os.WriteFile("client_test.yaml", []byte(yaml), 0644)
	fmt.Println("Wrote client_test.yaml")
}

func login(user, pass string) string {
	body, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	resp, _ := http.Post(API_BASE+"/api/login", "application/json", bytes.NewBuffer(body))
	var res map[string]string
	json.NewDecoder(resp.Body).Decode(&res)
	return res["token"]
}

func hmacBlessing(token, nonce string) string {
	req, _ := http.NewRequest("GET", API_BASE+"/api/auth/hmac-nonce?nonce="+nonce, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := http.DefaultClient.Do(req)
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

func createPeer(token, name, pub, nHash, encPriv string) (int, string) {
	body, _ := json.Marshal(map[string]string{
		"name": name,
		"public_key": pub,
		"nonce_hash": nHash,
		"encrypted_private_key": encPriv,
	})
	req, _ := http.NewRequest("POST", API_BASE+"/api/peers", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := http.DefaultClient.Do(req)
	var res map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&res)
	return int(res["id"].(float64)), res["assigned_ips"].(string)
}

type PeerPrivate struct {
	ID                  int    `json:"id"`
	PresharedKey        string `json:"preshared_key"`
	EncryptedPrivateKey string `json:"encrypted_private_key"`
}

func getPrivate(token string, id int, nHash string) PeerPrivate {
	url := fmt.Sprintf("%s/api/peers/%d/private", API_BASE, id)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Nonce-Hash", nHash)
	resp, _ := http.DefaultClient.Do(req)
	var res PeerPrivate
	json.NewDecoder(resp.Body).Decode(&res)
	return res
}

func getPublicConfig(token string) map[string]string {
	req, _ := http.NewRequest("GET", API_BASE+"/api/config/public", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := http.DefaultClient.Do(req)
	var res map[string]string
	json.NewDecoder(resp.Body).Decode(&res)
	return res
}
