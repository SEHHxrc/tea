//The algorithm implemented by this program is similar to the ECB mode of block cipher
package tea

import (
	"encoding/binary"
	"errors"
)

const (
	KEY_LENGTH   = 16
	BLOCK_LENGTH = 8
	ROUND        = 32
	DELTA        = 0x9e3779b9
)

type TEA struct {
	key []byte
}

func New(key []byte) (*TEA, error) {
	if len(key) != KEY_LENGTH {
		return nil, errors.New("tea: incorrect key length")
	}
	tea := &TEA{key: key}
	return tea, nil
}

func (tea *TEA) Encrypt(plaintext []byte) (ciphertext []byte) {
	var cipher [BLOCK_LENGTH]byte
	for i := 0; i < len(plaintext)/BLOCK_LENGTH; i++ { //encrypt every block
		tea.calc(plaintext[i*BLOCK_LENGTH:(i+1)*BLOCK_LENGTH], cipher[:], "encrypt")
		ciphertext = append(ciphertext, cipher[:]...) //append each encrypted block
	}
	return
}

func (tea *TEA) Decrypt(ciphertext []byte) (plaintext []byte) {
	var plain [BLOCK_LENGTH]byte
	for i := 0; i < len(ciphertext)/BLOCK_LENGTH; i++ { //decrypt every block
		tea.calc(ciphertext[i*BLOCK_LENGTH:(i+1)*BLOCK_LENGTH], plain[:], "decrypt")
		plaintext = append(plaintext, plain[:]...) //append each decrypted block
	}
	return
}

func (tea *TEA) calc(text, result []byte, mode string) { //calculate every plaintext or ciphertext block(8 bytes long)
	e := binary.BigEndian
	v0, v1 := e.Uint32(text[0:]), e.Uint32(text[4:])
	k0, k1, k2, k3 := e.Uint32(tea.key[0:]), e.Uint32(tea.key[4:]), e.Uint32(tea.key[8:]), e.Uint32(tea.key[12:])
	delta := uint32(DELTA)
	if mode == "encrypt" {
		sum := uint32(0)
		for i := 0; i < ROUND; i++ {
			sum += delta
			v0 += ((v1 << 4) + k0) ^ (sum + v1) ^ ((v1 >> 5) + k1)
			v1 += ((v0 << 4) + k2) ^ (sum + v0) ^ ((v0 >> 5) + k3)
		}
	} else {
		sum := uint32(delta) * uint32(ROUND)
		for i := 0; i < ROUND; i++ {
			v1 -= ((v0 << 4) + k2) ^ (sum + v0) ^ ((v0 >> 5) + k3)
			v0 -= ((v1 << 4) + k0) ^ (sum + v1) ^ ((v1 >> 5) + k1)
		}
	}
	e.PutUint32(result, v0)
	e.PutUint32(result[4:], v1)
}

func Test() ([]byte, error) {
	key := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	text := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	tea, err := New(key)
	if err != nil {
		return nil, err
	}
	cipher := tea.Encrypt(text)
	return cipher, nil
}
