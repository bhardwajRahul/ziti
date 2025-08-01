package idgen

import (
	"crypto/rand"
	"encoding/binary"
	"github.com/dineshappavoo/basex"
	"github.com/google/uuid"
	"github.com/teris-io/shortid"
	"math/big"
)

const Alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-"

var idGenerator Generator

func NewGenerator() Generator {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	seed := binary.LittleEndian.Uint64(buf)
	return &shortIdGenerator{
		Shortid: shortid.MustNew(0, Alphabet, seed),
	}
}

func init() {
	idGenerator = NewGenerator()
}

func New() string {
	id, _ := idGenerator.NextId()
	return id
}

type Generator interface {
	NextId() (string, error)
}

type shortIdGenerator struct {
	*shortid.Shortid
}

func (self *shortIdGenerator) NextId() (string, error) {
	for {
		id, err := self.Generate()
		if err != nil {
			return "", err
		}
		if id[0] != '-' && id[0] != '.' {
			return id, nil
		}
	}
}

func MustNewUUIDString() string {
	id := uuid.New()
	v := &big.Int{}
	v.SetBytes(id[:])
	result, err := basex.EncodeInt(v)
	if err != nil {
		panic(err)
	}
	return result
}

func NewUUIDString() (string, error) {
	id := uuid.New()
	v := &big.Int{}
	v.SetBytes(id[:])
	return basex.EncodeInt(v)
}
