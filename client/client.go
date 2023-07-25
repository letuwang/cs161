package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

type TaggedCipherText struct {
	CipherText []byte
	Tag        []byte
}

type User struct {
	Username string
	DecKey   userlib.PKEDecKey
	SignKey  userlib.DSSignKey
	rootKey  []byte // == PBKDF(password, uuid)
}

type UserPublicKeys struct {
	EncKey    userlib.PKEEncKey
	VerifyKey userlib.DSVerifyKey
}

type FileInfo struct {
	Owner       []byte    // hash(owner's username)
	Inviter     []byte    // hash(inviter's username)
	RootInviter []byte    // hash(root inviter's username)
	FileKeyId   uuid.UUID // uuid of the file's FileKey
}

type FileKey struct {
	selfId uuid.UUID
	FileId uuid.UUID
	EncKey []byte // AES Key for encryption/decryption
	MacKey []byte // AES Key for MAC
}

type File struct {
	NumBlocks         int // number of FileBlocks associated with this file
	LastBlockId       uuid.UUID
	InvitationTableID uuid.UUID // uuid of the file's InvitationTable
}

type FileBlock struct {
	Data        []byte
	PrevBlockId uuid.UUID
}

// {B: [B's uuid, D's uuid, E's uuid, F's uuid], C: [C's uuid, G's uuid]}
type InvitationTable map[string][]uuid.UUID

func getUserID(username string) (uuid.UUID, error) {
	id, err := uuid.FromBytes(userlib.Hash([]byte("User/" + username))[:16])
	if err != nil {
		return uuid.Nil, fmt.Errorf("error determining uuid: %w", err)
	}
	return id, nil
}

func symAuthEnc(data any, encKey []byte, macKey []byte) ([]byte, error) {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("error marshalling data: %w", err)
	}
	iv := userlib.RandomBytes(16)
	ciphertext := userlib.SymEnc(encKey, iv, dataBytes)
	tag, err := userlib.HMACEval(macKey, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("error evaluating HMAC: %w", err)
	}
	result, err := json.Marshal(TaggedCipherText{ciphertext, tag})
	if err != nil {
		return nil, fmt.Errorf("error marshalling tagged ciphertext: %w", err)
	}
	return result, nil
}

func InitUser(username string, password string) (*User, error) {
	id, err := getUserID(username)
	if err != nil {
		return nil, err
	}
	_, ok := userlib.DatastoreGet(id)
	if ok {
		return nil, fmt.Errorf("user already exists at uuid %v", id)
	}
	encKey, decKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, fmt.Errorf("error generating PKE keypair: %w", err)
	}
	signKey, verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, fmt.Errorf("error generating DS keypair: %w", err)
	}
	rootkey := userlib.Argon2Key([]byte(password), []byte(id.String()), 16)
	user := User{username, decKey, signKey, rootkey}
	userMacKey, err := userlib.HashKDF(rootkey, []byte("mac"))
	if err != nil {
		return nil, fmt.Errorf("error deriving mac key: %w", err)
	}
	encUserBytes, err := symAuthEnc(user, rootkey, userMacKey)
	if err != nil {
		return nil, fmt.Errorf("error encrypting user: %w", err)
	}
	userlib.DatastoreSet(id, encUserBytes)
	err = userlib.KeystoreSet(username+"/Enc", encKey)
	if err != nil {
		return nil, fmt.Errorf("error storing encryption key: %w", err)
	}
	userlib.KeystoreSet(username+"/Verify", verifyKey)
	if err != nil {
		return nil, fmt.Errorf("error storing verification key: %w", err)
	}
	return &user, nil
}

func symAuthDec(encTaggedCipherText []byte, encKey []byte, macKey []byte, resultPtr any) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	var taggedCipherTextPtr *TaggedCipherText
	err = json.Unmarshal(encTaggedCipherText, taggedCipherTextPtr)
	if err != nil {
		return fmt.Errorf("error unmarshalling tagged ciphertext: %w", err)
	}
	tag, err := userlib.HMACEval(macKey, taggedCipherTextPtr.CipherText)
	if err != nil {
		return fmt.Errorf("error evaluating HMAC: %w", err)
	}
	if !userlib.HMACEqual(tag, taggedCipherTextPtr.Tag) {
		return fmt.Errorf("HMACs do not match")
	}
	dataBytes := userlib.SymDec(encKey, taggedCipherTextPtr.CipherText)
	err = json.Unmarshal(dataBytes, resultPtr)
	if err != nil {
		return fmt.Errorf("error marshalling data: %w", err)
	}
	return nil
}

func GetUser(username string, password string) (*User, error) {
	userID, err := getUserID(username)
	if err != nil {
		return nil, err
	}
	encUserBytes, ok := userlib.DatastoreGet(userID)
	if !ok {
		return nil, fmt.Errorf("user %s not found", username)
	}
	rootkey := userlib.Argon2Key([]byte(password), []byte(userID.String()), 16)
	userMacKey, err := userlib.HashKDF(rootkey, []byte("mac"))
	if err != nil {
		return nil, fmt.Errorf("error deriving mac key: %w", err)
	}
	var user User
	err = symAuthDec(encUserBytes, rootkey, userMacKey, &user)
	if err != nil {
		return nil, err
	}
	user.rootKey = rootkey
	return &user, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
