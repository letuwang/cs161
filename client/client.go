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

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	"strconv"
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

type FileInfo struct {
	selfID      uuid.UUID
	Owner       string // owner's username
	Inviter     string // inviter's username
	AccessGroup string // the parent (of parent ...) of user that the owner directly shared the file with
	FileID      uuid.UUID
	FileKeyID   uuid.UUID // uuid of the file's FileKey
}

type FileKey struct {
	selfID uuid.UUID
	EncKey []byte // AES Key for encryption/decryption
	MacKey []byte // AES Key for MAC
}

type File struct {
	NumBlocks         int // number of FileBlocks associated with this file
	LastBlockID       uuid.UUID
	InvitationTableID uuid.UUID // uuid of the file's InvitationTable
}

type FileBlock struct {
	Data        []byte
	PrevBlockID uuid.UUID
}

// {B: [B's uuid, D's uuid, E's uuid, F's uuid], C: [C's uuid, G's uuid]}
type InvitationTable map[string][]uuid.UUID

func getUserID(username string) (uuid.UUID, error) {
	hash := userlib.Hash([]byte("User/" + username))
	id, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return uuid.Nil, fmt.Errorf("error determining User uuid: %w", err)
	}
	return id, nil
}

func authSymEnc(data any, encKey []byte, macKey []byte) ([]byte, error) {
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
	encUserBytes, err := authSymEnc(user, rootkey, userMacKey)
	if err != nil {
		return nil, fmt.Errorf("error encrypting user: %w", err)
	}
	userlib.DatastoreSet(id, encUserBytes)
	err = userlib.KeystoreSet(username+"/EncKey", encKey)
	if err != nil {
		return nil, fmt.Errorf("error storing encryption key: %w", err)
	}
	userlib.KeystoreSet(username+"/VerifyKey", verifyKey)
	if err != nil {
		return nil, fmt.Errorf("error storing verification key: %w", err)
	}
	return &user, nil
}

func authSymDec(encTaggedCipherText []byte, encKey []byte, macKey []byte, resultPtr any) (err error) {
	defer func() { // recover from potential panic from userlib.SymDec
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
	err = authSymDec(encUserBytes, rootkey, userMacKey, &user)
	if err != nil {
		return nil, err
	}
	user.rootKey = rootkey
	return &user, nil
}

func (user *User) getFileInfoID(filename string) (uuid.UUID, error) {
	hash := userlib.Hash([]byte("FileInfo/" + user.Username + filename))
	fileInfoID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return uuid.Nil, fmt.Errorf("error determining FileInfo uuid: %w", err)
	}
	return fileInfoID, nil
}

func authAsymEnc(data any, encKey userlib.PKEEncKey, signKey userlib.DSSignKey) ([]byte, error) {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("error marshalling data: %w", err)
	}
	ciphertext, err := userlib.PKEEnc(encKey, dataBytes)
	if err != nil {
		return nil, fmt.Errorf("error encrypting data: %w", err)
	}
	signature, err := userlib.DSSign(signKey, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("error signing ciphertext: %w", err)
	}
	result, err := json.Marshal(TaggedCipherText{ciphertext, signature})
	if err != nil {
		return nil, fmt.Errorf("error marshalling tagged ciphertext: %w", err)
	}
	return result, nil
}

func authAsymDec(encTaggedCipherText []byte, decKey userlib.PKEDecKey, verifyKey userlib.DSVerifyKey, resultPtr any) (err error) {
	var taggedCipherText TaggedCipherText
	err = json.Unmarshal(encTaggedCipherText, &taggedCipherText)
	if err != nil {
		return fmt.Errorf("error unmarshalling tagged ciphertext: %w", err)
	}
	err = userlib.DSVerify(verifyKey, taggedCipherText.CipherText, taggedCipherText.Tag)
	if err != nil {
		return fmt.Errorf("error verifying ciphertext signature: %w", err)
	}
	dataBytes, err := userlib.PKEDec(decKey, taggedCipherText.CipherText)
	if err != nil {
		return fmt.Errorf("error decrypting data: %w", err)
	}
	err = json.Unmarshal(dataBytes, resultPtr)
	if err != nil {
		return fmt.Errorf("error marshalling data: %w", err)
	}
	return nil
}

func (user *User) getFileInfoKeys(filename string) ([]byte, []byte, error) {
	encKey, err := userlib.HashKDF(user.rootKey, []byte(filename+"/encKey"))
	if err != nil {
		return nil, nil, fmt.Errorf("error deriving file info encryption key: %w", err)
	}
	macKey, err := userlib.HashKDF(user.rootKey, []byte(filename+"/macKey"))
	if err != nil {
		return nil, nil, fmt.Errorf("error deriving file info mac key: %w", err)
	}
	return encKey, macKey, nil
}

func (user *User) isFileExist(filename string) bool {
	fileInfoID, err := user.getFileInfoID(filename)
	if err != nil {
		return false
	}
	_, ok := userlib.DatastoreGet(fileInfoID)
	return ok
}

/* creates and stores to datastore a FileInfo struct, FileKey struct, File struct, and InvitationTable struct with all fields properly filled, except that File.LastBlockId is set to uuid.Nil; returns the File struct. Notes: *dangerously* assumes that the file does not already exist. */
func (user *User) createFile(filename string) (FileInfo, FileKey, File, error) {
	// new FileInfo struct
	fileInfoID, err := user.getFileInfoID(filename)
	if err != nil {
		return FileInfo{}, FileKey{}, File{}, err
	}
	fileID, err := uuid.NewRandom()
	if err != nil {
		return FileInfo{}, FileKey{}, File{}, fmt.Errorf("error generating File uuid: %w", err)
	}
	fileKeyID, err := uuid.NewRandom()
	if err != nil {
		return FileInfo{}, FileKey{}, File{}, fmt.Errorf("error generating FileKey uuid: %w", err)
	}
	fileInfo := FileInfo{fileInfoID, user.Username, user.Username, user.Username, fileID, fileKeyID}
	fileInfoEncKey, fileInfoMacKey, err := user.getFileInfoKeys(filename)
	if err != nil {
		return FileInfo{}, FileKey{}, File{}, err
	}
	encFileInfoBytes, err := authSymEnc(fileInfo, fileInfoEncKey, fileInfoMacKey)
	if err != nil {
		return FileInfo{}, FileKey{}, File{}, fmt.Errorf("error encrypting FileInfo: %w", err)
	}
	userlib.DatastoreSet(fileInfoID, encFileInfoBytes)

	// new FileKey struct
	fileEncKey := userlib.RandomBytes(16)
	fileMacKey := userlib.RandomBytes(16)
	fileKey := FileKey{fileKeyID, fileEncKey, fileMacKey}
	userEncKey, ok := userlib.KeystoreGet(user.Username + "/EncKey")
	if !ok {
		return FileInfo{}, FileKey{}, File{}, fmt.Errorf("error retrieving user encryption key")
	}
	encFileKeyBytes, err := authAsymEnc(fileKey, userEncKey, user.SignKey)
	if err != nil {
		return FileInfo{}, FileKey{}, File{}, fmt.Errorf("error encrypting FileKey: %w", err)
	}
	userlib.DatastoreSet(fileKeyID, encFileKeyBytes)

	// new File struct
	invitationTableID, err := uuid.NewRandom()
	if err != nil {
		return FileInfo{}, FileKey{}, File{}, fmt.Errorf("error generating invitation table uuid: %w", err)
	}
	file := File{0, uuid.Nil, invitationTableID}
	encFileBytes, err := authSymEnc(file, fileEncKey, fileMacKey)
	if err != nil {
		return FileInfo{}, FileKey{}, File{}, fmt.Errorf("error encrypting File: %w", err)
	}
	userlib.DatastoreSet(fileID, encFileBytes)

	// new InvitationTable struct
	invitationTable := InvitationTable{}
	invitationTableEncKey, err := userlib.HashKDF(fileEncKey, []byte("/InvitationTable"))
	if err != nil {
		return FileInfo{}, FileKey{}, File{}, fmt.Errorf("error deriving invitation table encryption key: %w", err)
	}
	invitationTableMacKey, err := userlib.HashKDF(fileMacKey, []byte("/InvitationTable"))
	if err != nil {
		return FileInfo{}, FileKey{}, File{}, fmt.Errorf("error deriving invitation table mac key: %w", err)
	}
	encInvitationTableBytes, err := authSymEnc(invitationTable, invitationTableEncKey, invitationTableMacKey)
	if err != nil {
		return FileInfo{}, FileKey{}, File{}, fmt.Errorf("error encrypting InvitationTable: %w", err)
	}
	userlib.DatastoreSet(invitationTableID, encInvitationTableBytes)
	return fileInfo, fileKey, file, nil
}

func (user *User) getFileStruct(filename string) (FileInfo, FileKey, File, error) {
	// get FileInfo struct
	fileInfoID, err := user.getFileInfoID(filename)
	if err != nil {
		return FileInfo{}, FileKey{}, File{}, err
	}
	encFileInfoBytes, ok := userlib.DatastoreGet(fileInfoID)
	if !ok {
		return FileInfo{}, FileKey{}, File{}, fmt.Errorf("file %s does not exist", filename)
	}
	fileInfoEncKey, fileInfoMacKey, err := user.getFileInfoKeys(filename)
	if err != nil {
		return FileInfo{}, FileKey{}, File{}, err
	}
	var fileInfo FileInfo
	err = authSymDec(encFileInfoBytes, fileInfoEncKey, fileInfoMacKey, &fileInfo)
	if err != nil {
		return FileInfo{}, FileKey{}, File{}, fmt.Errorf("error decrypting FileInfo: %w", err)
	}

	// get FileKey struct
	encFileKeyBytes, ok := userlib.DatastoreGet(fileInfo.FileKeyID)
	if !ok {
		return FileInfo{}, FileKey{}, File{}, fmt.Errorf("error retrieving file key")
	}
	inviterVerifyKey, ok := userlib.KeystoreGet(fileInfo.Inviter + "/VerifyKey")
	if !ok {
		return FileInfo{}, FileKey{}, File{}, fmt.Errorf("error retrieving inviter's verification key")
	}
	var fileKey FileKey
	err = authAsymDec(encFileKeyBytes, user.DecKey, inviterVerifyKey, &fileKey)
	if err != nil { // inviter did not sign FileKey -> owner signed FileKey OR something's wrong with FileKey
		ownerVerifyKey, ok := userlib.KeystoreGet(fileInfo.Owner + "/VerifyKey")
		if !ok {
			return FileInfo{}, FileKey{}, File{}, fmt.Errorf("error retrieving owner's verification key")
		}
		var fileKey FileKey
		err = authAsymDec(encFileKeyBytes, user.DecKey, ownerVerifyKey, &fileKey)
		if err != nil {
			// owner did not sign FileKey -> something's wrong with FileKey
			return FileInfo{}, FileKey{}, File{}, fmt.Errorf("error decrypting FileKey: %w", err)
		}
		if fileKey.selfID != fileInfo.FileKeyID {
			return FileInfo{}, FileKey{}, File{}, fmt.Errorf("error decrypting FileKey: FileKey.selfId does not match FileInfo.FileKeyId")
		}
	}

	// get File struct
	encFileBytes, ok := userlib.DatastoreGet(fileInfo.FileID)
	if !ok {
		return FileInfo{}, FileKey{}, File{}, fmt.Errorf("error retrieving file")
	}
	var file File
	err = authSymDec(encFileBytes, fileKey.EncKey, fileKey.MacKey, &file)
	if err != nil {
		return FileInfo{}, FileKey{}, File{}, fmt.Errorf("error decrypting File: %w", err)
	}
	return fileInfo, fileKey, file, nil
}

func (user *User) StoreFile(filename string, content []byte) (err error) {
	var (
		fileInfo FileInfo
		file     File
		fileKey  FileKey
	)
	if user.isFileExist(filename) {
		fileInfo, fileKey, file, err = user.getFileStruct(filename)
	} else {
		fileInfo, fileKey, file, err = user.createFile(filename)
	}
	if err != nil {
		return err
	}
	// new FileBlock struct
	fileBlock := FileBlock{content, uuid.Nil}
	fileBlockEncKey, err := userlib.HashKDF(fileKey.EncKey, []byte("/Block0"))
	if err != nil {
		return fmt.Errorf("error deriving FileBlock encryption key: %w", err)
	}
	fileBlockMacKey, err := userlib.HashKDF(fileKey.MacKey, []byte("/Block0"))
	if err != nil {
		return fmt.Errorf("error deriving FileBlock mac key: %w", err)
	}
	encFileBlockBytes, err := authSymEnc(fileBlock, fileBlockEncKey, fileBlockMacKey)
	if err != nil {
		return fmt.Errorf("error encrypting FileBlock: %w", err)
	}
	fileBlockId, err := uuid.NewRandom()
	if err != nil {
		return fmt.Errorf("error generating FileBlock uuid: %w", err)
	}
	userlib.DatastoreSet(fileBlockId, encFileBlockBytes)

	// update File struct
	file.NumBlocks = 1
	file.LastBlockID = fileBlockId
	encFileBytes, err := authSymEnc(file, fileKey.EncKey, fileKey.MacKey)
	if err != nil {
		return fmt.Errorf("error encrypting File: %w", err)
	}
	userlib.DatastoreSet(fileInfo.FileID, encFileBytes)

	return nil
}

func (user *User) AppendToFile(filename string, content []byte) error {
	fileInfo, fileKey, file, err := user.getFileStruct(filename)
	if err != nil {
		return err
	}

	// new FileBlock struct
	fileBlock := FileBlock{content, file.LastBlockID}
	fileBlockEncKey, err := userlib.HashKDF(fileKey.EncKey, []byte("/Block"+strconv.Itoa(file.NumBlocks)))
	if err != nil {
		return fmt.Errorf("error deriving FileBlock encryption key: %w", err)
	}
	fileBlockMacKey, err := userlib.HashKDF(fileKey.MacKey, []byte("/Block"+strconv.Itoa(file.NumBlocks)))
	if err != nil {
		return fmt.Errorf("error deriving FileBlock mac key: %w", err)
	}
	encFileBlockBytes, err := authSymEnc(fileBlock, fileBlockEncKey, fileBlockMacKey)
	if err != nil {
		return fmt.Errorf("error encrypting FileBlock: %w", err)
	}
	fileBlockId, err := uuid.NewRandom()
	if err != nil {
		return fmt.Errorf("error generating FileBlock uuid: %w", err)
	}
	userlib.DatastoreSet(fileBlockId, encFileBlockBytes)

	// update File struct
	file.NumBlocks++
	file.LastBlockID = fileBlockId
	encFileBytes, err := authSymEnc(file, fileKey.EncKey, fileKey.MacKey)
	if err != nil {
		return fmt.Errorf("error encrypting File: %w", err)
	}
	userlib.DatastoreSet(fileInfo.FileID, encFileBytes)

	return nil
}

func (user *User) LoadFile(filename string) ([]byte, error) {
	_, fileKey, file, err := user.getFileStruct(filename)
	if err != nil {
		return nil, fmt.Errorf("error retrieving File: %w", err)
	}

	var content []byte
	for blockIndex, blockID := file.NumBlocks-1, file.LastBlockID; blockID != uuid.Nil; {
		encFileBlockBytes, ok := userlib.DatastoreGet(blockID)
		if !ok {
			return nil, fmt.Errorf("error retrieving FileBlock %v", blockID)
		}
		fileBlockEncKey, err := userlib.HashKDF(fileKey.EncKey, []byte("/Block"+strconv.Itoa(blockIndex)))
		if err != nil {
			return nil, fmt.Errorf("error deriving FileBlock encryption key: %w", err)
		}
		fileBlockMacKey, err := userlib.HashKDF(fileKey.MacKey, []byte("/Block"+strconv.Itoa(blockIndex)))
		if err != nil {
			return nil, fmt.Errorf("error deriving FileBlock mac key: %w", err)
		}
		var fileBlock FileBlock
		err = authSymDec(encFileBlockBytes, fileBlockEncKey, fileBlockMacKey, &fileBlock)
		if err != nil {
			return nil, fmt.Errorf("error decrypting FileBlock: %w", err)
		}
		content = append(fileBlock.Data, content...)

		blockIndex--
		blockID = fileBlock.PrevBlockID
	}

	return content, nil
}

func authHybridEnc(data any, asymEncKey userlib.PKEEncKey, asymSignKey userlib.DSSignKey) ([]byte, error) {
	// symmetrically encrypt & authenticate data
	symKeys := userlib.RandomBytes(32)
	encDataBytes, err := authSymEnc(data, symKeys[:16], symKeys[16:])

	// asymmetrically encrypt symmetric keys
	encSymKeys, err := userlib.PKEEnc(asymEncKey, symKeys)
	if err != nil {
		return nil, fmt.Errorf("error encrypting symmetric keys: %w", err)
	}

	// sign ciphertext
	ciphertext := append(encSymKeys, encDataBytes...)
	tag, err := userlib.DSSign(asymSignKey, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("error signing ciphertext: %w", err)
	}

	result, err := json.Marshal(TaggedCipherText{ciphertext, tag})
	if err != nil {
		return nil, fmt.Errorf("error marshalling tagged ciphertext: %w", err)
	}
	return result, nil
}

func (user *User) CreateInvitation(filename string, recipientUsername string) (uuid.UUID, error) {
	fileInfo, fileKey, file, err := user.getFileStruct(filename)
	if err != nil {
		return uuid.Nil, err
	}

	// new FileKey struct for recipient
	recipientFileKeyID, err := uuid.NewRandom()
	if err != nil {
		return uuid.Nil, fmt.Errorf("error generating new FileKey uuid: %w", err)
	}
	recipientFileKey := FileKey{recipientFileKeyID, fileKey.EncKey, fileKey.MacKey}
	recipientEncKey, ok := userlib.KeystoreGet(recipientUsername + "/EncKey")
	if !ok {
		return uuid.Nil, fmt.Errorf("error retrieving recipient's encryption key")
	}
	encRecipientFileKeyBytes, err := authAsymEnc(recipientFileKey, recipientEncKey, user.SignKey)
	if err != nil {
		return uuid.Nil, fmt.Errorf("error encrypting recipient's FileKey: %w", err)
	}

	// new FileInfo struct for recipient
	recipientFileInfoID, err := uuid.NewRandom()
	if err != nil {
		return uuid.Nil, fmt.Errorf("error generating new Invitation uuid: %w", err)
	}
	var recipientAccessGroup string
	if fileInfo.Owner == user.Username {
		recipientAccessGroup = recipientUsername
	} else {
		recipientAccessGroup = fileInfo.AccessGroup
	}
	recipientFileInfo := FileInfo{recipientFileInfoID, fileInfo.Owner, user.Username, recipientAccessGroup, fileInfo.FileID, recipientFileKeyID}
	encRecipientFileInfoBytes, err := authHybridEnc(recipientFileInfo, recipientEncKey, user.SignKey)
	if err != nil {
		return uuid.Nil, fmt.Errorf("error encrypting recipient's FileInfo: %w", err)
	}

	// update InvitationTable struct
	invitationTableID := file.InvitationTableID
	encInvitationTableBytes, ok := userlib.DatastoreGet(invitationTableID)
	invitationTableEncKey, err := userlib.HashKDF(fileKey.EncKey, []byte("InvitationTable"))
	if err != nil {
		return uuid.Nil, fmt.Errorf("error deriving InvitationTable encryption key: %w", err)
	}
	invitationTableMacKey, err := userlib.HashKDF(fileKey.MacKey, []byte("InvitationTable"))
	if err != nil {
		return uuid.Nil, fmt.Errorf("error deriving InvitationTable mac key: %w", err)
	}
	var invitationTable InvitationTable
	err = authSymDec(encInvitationTableBytes, invitationTableEncKey, invitationTableMacKey, &invitationTable)
	if err != nil {
		return uuid.Nil, fmt.Errorf("error decrypting InvitationTable: %w", err)
	}
	if _, ok := invitationTable[user.Username]; ok {
		invitationTable[user.Username] = append(invitationTable[user.Username], recipientFileKeyID)
	} else {
		invitationTable[user.Username] = []uuid.UUID{recipientFileKeyID}
	}
	encInvitationTableBytes, err = authSymEnc(invitationTable, invitationTableEncKey, invitationTableMacKey)

	userlib.DatastoreSet(recipientFileKeyID, encRecipientFileKeyBytes)
	userlib.DatastoreSet(recipientFileInfoID, encRecipientFileInfoBytes)
	userlib.DatastoreSet(invitationTableID, encInvitationTableBytes)
	return recipientFileInfoID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
