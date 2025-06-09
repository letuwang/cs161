package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const passwordOne = "password"
const passwordTwo = "password2"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// user declarations
	var alice *client.User
	var bob *client.User
	var charles *client.User
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var hank *client.User
	// var ian *client.User
	// var jack *client.User
	// var kate *client.User
	// var larry *client.User
	// var mary *client.User
	// var nancy *client.User
	// var oscar *client.User
	var currentContent []byte
	var userMap map[string]*client.User
	var invitationMap map[string]userlib.UUID

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	dorisFile := "dorisFile.txt"
	eveFile := "eveFile.txt"
	frankFile := "frankFile.txt"
	graceFile := "graceFile.txt"
	hankFile := "hankFile.txt"
	ianFile := "ianFile.txt"
	jackFile := "jackFile.txt"
	kateFile := "kateFile.txt"
	larryFile := "larryFile.txt"
	maryFile := "maryFile.txt"
	nancyFile := "nancyFile.txt"
	oscarFile := "oscarFile.txt"

	Describe("Basic Tests", func() {
		BeforeEach(func() {
			userlib.DatastoreClear()
			userlib.KeystoreClear()
		})

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", passwordOne)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", passwordOne)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", passwordOne)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", passwordOne)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", passwordOne)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", passwordOne)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", passwordOne)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", passwordOne)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", passwordOne)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", passwordOne)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})

	Describe("Functionality Tests: InitUser/GetUser", func() {
		BeforeEach(func() {
			userlib.DatastoreClear()
			userlib.KeystoreClear()
		})

		Specify("InitUser: Testing empty username", func() {
			_, err = client.InitUser(emptyString, passwordOne)
			Expect(err).ToNot(BeNil())
		})

		Specify("InitUser: Testing duplicate username", func() {
			_, err = client.InitUser("alice", passwordOne)
			Expect(err).To(BeNil())
			_, err = client.InitUser("alice", passwordOne)
			Expect(err).ToNot(BeNil())
			_, err = client.InitUser("alice", passwordTwo)
			Expect(err).ToNot(BeNil())
		})

		Specify("InitUser: testing username is case sensitive", func() {
			_, err = client.InitUser("alice", passwordOne)
			Expect(err).To(BeNil())
			_, err = client.InitUser("Alice", passwordTwo)
			Expect(err).To(BeNil())
		})

		Specify("InitUser: Testing empty password", func() {
			_, err = client.InitUser("alice", emptyString)
			Expect(err).To(BeNil())
			_, err = client.GetUser("alice", emptyString)
			Expect(err).To(BeNil())
		})

		Specify("GetUser: testing non-existent user", func() {
			_, err = client.GetUser("alice", passwordOne)
			Expect(err).ToNot(BeNil())
		})

		Specify("GetUser: testing incorrect password", func() {
			_, err = client.InitUser("alice", passwordOne)
			Expect(err).To(BeNil())
			_, err = client.GetUser("alice", passwordTwo)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Functionality Tests: StoreFile/LoadFile/AppendToFile", func() {
		BeforeEach(func() {
			userlib.DatastoreClear()
			userlib.KeystoreClear()
		})

		Specify("StoreFile: Testing empty filename", func() {
			alice, err = client.InitUser("alice", passwordOne)
			Expect(err).To(BeNil())
			err = alice.StoreFile(emptyString, []byte(contentOne))
			Expect(err).To(BeNil())
			retrievedContent, err := alice.LoadFile(emptyString)
			Expect(err).To(BeNil())
			Expect(retrievedContent).To(Equal([]byte(contentOne)))
		})

		Specify("StoreFile: Testing empty content", func() {
			alice, err = client.InitUser("alice", passwordOne)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(emptyString))
			Expect(err).To(BeNil())
			retrievedContent, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(retrievedContent).To(Equal([]byte(emptyString)))
		})

		Specify("StoreFile: Testing empty filename and content", func() {
			alice, err = client.InitUser("alice", passwordOne)
			Expect(err).To(BeNil())
			err = alice.StoreFile(emptyString, []byte(emptyString))
			Expect(err).To(BeNil())
			retrievedContent, err := alice.LoadFile(emptyString)
			Expect(err).To(BeNil())
			Expect(retrievedContent).To(Equal([]byte(emptyString)))
		})

		Specify("StoreFile: Testing overwriting file", func() {
			alice, err = client.InitUser("alice", passwordOne)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			retrievedContent, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(retrievedContent).To(Equal([]byte(contentTwo)))
		})

		Specify("StoreFile: testing different users storing files with same name", func() {
			alice, err = client.InitUser("alice", passwordOne)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", passwordOne)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			err = bob.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			aliceContent, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(aliceContent).To(Equal([]byte(contentOne)))
			bobContent, err := bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(bobContent).To(Equal([]byte(contentTwo)))
		})

		Specify("LoadFile: testing non-existent file", func() {
			alice, err = client.InitUser("alice", passwordOne)
			Expect(err).To(BeNil())
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("AppendToFile: testing normal append", func() {
			alice, err = client.InitUser("alice", passwordOne)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			retrievedContent, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(retrievedContent).To(Equal([]byte(contentOne + contentTwo)))
		})
	})

	Describe("Functionality Tests: Share/Receive File", func() {
		BeforeEach(func() {
			userlib.DatastoreClear()
			userlib.KeystoreClear()
		})

		Specify("CreateInvitation: non-existent file", func() {
			alice, err = client.InitUser("alice", passwordOne)
			Expect(err).To(BeNil())
			_, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("CreateInvitation: non-existent user", func() {
			alice, err = client.InitUser("alice", passwordOne)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			_, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("AcceptInvitation: file already exist", func() {
			alice, err = client.InitUser("alice", passwordOne)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", passwordOne)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			invitation, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			bob.StoreFile(bobFile, []byte(contentTwo))
			err = bob.AcceptInvitation("alice", invitation, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("AcceptInvitation: wrong sender", func() {
			alice, err = client.InitUser("alice", passwordOne)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", passwordOne)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			invitation, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("Alice", invitation, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("AcceptInvitation: non-existent invitation", func() {
			alice, err = client.InitUser("alice", passwordOne)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", passwordOne)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			invitation, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DatastoreDelete(invitation)
			err = bob.AcceptInvitation("alice", invitation, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("AcceptInvitation: wrong receiver", func() {
			alice, err = client.InitUser("alice", passwordOne)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", passwordOne)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			invitation, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", passwordOne)
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("alice", invitation, charlesFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("RevokeAccess: revoke before accept", func() {
			alice, err = client.InitUser("alice", passwordOne)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", passwordOne)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			invitation, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invitation, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("RevokeAccess: revoke after accept", func() {
			alice, err = client.InitUser("alice", passwordOne)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", passwordOne)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			invitation, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invitation, bobFile)
			Expect(err).To(BeNil())
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})

	Specify("Complete Test: share/receive file", func() {
		userMap = make(map[string]*client.User)
		invitationMap = make(map[string]userlib.UUID)

		for _, username := range []string{"alice", "bob", "charles", "doris", "eve", "frank", "grace", "hank", "ian", "jack", "kate", "larry", "mary", "nancy", "oscar"} {
			userlib.DebugMsg("initializing user: " + username)
			user, err := client.InitUser(username, passwordOne)
			Expect(err).To(BeNil())
			userMap[username] = user
		}

		userlib.DebugMsg("alice storing file")
		alice = userMap["alice"]
		err = alice.StoreFile(aliceFile, []byte(contentOne))
		Expect(err).To(BeNil())
		currentContent = []byte(contentOne)

		By("creating invitation recipient should not have access to file until recipient accepts invitation")
		for _, v := range [][]any{
			{"alice", aliceFile, "bob", bobFile},
			{"alice", aliceFile, "charles", charlesFile},
			{"bob", bobFile, "doris", dorisFile},
			{"bob", bobFile, "eve", eveFile},
			{"doris", dorisFile, "frank", frankFile},
			{"charles", charlesFile, "grace", graceFile},
			{"grace", graceFile, "hank", emptyString},
			{"charles", charlesFile, "ian", emptyString},
			{"doris", dorisFile, "jack", emptyString},
			{"bob", bobFile, "kate", emptyString},
			{"alice", aliceFile, "larry", emptyString},
			{"eve", eveFile, "mary", maryFile},
			{"grace", graceFile, "mary", emptyString},
			{"eve", eveFile, "nancy", emptyString},
			{"grace", graceFile, "nancy", nancyFile},
			{"eve", eveFile, "oscar", emptyString},
			{"grace", graceFile, "oscar", emptyString},
		} {
			senderName := v[0].(string)
			senderFilename := v[1].(string)
			recipientName := v[2].(string)
			recipientFilename := v[3].(string)

			userlib.DebugMsg("creating invitation: " + senderName + " -> " + recipientName)
			sender, ok := userMap[senderName]
			Expect(ok).To(BeTrue())
			recipient, ok := userMap[recipientName]
			Expect(ok).To(BeTrue())
			invitation, err := sender.CreateInvitation(senderFilename, recipientName)
			Expect(err).To(BeNil())
			Expect(invitation).ToNot(BeNil())
			invitationMap[senderName+"->"+recipientName] = invitation

			if recipientFilename == emptyString { // recipient is not accepting invitation
				userlib.DebugMsg("test " + recipientName + " cannot load file")
				_, err = recipient.LoadFile(recipientFilename)
				Expect(err).ToNot(BeNil())

				userlib.DebugMsg("test " + recipientName + " cannot append to file")
				err = recipient.AppendToFile(recipientFilename, []byte(contentTwo))
				Expect(err).ToNot(BeNil())
				content, err := alice.LoadFile(aliceFile)
				Expect(err).To(BeNil())
				Expect(content).To(Equal(currentContent))

				userlib.DebugMsg("test " + recipientName + " cannot create invitation")
				_, err = recipient.CreateInvitation(recipientFilename, "alice")
				Expect(err).ToNot(BeNil())
			} else {
				userlib.DebugMsg(recipientName + " accepting invitation")
				err = recipient.AcceptInvitation(senderName, invitation, recipientFilename)
				Expect(err).To(BeNil())

				userlib.DebugMsg("test " + recipientName + " can load file")
				content, err := recipient.LoadFile(recipientFilename)
				Expect(err).To(BeNil())
				Expect(content).To(Equal(currentContent))

				userlib.DebugMsg("test " + recipientName + " can overwrite file")
				err = recipient.StoreFile(recipientFilename, []byte(contentTwo))
				Expect(err).To(BeNil())
				currentContent = []byte(contentTwo)
				content, err = recipient.LoadFile(recipientFilename)
				Expect(err).To(BeNil())
				Expect(content).To(Equal(currentContent))

				userlib.DebugMsg("test " + recipientName + " can append to file")
				err = recipient.AppendToFile(recipientFilename, []byte(contentTwo))
				Expect(err).To(BeNil())
				currentContent = append(currentContent, []byte(contentTwo)...)
				content, err = recipient.LoadFile(recipientFilename)
				Expect(err).To(BeNil())
				Expect(content).To(Equal(currentContent))
			}
		}

		By("revoking access of Bob")
		userlib.DebugMsg("alice revoking access of bob")
		err := alice.RevokeAccess(aliceFile, "bob")
		Expect(err).To(BeNil())

		By("everyone in the same access group who accepted invitation should no longer have access to file")
		for _, v := range [][]any{
			{"bob", bobFile},
			{"doris", dorisFile},
			{"eve", eveFile},
			{"frank", frankFile},
			{"mary", maryFile},
		} {
			username := v[0].(string)
			filename := v[1].(string)

			user, ok := userMap[username]
			Expect(ok).To(BeTrue())

			userlib.DebugMsg("test " + username + " cannot load file")
			_, err := user.LoadFile(filename)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("test " + username + " cannot append to file")
			err = user.AppendToFile(filename, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
			content, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal(currentContent))

			userlib.DebugMsg("test " + username + " cannot create invitation")
			_, err = user.CreateInvitation(filename, "alice")
			Expect(err).ToNot(BeNil())
		}

		By("everyone in the same access group who did not accept invitation should not be able to accept invitation")
		for _, v := range [][]any{
			{"doris", "jack", jackFile},
			{"bob", "kate", kateFile},
			{"eve", "oscar", oscarFile},
		} {
			senderName := v[0].(string)
			username := v[1].(string)
			filename := v[2].(string)

			user, ok := userMap[username]
			Expect(ok).To(BeTrue())
			invitation, ok := invitationMap[senderName+"->"+username]
			Expect(ok).To(BeTrue())

			userlib.DebugMsg("test " + username + " cannot accept invitation from " + senderName)
			err := user.AcceptInvitation(senderName, invitation, filename)
			Expect(err).ToNot(BeNil())
		}

		By("everyone NOT in the same access group who accepted invitation should still have access to file")
		for _, v := range [][]any{
			{"alice", aliceFile},
			{"charles", charlesFile},
			{"grace", graceFile},
			{"nancy", nancyFile},
		} {
			username := v[0].(string)
			filename := v[1].(string)

			user, ok := userMap[username]
			Expect(ok).To(BeTrue())

			userlib.DebugMsg("test " + username + " can load file")
			content, err := user.LoadFile(filename)
			Expect(err).To(BeNil())
			Expect(content).To(Equal(currentContent))

			userlib.DebugMsg("test " + username + " can overwrite file")
			err = user.StoreFile(filename, []byte(contentTwo))
			Expect(err).To(BeNil())
			currentContent = []byte(contentTwo)
			content, err = user.LoadFile(filename)
			Expect(err).To(BeNil())
			Expect(content).To(Equal(currentContent))

			userlib.DebugMsg("test " + username + " can append to file")
			err = user.AppendToFile(filename, []byte(contentTwo))
			Expect(err).To(BeNil())
			currentContent = append(currentContent, []byte(contentTwo)...)
			content, err = user.LoadFile(filename)
			Expect(err).To(BeNil())
			Expect(content).To(Equal(currentContent))
		}

		By("everyone NOT in the same access group who did not accept invitation should still be able to accept invitation")
		for _, v := range [][]any{
			{"grace", "hank", hankFile},
			{"charles", "ian", ianFile},
			{"alice", "larry", larryFile},
			{"grace", "mary", maryFile},
			{"grace", "oscar", oscarFile},
		} {
			senderName := v[0].(string)
			username := v[1].(string)
			filename := v[2].(string)

			user, ok := userMap[username]
			Expect(ok).To(BeTrue())
			invitation, ok := invitationMap[senderName+"->"+username]
			Expect(ok).To(BeTrue())

			userlib.DebugMsg("test " + username + " can accept invitation from " + senderName)
			err := user.AcceptInvitation(senderName, invitation, filename)
			Expect(err).To(BeNil())

			userlib.DebugMsg("test " + username + " can load file")
			content, err := user.LoadFile(filename)
			Expect(err).To(BeNil())
			Expect(content).To(Equal(currentContent))

			userlib.DebugMsg("test " + username + " can overwrite file")
			err = user.StoreFile(filename, []byte(contentTwo))
			Expect(err).To(BeNil())
			currentContent = []byte(contentTwo)
			content, err = user.LoadFile(filename)
			Expect(err).To(BeNil())
			Expect(content).To(Equal(currentContent))

			userlib.DebugMsg("test " + username + " can append to file")
			err = user.AppendToFile(filename, []byte(contentTwo))
			Expect(err).To(BeNil())
			currentContent = append(currentContent, []byte(contentTwo)...)
			content, err = user.LoadFile(filename)
			Expect(err).To(BeNil())
			Expect(content).To(Equal(currentContent))
		}
	})

	Describe("Security Tests", func() {
		JustBeforeEach(func() {
			alice, err = client.InitUser("alice", passwordOne)
			Expect(err).To(BeNil())
		})

		It("should not be able to load file with tampered metadata", func() {
			oldDatastore := make(map[userlib.UUID][]byte)
			for k, v := range userlib.DatastoreGetMap() {
				oldDatastore[k] = v
			}

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			// tamper data
			for k, v := range userlib.DatastoreGetMap() {
				if _, ok := oldDatastore[k]; !ok {
					v = append(v, []byte("tampered")...)
					userlib.DatastoreSet(k, v)
				}
			}

			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		PDescribeTable("should not load the wrong file if two files are swapped", func() {
			oldDatastore := make(map[userlib.UUID][]byte)
			for k, v := range userlib.DatastoreGetMap() {
				oldDatastore[k] = v
			}

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			file1Entries := make(map[userlib.UUID][]byte)
			for k, v := range userlib.DatastoreGetMap() {
				if _, ok := oldDatastore[k]; !ok {
					file1Entries[k] = v
					oldDatastore[k] = v
				}
			}

			err = alice.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			file2Entries := make(map[userlib.UUID][]byte)
			for k, v := range userlib.DatastoreGetMap() {
				if _, ok := oldDatastore[k]; !ok {
					file2Entries[k] = v
				}
			}

			// swap entries

		})

		It("should error but not panic if try to decrypt ciphertext shorter than one aes block", func() {
			datastore := userlib.DatastoreGetMap()
			for k := range datastore {
				userlib.DatastoreSet(k, []byte("A"))
			}
			_, err := client.GetUser("alice", passwordOne)
			Expect(err).ToNot(BeNil())
		})

		It("should detect swapped appendToFile entries", func() {
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			oldDatastore := make(map[userlib.UUID][]byte)
			for k, v := range userlib.DatastoreGetMap() {
				oldDatastore[k] = v
			}

			err = alice.AppendToFile(aliceFile, []byte(contentTwo))

			firstEntries := make(map[userlib.UUID][]byte)
			for k, v := range userlib.DatastoreGetMap() {
				if _, ok := oldDatastore[k]; !ok {
					firstEntries[k] = v
					oldDatastore[k] = v
				}
			}

			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			secondEntries := make(map[userlib.UUID][]byte)
			for k, v := range userlib.DatastoreGetMap() {
				if _, ok := oldDatastore[k]; !ok {
					secondEntries[k] = v
				}
			}

			// swap entries
			for k, v := range firstEntries {
				for k2, v2 := range secondEntries {
					userlib.DatastoreSet(k, v2)
					userlib.DatastoreSet(k2, v)
					return
				}
			}

			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})
	})
})
