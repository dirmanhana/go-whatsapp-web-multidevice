package chatstorage

import (
	"testing"
	"time"

	domainChatStorage "github.com/aldinokemal/go-whatsapp-web-multidevice/domains/chatstorage"
)

func TestUserAndTokenRoundTrip(t *testing.T) {
	repo := newTestSQLiteRepository(t)

	id, err := repo.CreateUser("alice", "", "hash-of-password")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if id == 0 {
		t.Fatal("expected non-zero user id")
	}

	user, err := repo.GetUserByUsername("alice")
	if err != nil {
		t.Fatalf("get user by username: %v", err)
	}
	if user == nil || user.ID != id || user.PasswordHash != "hash-of-password" {
		t.Fatalf("unexpected user: %+v", user)
	}

	// Case-insensitive username lookup
	user, err = repo.GetUserByUsername("ALICE")
	if err != nil || user == nil {
		t.Fatalf("case-insensitive lookup failed: user=%+v err=%v", user, err)
	}

	byID, err := repo.GetUserByID(id)
	if err != nil || byID == nil || byID.Username != "alice" {
		t.Fatalf("get user by id failed: user=%+v err=%v", byID, err)
	}

	// Duplicate username is rejected by the unique index
	if _, err := repo.CreateUser("alice", "", "other-hash"); err == nil {
		t.Fatal("expected duplicate username to fail")
	}

	// Tokens: only a non-expired token resolves the user
	deadHash := "deadbeef"
	if err := repo.CreateAuthToken(deadHash, id, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("create expired token: %v", err)
	}
	user, err = repo.GetUserByTokenHash(deadHash)
	if err != nil || user != nil {
		t.Fatalf("expired token must not resolve: user=%+v err=%v", user, err)
	}

	liveHash := "cafebabe"
	if err := repo.CreateAuthToken(liveHash, id, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create live token: %v", err)
	}
	user, err = repo.GetUserByTokenHash(liveHash)
	if err != nil || user == nil || user.ID != id {
		t.Fatalf("live token must resolve user: user=%+v err=%v", user, err)
	}

	// Delete revokes the token
	if err := repo.DeleteAuthToken(liveHash); err != nil {
		t.Fatalf("delete token: %v", err)
	}
	user, err = repo.GetUserByTokenHash(liveHash)
	if err != nil || user != nil {
		t.Fatalf("deleted token must not resolve: user=%+v err=%v", user, err)
	}
}

func TestDeleteExpiredAuthTokens(t *testing.T) {
	repo := newTestSQLiteRepository(t)

	id, err := repo.CreateUser("bob", "", "hash")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := repo.CreateAuthToken("expired-1", id, time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("create expired token: %v", err)
	}
	if err := repo.CreateAuthToken("live-1", id, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create live token: %v", err)
	}

	if err := repo.DeleteExpiredAuthTokens(); err != nil {
		t.Fatalf("delete expired tokens: %v", err)
	}

	if user, _ := repo.GetUserByTokenHash("expired-1"); user != nil {
		t.Fatal("expired token still resolves after cleanup")
	}
	if user, _ := repo.GetUserByTokenHash("live-1"); user == nil {
		t.Fatal("live token must survive cleanup")
	}
}

func TestListAndDeleteUserAuthTokens(t *testing.T) {
	repo := newTestSQLiteRepository(t)

	id, err := repo.CreateUser("erin", "", "hash")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Two live tokens and one expired token.
	base := time.Now().Add(-2 * time.Hour)
	for i, hash := range []string{"live-1", "live-2", "expired-3"} {
		expiresAt := time.Now().Add(time.Hour)
		if hash == "expired-3" {
			expiresAt = time.Now().Add(-time.Minute)
		}
		// Stagger created_at so the newest-first ordering is deterministic.
		if _, err := repo.db.Exec(`
			INSERT INTO auth_tokens (user_id, token_hash, expires_at, created_at)
			VALUES (?, ?, ?, ?)
		`, id, hash, expiresAt, base.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("insert token %s: %v", hash, err)
		}
	}

	tokens, err := repo.ListAuthTokens(id)
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	if len(tokens) != 3 {
		t.Fatalf("expected 3 tokens, got %d", len(tokens))
	}
	// Newest first (expired-3 was created last).
	if tokens[0].TokenHash != "expired-3" || tokens[2].TokenHash != "live-1" {
		t.Fatalf("expected newest-first ordering, got %+v", tokens)
	}
	if tokens[0].UserID != id || tokens[0].ID == 0 {
		t.Fatalf("unexpected token row: %+v", tokens[0])
	}

	// Listing is scoped per user: another user sees nothing.
	otherID, err := repo.CreateUser("frank", "", "hash")
	if err != nil {
		t.Fatalf("create other user: %v", err)
	}
	if tokens, err := repo.ListAuthTokens(otherID); err != nil || len(tokens) != 0 {
		t.Fatalf("expected no tokens for other user: len=%d err=%v", len(tokens), err)
	}

	// Revoke-all removes every token of the user.
	if err := repo.DeleteUserAuthTokens(id); err != nil {
		t.Fatalf("delete user tokens: %v", err)
	}
	for _, hash := range []string{"live-1", "live-2", "expired-3"} {
		if user, _ := repo.GetUserByTokenHash(hash); user != nil {
			t.Fatalf("token %s must not resolve after revoke-all", hash)
		}
	}
}

func TestAdminAndUserManagement(t *testing.T) {
	repo := newTestSQLiteRepository(t)

	// Fresh DB: zero users.
	count, err := repo.CountUsers()
	if err != nil || count != 0 {
		t.Fatalf("expected 0 users, got %d (err=%v)", count, err)
	}

	aliceID, err := repo.CreateUser("alice", "", "hash")
	if err != nil {
		t.Fatalf("create alice: %v", err)
	}
	if _, err := repo.CreateUser("bob", "", "hash"); err != nil {
		t.Fatalf("create bob: %v", err)
	}

	// Grant admin and verify the flag round-trips through every lookup.
	if err := repo.SetUserAdmin(aliceID, true); err != nil {
		t.Fatalf("set admin: %v", err)
	}
	alice, err := repo.GetUserByID(aliceID)
	if err != nil || alice == nil || !alice.IsAdmin {
		t.Fatalf("expected alice to be admin: user=%+v err=%v", alice, err)
	}
	if user, _ := repo.GetUserByUsername("alice"); user == nil || !user.IsAdmin {
		t.Fatal("admin flag must survive username lookup")
	}

	// Disable bob; the flag is visible via lookups.
	users, err := repo.ListUsers()
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	var bobID int64
	for _, user := range users {
		if user.Username == "bob" {
			bobID = user.ID
		}
	}
	if bobID == 0 {
		t.Fatal("bob not found in list")
	}
	if err := repo.SetUserDisabled(bobID, true); err != nil {
		t.Fatalf("disable bob: %v", err)
	}
	bob, err := repo.GetUserByID(bobID)
	if err != nil || bob == nil || !bob.Disabled {
		t.Fatalf("expected bob disabled: user=%+v err=%v", bob, err)
	}

	// ListUsers reports both flags.
	users, err = repo.ListUsers()
	if err != nil || len(users) != 2 {
		t.Fatalf("expected 2 users, got %d (err=%v)", len(users), err)
	}
	byName := map[string]domainChatStorage.User{}
	for _, user := range users {
		byName[user.Username] = user
	}
	if !byName["alice"].IsAdmin || byName["alice"].Disabled {
		t.Fatalf("unexpected alice flags: %+v", byName["alice"])
	}
	if byName["bob"].IsAdmin || !byName["bob"].Disabled {
		t.Fatalf("unexpected bob flags: %+v", byName["bob"])
	}

	// Re-enabling clears the flag.
	if err := repo.SetUserDisabled(bobID, false); err != nil {
		t.Fatalf("enable bob: %v", err)
	}
	if bob, _ := repo.GetUserByID(bobID); bob == nil || bob.Disabled {
		t.Fatal("bob must be enabled again")
	}
}

func TestUserEmailRoundTrip(t *testing.T) {
	repo := newTestSQLiteRepository(t)

	id, err := repo.CreateUser("alice", "alice@example.com", "hash")
	if err != nil {
		t.Fatalf("create user with email: %v", err)
	}

	// Email lookup is case-insensitive.
	user, err := repo.GetUserByEmail("ALICE@Example.COM")
	if err != nil || user == nil {
		t.Fatalf("email lookup failed: user=%+v err=%v", user, err)
	}
	if user.ID != id || user.Email != "alice@example.com" {
		t.Fatalf("unexpected user: %+v", user)
	}

	// The email survives every lookup path.
	for _, lookup := range []func() (*domainChatStorage.User, error){
		func() (*domainChatStorage.User, error) { return repo.GetUserByUsername("alice") },
		func() (*domainChatStorage.User, error) { return repo.GetUserByID(id) },
	} {
		u, err := lookup()
		if err != nil || u == nil {
			t.Fatalf("expected user, got %+v err=%v", u, err)
		}
		if u.Email != "alice@example.com" {
			t.Fatalf("expected email in user, got %+v", u)
		}
	}

	// Duplicate email is rejected by the partial unique index.
	if _, err := repo.CreateUser("alice2", "alice@example.com", "hash2"); err == nil {
		t.Fatal("expected duplicate email to fail")
	}

	// Empty email is the legacy default; multiple legacy users share it.
	if _, err := repo.CreateUser("bob", "", "hash"); err != nil {
		t.Fatalf("create legacy user: %v", err)
	}
	if user, _ := repo.GetUserByEmail(""); user != nil {
		t.Fatal("empty email must not resolve a user")
	}

	// ListUsers carries the email.
	users, err := repo.ListUsers()
	if err != nil || len(users) != 2 {
		t.Fatalf("expected 2 users, got %d (err=%v)", len(users), err)
	}
	emails := map[string]string{}
	for _, u := range users {
		emails[u.Username] = u.Email
	}
	if emails["alice"] != "alice@example.com" || emails["bob"] != "" {
		t.Fatalf("unexpected emails: %+v", emails)
	}
}

func TestDeviceOwnerClaim(t *testing.T) {
	repo := newTestSQLiteRepository(t)

	if err := repo.SaveDeviceRecord(&domainChatStorage.DeviceRecord{
		DeviceID:    "slot-1",
		DisplayName: "Slot 1",
	}); err != nil {
		t.Fatalf("save device record: %v", err)
	}

	userID, err := repo.CreateUser("carol", "", "hash")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Unclaimed slot can be claimed by the first user
	claimed, err := repo.SetDeviceOwner("slot-1", userID)
	if err != nil || !claimed {
		t.Fatalf("expected claim to succeed: claimed=%v err=%v", claimed, err)
	}
	if count, err := repo.CountUserDevices(userID); err != nil || count != 1 {
		t.Fatalf("expected 1 owned device, got %d (err=%v)", count, err)
	}

	// A second user cannot steal the claim
	otherID, err := repo.CreateUser("dave", "", "hash")
	if err != nil {
		t.Fatalf("create other user: %v", err)
	}
	claimed, err = repo.SetDeviceOwner("slot-1", otherID)
	if err != nil || claimed {
		t.Fatalf("expected claim by other user to fail: claimed=%v err=%v", claimed, err)
	}

	// The owning user can re-claim idempotently (no error)
	claimed, err = repo.SetDeviceOwner("slot-1", userID)
	if err != nil || !claimed {
		t.Fatalf("expected re-claim by owner to succeed: claimed=%v err=%v", claimed, err)
	}

	// Owner round-trips through the registry record
	rec, err := repo.GetDeviceRecord("slot-1")
	if err != nil || rec == nil || rec.OwnerUserID != userID {
		t.Fatalf("expected record owner %d, got %+v (err=%v)", userID, rec, err)
	}

	// SaveDeviceRecord without an owner preserves the existing claim
	if err := repo.SaveDeviceRecord(&domainChatStorage.DeviceRecord{
		DeviceID:    "slot-1",
		DisplayName: "Slot 1 renamed",
	}); err != nil {
		t.Fatalf("save record without owner: %v", err)
	}
	rec, err = repo.GetDeviceRecord("slot-1")
	if err != nil || rec == nil || rec.OwnerUserID != userID {
		t.Fatalf("owner must survive ownerless update, got %+v (err=%v)", rec, err)
	}

	// Count scopes per user
	if count, err := repo.CountUserDevices(otherID); err != nil || count != 0 {
		t.Fatalf("expected other user to own 0 devices, got %d (err=%v)", count, err)
	}
}