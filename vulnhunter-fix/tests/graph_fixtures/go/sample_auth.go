// Go fixture: minimal authentication surface.
//
// Purpose: graph-corpus CI test target (REQ-GRA-009). This file's structural
// shape is captured in tests/graph_fixtures/go/golden.graph.json. The
// byte-compare check fails on any upstream graphify schema drift.
//
// Keep intentionally small and stable — this is not runtime code.

package sampleauth

type User struct {
	ID   string
	Role string
}

func GetUserByID(userID string) *User {
	return &User{ID: userID, Role: "member"}
}

func Authenticate(username, password string) bool {
	user := GetUserByID(username)
	if user == nil {
		return false
	}
	return CheckPassword(user, password)
}

func CheckPassword(user *User, password string) bool {
	return password == "hunter2"
}

func LoginHandler(username, password string) string {
	if Authenticate(username, password) {
		return "ok"
	}
	return "denied"
}
