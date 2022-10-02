package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

// hashPassword takes a password string and returns a hash
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// checkPasswordHash compares a password to a hash and returns true if they
// match
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// parseToken takes a token string, checks its validity, and parses it into a
// set of credentials. If the token is invalid it returns an error
func parseToken(tokenString string) (*credentials, error) {
	var claims *credentials
	token, err := jwt.ParseWithClaims(tokenString, &credentials{}, func(token *jwt.Token) (interface{}, error) {
		return hmacSampleSecret, nil
	})
	if err != nil {
		fmt.Println(err)
		cc := credentials{IsLoggedIn: false}
		return &cc, err
	}

	if claims, ok := token.Claims.(*credentials); ok && token.Valid {
		return claims, nil
	}
	return claims, err
}

// renewToken renews a users token using existing claims, sets it as a cookie
// on the client, and adds it to the database.
// TODO: FIX EXPIRY
func renewToken(w http.ResponseWriter, r *http.Request, claims *credentials) (ctxx context.Context) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(hmacSampleSecret)
	if err != nil {
		fmt.Println(err)
	}

	expire := time.Now().Add(10 * time.Minute)
	cookie := http.Cookie{Name: "token", Value: ss, Path: "/", Expires: expire, MaxAge: 0}
	http.SetCookie(w, &cookie)

	rdb.Set(ctx, claims.Name+":token", ss, 0)
	ctxx = context.WithValue(r.Context(), ctxkey, claims)
	return
}

// newClaims creates a new set of claims using user credentials, and uses
// the claims to create a new token using renewToken()
func newClaims(w http.ResponseWriter, r *http.Request, c *credentials) (ctxx context.Context) {
	claims := credentials{
		c.Name,
		"",
		true,
		[]string{},
		0,
		jwt.StandardClaims{
			// ExpiresAt: 15000,
			// Issuer:    "test",
		},
	}

	return renewToken(w, r, &claims)
	// token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// ss, err := token.SignedString(hmacSampleSecret)
	// if err != nil {
	// 	fmt.Println(err)
	// }

	// expire := time.Now().Add(10 * time.Minute)
	// cookie := http.Cookie{Name: "token", Value: ss, Path: "/", Expires: expire, MaxAge: 0}
	// http.SetCookie(w, &cookie)

	// rdb.Set(ctx, c.Name+":token", ss, -1)
	// ctxx = context.WithValue(r.Context(), ctxkey, claims)
	// return
}

// genPostID generates a post ID
func genPostID(length int) (ID string) {
	symbols := "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	for i := 0; i <= length; i++ {
		s := rand.Intn(len(symbols))
		ID += symbols[s : s+1]
	}
	return
}

// marshalpostData is used convert a request body into a postData{} struct
func marshalpostData(r *http.Request) (*postData, error) {
	t := &postData{}
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()
	err := decoder.Decode(t)
	if err != nil {
		return t, err
	}
	return t, nil
}

func marshalPageData(r *http.Request) (*pageData, error) {
	t := &pageData{}
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()
	err := decoder.Decode(t)
	if err != nil {
		return t, err
	}
	return t, nil
}

// marshalCredentials is used convert a request body into a credentials{}
// struct
func marshalCredentials(r *http.Request) (*credentials, error) {
	t := &credentials{}
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()
	err := decoder.Decode(t)
	if err != nil {
		return t, err
	}
	return t, nil
}

// makePost takes data in the form of a map[string]string, and returns a
// *postData{} struct. Use withChildren to specify whether or not to also get
// the children. If withChildren is true, getChildren() will be run, which is
// a recursive function should only be run when necessary.
func makePost(data map[string]string, withChildren bool) *postData {
	var arr []string
	_ = json.Unmarshal([]byte(data["tags"]), &arr)
	if withChildren {
		return &postData{
			ID:       data["ID"],
			Title:    data["title"],
			Body:     template.HTML(data["body"]),
			Children: getChildren(data["ID"]),
			Parent:   data["parent"],
			TS:       data["created"],
			Author:   data["author"],
			Tags:     arr,
		}
	}
	return &postData{
		ID:       data["ID"],
		Title:    data["title"],
		Body:     template.HTML(data["body"]),
		Children: nil,
		Parent:   data["parent"],
		TS:       data["created"],
		Author:   data["author"],
		Tags:     arr,
	}
}

// removeDuplicateStr removes duplicate strings from a slice of strings
// [0] https://stackoverflow.com/questions/66643946/how-to-remove-duplicates-strings-or-int-from-slice-in-go
func removeDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		item = strings.ToLower(item)
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

// bytify is used to store tags in redis. Redis can't store a slice/array as
// a value to a key of a hash, and storing it as a JSON string comes out
// wonky(?), so we store it as a []byte and convert it to a slice using the
// JSON marshaler
func bytify(a any) ([]byte, error) {
	bTags, err := json.Marshal(a)
	if err != nil {
		fmt.Println(err)
		return bTags, err
	}

	return bTags, nil
}

// validateBody performs a sanity check on the post body. Currently it just
// makes sure the body is greater than two characters and less than 2500.
// TODO: Define the parameters of sanity (using regexp?)
func validateBody(s string) bool {
	l := len(s)
	if l > 2 && l < 2500 {
		return true
	}
	return false
}

// makePage returns a *pageData{} struct
func makePage() *pageData {
	return &pageData{
		Tags:        tags,
		DefaultTags: defaultTags,
		UserData:    &credentials{},
	}
}

// ajaxResponse is used to respond to ajax requests with arbitrary data in the
// format of map[string]string
func ajaxResponse(w http.ResponseWriter, res map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(res)
	if err != nil {
		log.Println(err)
	}
}

// exeTmpl is used to build and execute an html template.
func exeTmpl(w http.ResponseWriter, r *http.Request, page *pageData, tmpl string) {
	// Add the user data to the page if they're logged in.
	c := r.Context().Value(ctxkey)
	if a, ok := c.(*credentials); ok && a.IsLoggedIn {
		page.UserData = a

		err := templates.ExecuteTemplate(w, tmpl, page)
		if err != nil {
			fmt.Println(err)
		}
		return
	}

	err := templates.ExecuteTemplate(w, tmpl, page)
	if err != nil {
		fmt.Println(err)
	}
}

// handleErr is used for handling errors. It needs to be more robust.
// TODO: Add robustness
func handleErr(e error) {
	if e != nil {
		fmt.Println(e)
	}
}

func addToDB(post map[string]interface{}, authorName string, postID string) error {
	// TODO: Create database pipeline/reversal
	// Add the post to redis with "OBJECT:postID:author" as the key
	_, err := rdb.HMSet(ctx, "OBJECT:"+postID+":"+authorName, post).Result()
	if err != nil {
		return err
	}

	beginCache()

	return nil
}

// getChildren takes a postID, retrieves the replies, and returns them as a
// slice
func getChildren(ID string) (childs []*postData) {
	// get the postIDs of the children
	children, err := rdb.ZRevRange(ctx, ID+":CHILDREN", 0, -1).Result()
	if err != nil {
		fmt.Println(err)
	}

	// look up each postID to get the post data for the children
	for _, child := range children {
		data, err := rdb.HGetAll(ctx, "OBJECT:"+child).Result()
		if err != nil {
			fmt.Println(err)
		}

		// append the child to the comment tree
		childs = append(childs, makePost(data, true))
	}
	return
}
