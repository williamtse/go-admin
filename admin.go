// Auth example is an example application which requires a login
// to view a private link. The username is "testuser" and the password
// is "password". This will require GORP and an SQLite3 database.
package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"

	"crypto/md5"

	"encoding/hex"
	"math/rand"
	"time"

	"github.com/coopernurse/gorp"
	"github.com/go-martini/martini"
	"github.com/martini-contrib/binding"
	"github.com/martini-contrib/render"
	"github.com/martini-contrib/sessionauth"
	"github.com/martini-contrib/sessions"
)

var dbmap *gorp.DbMap

func initDb() *gorp.DbMap {
	// Delete our SQLite database if it already exists so we have a clean start
	db, err := sql.Open("mysql", "root:@tcp(localhost:3306)/martini_blog")

	if err != nil {
		log.Fatalln("Fail to connect to database", err)
	}

	dbmap := &gorp.DbMap{Db: db, Dialect: gorp.MySQLDialect{"InnoDB", "UTF8"}}
	dbmap.AddTableWithName(MyUserModel{}, "users").SetKeys(true, "Id")
	err = dbmap.CreateTablesIfNotExists()
	if err != nil {
		log.Fatalln("Could not build tables", err)
	}
	user := MyUserModel{}
	err = dbmap.SelectOne(&user, "SELECT * FROM users limit 1")
	if err != nil {
		uname := "xwengf"
		pwd := "51329017"
		salt := GetRandomSalt()
		dk := MD5(uname + pwd + salt)
		user := MyUserModel{1, "xwengf", dk, salt, false}
		err = dbmap.Insert(&user)
		if err != nil {
			log.Fatalln("Could not insert test user", err)
		}
	}
	return dbmap
}

func main() {
	store := sessions.NewCookieStore([]byte("secret123"))
	dbmap = initDb()

	m := martini.Classic()
	m.Use(render.Renderer())
	m.Use(martini.Static("assets"))
	// Default our store to use Session cookies, so we don't leave logged in
	// users roaming around
	store.Options(sessions.Options{
		MaxAge: 0,
	})
	m.Use(sessions.Sessions("my_session", store))
	m.Use(sessionauth.SessionUser(GenerateAnonymousUser))
	sessionauth.RedirectUrl = "/new-login"
	sessionauth.RedirectParam = "new-next"

	m.Get("/", sessionauth.LoginRequired, func(r render.Render) {
		r.HTML(200, "index", nil)
	})

	m.Get("/new-login", func(r render.Render) {
		r.HTML(200, "login", nil)
	})

	m.Post("/new-login", binding.Bind(MyUserModel{}), func(session sessions.Session, postedUser MyUserModel, r render.Render, req *http.Request) {
		// You should verify credentials against a database or some other mechanism at this point.
		// Then you can authenticate this session.
		user := MyUserModel{}

		err := dbmap.SelectOne(&user, "SELECT * FROM users WHERE username = ? limit 1", postedUser.Username)
		if err != nil {

			r.Redirect(sessionauth.RedirectUrl)
			return

		} else {
			salt := user.Salt
			pwd := MD5(postedUser.Username + postedUser.Password + salt)
			if pwd == user.Password {
				fmt.Println("pass")
				err := sessionauth.AuthenticateSession(session, &user)
				if err != nil {
					fmt.Println("authenticate failed")
					r.JSON(500, err)
				}

				params := req.URL.Query()
				redirect := params.Get(sessionauth.RedirectParam)
				r.Redirect(redirect)
				return
			} else {
				fmt.Println("not pass")
				r.Redirect(sessionauth.RedirectUrl)
				return
			}

		}
	})

	m.Get("/private", sessionauth.LoginRequired, func(r render.Render, user sessionauth.User) {
		r.HTML(200, "private", user.(*MyUserModel))
	})

	m.Get("/logout", sessionauth.LoginRequired, func(session sessions.Session, user sessionauth.User, r render.Render) {
		sessionauth.Logout(session, user)
		r.Redirect("/")
	})

	m.Run()
}
func GetRandomSalt() string {
	return GetRandomString(8)
}

// 生成32位MD5
func MD5(text string) string {
	ctx := md5.New()
	ctx.Write([]byte(text))
	return hex.EncodeToString(ctx.Sum(nil))
}

//生成随机字符串
func GetRandomString(leng int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	bytes := []byte(str)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < leng; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return string(result)
}
