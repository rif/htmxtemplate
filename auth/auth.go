package auth

import (
	"context"
	"crypto/sha1"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"templates/models"
	"time"

	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rif/cache2go"
	"golang.org/x/crypto/bcrypt"
)

var (
	sha1Hash = sha1.New()
)

func Sha1(attrs ...any) string {
	for _, attr := range attrs {
		if attr == nil {
			continue
		}
		sha1Hash.Write([]byte(attr.(string)))
	}
	defer sha1Hash.Reset()

	return fmt.Sprintf("%x", sha1Hash.Sum(nil))
}

const (
	CookieSession = "session"
	CookieSecret  = "aisiep0oongeiDaeCh7Yie3saPi0ciu4feiJoqu6woh6Xoopo4Ahx4ca6ga4shei"
	GroupAdmin    = "admin"
)

type AuthManager struct {
	cache *cache2go.Cache
	db    *pgxpool.Pool
	ctx   context.Context
	sync.RWMutex
}

func NewAuthManager(db *pgxpool.Pool) (*AuthManager, error) {
	am := &AuthManager{
		db:    db,
		cache: cache2go.New(1000, 60*time.Minute),
		ctx:   context.Background(),
	}
	if err := am.initAuth(); err != nil {
		return nil, err
	}

	return am, nil
}

func (am *AuthManager) GetKeyAuth(c echo.Context) string {
	authScheme := "Bearer"
	auth := c.Request().Header.Get(echo.HeaderAuthorization)
	if auth != "" {
		l := len(authScheme)
		if len(auth) > l+1 && auth[:l] == authScheme {
			return am.EmailForKey(auth[l+1:])
		}
	}
	return ""
}

func (am *AuthManager) initAuth() error {
	var userCount int
	if err := pgxscan.Get(am.ctx, am.db, &userCount, `SELECT count(*) FROM "user"`); err != nil {
		return fmt.Errorf("Failed to fetch: %v\n", err)
	}
	if userCount == 0 {
		hash, err := bcrypt.GenerateFromPassword([]byte("testus"), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		if _, err := am.db.Exec(am.ctx, `insert into "user"(id, email, hashed_password, "group") values ($1, $2, $3, $4)`, uuid.NewString(), "admin@mailinator.com", string(hash), GroupAdmin); err != nil {
			slog.Error(err.Error())
			return err
		}
	}
	return nil
}

func (am *AuthManager) EmailForKey(uuid string) string {
	am.RLock()
	defer am.RUnlock()
	if email, ok := am.cache.Get(uuid); ok {
		return email.(string)
	}
	var k models.Key
	if err := pgxscan.Get(
		am.ctx, am.db, &k, `SELECT * FROM key WHERE value=$1`, uuid,
	); err != nil {
		slog.Error("Failed to get key: " + err.Error())
	}
	if k.Email != "" {
		am.cache.Set(k.Value, k.Email)
	}
	return k.Email
}

func (am *AuthManager) AuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// check key first
		if email := am.GetKeyAuth(c); email != "" {
			c.Set("email", email)
			return next(c)
		}
		cookie, err := c.Cookie(CookieSession)
		if err != nil || cookie == nil {
			return c.Redirect(http.StatusFound, "/login")
		}
		s := models.Session{}
		if err := pgxscan.Get(
			am.ctx, am.db, &s, `SELECT * FROM key WHERE id=$1`, cookie.Value,
		); err != nil {
			return c.Redirect(http.StatusFound, "/login")
		}

		c.Set("email", s.Email)
		c.Set("group", s.Group)
		return next(c)
	}
}

func (am *AuthManager) AdminMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		group, ok := c.Get("group").(string)
		if !ok || group != GroupAdmin {
			slog.Warn("admin access", slog.String("email", c.Get("email").(string)), slog.String("group", c.Get("group").(string)))
			return c.NoContent(http.StatusForbidden)
		}
		return next(c)
	}
}

func (am *AuthManager) LoginHandler(c echo.Context) error {
	cookie, err := c.Cookie(CookieSession)
	if err == nil && cookie != nil {
		s := models.Session{}
		if err := pgxscan.Get(
			am.ctx, am.db, &s, `SELECT * FROM key WHERE id=$1`, cookie.Value,
		); err != nil {
			return c.Redirect(http.StatusFound, "/")
		}
	}
	return c.Render(http.StatusOK, "login", map[string]any{
		"CSRF": c.Get(middleware.DefaultCSRFConfig.ContextKey),
	})
}

func (am *AuthManager) LoginPostHandler(c echo.Context) error {
	email := c.FormValue("email")
	pass := c.FormValue("pass")

	u := models.User{}
	if err := pgxscan.Get(
		am.ctx, am.db, &u, fmt.Sprintf(`SELECT hashed_password, "group" FROM "user" WHERE email='%s'`, email),
	); err != nil {
		slog.Error(err.Error())
		return c.String(http.StatusForbidden, "tryagain")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.HashedPassword), []byte(pass)); err != nil {
		return c.String(http.StatusForbidden, "tryagain")
	}

	cookie := Sha1(CookieSecret, email, pass)

	c.SetCookie(&http.Cookie{
		Path:    "/",
		Name:    CookieSession,
		Value:   cookie,
		Expires: time.Now().Add(24 * 365 * 5 * time.Hour),
	})
	if _, err := am.db.Exec(am.ctx, `insert into "session" (id, email, "group") values ($1, $2, $3)`, cookie, email, u.Group); err != nil {
		slog.Error(err.Error())
		return err
	}
	return c.String(http.StatusOK, "OK")
}

func (am *AuthManager) LogoutHandler(c echo.Context) error {
	cookie, err := c.Cookie(CookieSession)
	if err != nil || cookie == nil {
		return c.Redirect(http.StatusFound, "/login")
	}
	if _, err := am.db.Exec(am.ctx, `delete from "session" where id=$1`, cookie.Value); err != nil {
		slog.Error(err.Error())
		return err
	}
	c.SetCookie(&http.Cookie{
		Path:    "/",
		Name:    CookieSession,
		Value:   "logout",
		Expires: time.Unix(0, 0),
	})

	return c.Redirect(http.StatusFound, "/login")
}

func (am *AuthManager) UsersHandler(c echo.Context) error {
	var users []*models.User
	if err := pgxscan.Select(
		am.ctx, am.db, &users, `SELECT id, "group", email FROM "user"`); err != nil {
			slog.Error("HERE", "err", err)

			return c.Redirect(http.StatusFound, "/")
		}

	block := "usersPage"
	if c.Request().Header.Get("Hx-Request") == "true" {
		block = "usersContainer"
	}
	return c.Render(http.StatusOK, block, map[string]any{
		"Name":"Users",
		"items": users,
	})
}

func (am *AuthManager) UserPostHandler(c echo.Context) error {
	u := new(models.User)
	if err := c.Bind(u); err != nil {
		return err
	}
	if strings.TrimSpace(u.HashedPassword) != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(u.HashedPassword), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		u.HashedPassword = string(hash)
	} else {
		// get previous password
		if u.ID != "" {
			oldUser := models.User{}
			if err := pgxscan.Get(am.ctx, am.db, &oldUser, fmt.Sprintf(`SELECT hashed_password FROM "user" WHERE id='%s'`, u.ID)); err == nil {
				u.HashedPassword = oldUser.HashedPassword
			}
		}
	}

	return c.NoContent(http.StatusOK)
}

func (am *AuthManager) UserDeleteHandler(c echo.Context) error {
	u := new(models.User)
	if err := c.Bind(u); err != nil {
		return err
	}
	if _, err := am.db.Exec(am.ctx, `delete from "user" where id=$1`, u.ID); err != nil {
		slog.Error(err.Error())
		return err
	}
	// delete associated keys
	if _, err := am.db.Exec(am.ctx, `delete from "key" where email=$1`, u.Email); err != nil {
		slog.Error(err.Error())
		return err
	}

	return c.NoContent(http.StatusOK)
}

func (am *AuthManager) KeysHandler(c echo.Context) error {
	am.RLock()
	defer am.RUnlock()
	var keys []*models.Key
	if err := pgxscan.Select(am.ctx, am.db, &keys, `SELECT email, "value", "description" FROM "key"`); err != nil {
		return nil
	}

	var users []*models.User
	if err := pgxscan.Select(
		am.ctx, am.db, &users, `SELECT id, "group", first_name, last_name, email FROM "user"`); err != nil {
		return nil
		}

	var emails []string
	for _, u := range users {
		emails = append(emails, u.Email)
	}
	response := map[string]any{
		"emails": emails,
		"keys":   keys,
	}
	return c.JSON(http.StatusOK, response)
}

func (am *AuthManager) KeyPostHandler(c echo.Context) error {
	am.Lock()
	defer am.Unlock()
	k := new(models.Key)
	if err := c.Bind(k); err != nil {
		return err
	}
	key := &models.Key{
		Email:       k.Email,
		Description: k.Description,
		Value:       uuid.NewString(),
	}

	am.cache.Set(key.Value, key.Email)
	if _, err := am.db.Exec(am.ctx, `insert into "key" (email, "value", description) values ($1, $2, $3)`, key.Email, key.Value, key.Description); err != nil {
		slog.Error(err.Error())
		return err
	}
	return c.String(http.StatusOK, key.Value)
}

func (am *AuthManager) KeyDeleteHandler(c echo.Context) error {
	am.Lock()
	defer am.Unlock()
	k := new(models.Key)
	if err := c.Bind(k); err != nil {
		return err
	}
	am.cache.Delete(k.Value)

	if _, err := am.db.Exec(am.ctx, `delete from "key" where email=$1`, k.Email); err != nil {
		slog.Error(err.Error())
		return err
	}
	return c.NoContent(http.StatusOK)
}

type Role struct {
	Name        string              `json:"name"`
	Permissions map[string][]string `json:"permissions"`
}
