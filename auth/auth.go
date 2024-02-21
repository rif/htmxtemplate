package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"templates/models"
	"time"

	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/rif/cache2go"
	"golang.org/x/crypto/bcrypt"
)

const (
	CookieSession   = "session"
	CookieSecret    = "aisiep0oongeiDaeCh7Yie3saPi0ciu4feiJoqu6woh6Xoopo4Ahx4ca6ga4shei"
	GroupAdmin      = "admin"
	GroupInfluencer = "influencer"
	GroupSeamstress = "seamstress"
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
		if _, err := am.db.Exec(am.ctx, `insert into "user"(email, hashed_password, group) values ($1, $2, $3)`, "admin@mailinator.com", string(hash), GroupAdmin); err != nil {
			return err
		} else {
			slog.Info("CMD: ")
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

/*func (am *AuthManager) AdminMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		group, ok := c.Get("group").(string)
		if !ok || group != GroupAdmin {
			log.Warn().Interface("email", c.Get("email")).Interface("group", c.Get("group")).Msg("admin access")
			return c.NoContent(http.StatusForbidden)
		}
		return next(c)
	}
}

func (am *AuthManager) InfluencerMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		group, ok := c.Get("group").(string)
		if !ok || (group != GroupInfluencer && group != GroupAdmin) {
			log.Warn().Interface("email", c.Get("email")).Interface("group", c.Get("group")).Msg("influencer access")
			return c.NoContent(http.StatusForbidden)
		}
		return next(c)
	}
}

func (am *AuthManager) LoginHandler(c echo.Context) error {
	cookie, err := c.Cookie(CookieSession)
	if err == nil && cookie != nil {
		s := Session{}
		if err := am.db.One("Key", cookie.Value, &s); err == nil {
			return c.Redirect(http.StatusFound, "/")
		}
	}
	return c.Render(http.StatusOK, "login", map[string]interface{}{
		"CSRF": c.Get(middleware.DefaultCSRFConfig.ContextKey),
	})
}

func (am *AuthManager) LoginPostHandler(c echo.Context) error {
	credentials := struct {
		Email string `json:"email"`
		Pass  string `json:"pass"`
	}{}
	if err := c.Bind(&credentials); err != nil {
		return err
	}
	u := User{}
	if err := am.db.One("Email", credentials.Email, &u); err != nil {
		return c.String(http.StatusForbidden, "tryagain")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(credentials.Pass)); err != nil {
		return c.String(http.StatusForbidden, "tryagain")
	}

	cookie := Sha1(CookieSecret, credentials.Email, credentials.Pass)

	c.SetCookie(&http.Cookie{
		Path:    "/",
		Name:    CookieSession,
		Value:   cookie,
		Expires: time.Now().Add(24 * 365 * 5 * time.Hour),
	})
	am.db.Save(&Session{
		Key:   cookie,
		Email: credentials.Email,
		Group: u.Group,
		Code:  u.InfluencerCode,
	})
	return c.String(http.StatusOK, "OK")
}

func (am *AuthManager) LogoutHandler(c echo.Context) error {
	cookie, err := c.Cookie(CookieSession)
	if err != nil || cookie == nil {
		return c.Redirect(http.StatusFound, "/login")
	}
	if err := am.db.DeleteStruct(&Session{Key: cookie.Value}); err != nil {
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
	var users []*User
	if err := am.db.All(&users); err != nil {
		return err
	}

	for _, user := range users {
		user.Password = ""
	}
	response := map[string]interface{}{
		"items": users,
	}
	return c.JSON(http.StatusOK, response)
}

func (am *AuthManager) UserPostHandler(c echo.Context) error {
	u := new(User)
	if err := c.Bind(u); err != nil {
		return err
	}
	if strings.TrimSpace(u.Password) != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		u.Password = string(hash)
	} else {
		// get previous password
		if u.ID != 0 {
			oldUser := &User{}
			if err := am.db.One("ID", u.ID, oldUser); err == nil {
				u.Password = oldUser.Password
			}
		}
	}
	// check influencer code
	if u.Group == GroupInfluencer {
		var users []*User
		if err := am.db.All(&users); err != nil {
			return err
		}
		for _, iterUser := range users {
			if iterUser.InfluencerCode == u.InfluencerCode &&
				iterUser.ID != u.ID {
				// duplicate code
				return c.NoContent(http.StatusFound)
			}
		}
	}
	if err := am.db.Save(u); err != nil {
		return err
	}
	return c.NoContent(http.StatusOK)
}

func (am *AuthManager) UserDeleteHandler(c echo.Context) error {
	u := new(User)
	if err := c.Bind(u); err != nil {
		return err
	}
	if err := am.db.DeleteStruct(u); err != nil {
		return err
	}
	// delete associated keys
	if err := am.db.Select(q.Eq("Email", u.Email)).Delete(new(Key)); err != nil {
		return err
	}

	return c.NoContent(http.StatusOK)
}

func (am *AuthManager) KeysHandler(c echo.Context) error {
	am.RLock()
	defer am.RUnlock()
	var keys []*Key
	if err := am.db.All(&keys); err != nil {
		return nil
	}
	var users []*User
	if err := am.db.All(&users); err != nil {
		return nil
	}
	var emails []string
	for _, u := range users {
		emails = append(emails, u.Email)
	}
	response := map[string]interface{}{
		"emails": emails,
		"keys":   keys,
	}
	return c.JSON(http.StatusOK, response)
}

func (am *AuthManager) KeyPostHandler(c echo.Context) error {
	am.Lock()
	defer am.Unlock()
	k := new(Key)
	if err := c.Bind(k); err != nil {
		return err
	}
	key := &Key{
		Email: k.Email,
		Value: nuid.Next(),
	}
	am.cache.Set(key.Value, key.Email)
	if err := am.db.Save(key); err != nil {
		return err
	}
	return c.String(http.StatusOK, key.Value)
}

func (am *AuthManager) KeyDeleteHandler(c echo.Context) error {
	am.Lock()
	defer am.Unlock()
	k := new(Key)
	if err := c.Bind(k); err != nil {
		return err
	}
	am.cache.Delete(k.Value)
	if err := am.db.DeleteStruct(k); err != nil {
		return err
	}
	return c.NoContent(http.StatusOK)
}

type Role struct {
	Name        string              `json:"name"`
	Permissions map[string][]string `json:"permissions"`
}

func (am *AuthManager) InfluencersHandler(c echo.Context) error {
	var users []*User
	if err := am.db.Find("Group", GroupInfluencer, &users); err != nil {
		return err
	}

	for _, user := range users {
		user.Password = ""
	}
	response := map[string]interface{}{
		"items": users,
	}
	return c.JSON(http.StatusOK, response)
}
*/
