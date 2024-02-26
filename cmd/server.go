package main

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"os"

	"net/http"
	"templates/auth"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

const version = "v0.0.1"

type Templates struct {
	*template.Template
}

func (t *Templates) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.ExecuteTemplate(w, name, data)
}

func main() {
	ctx := context.Background()
	db, err := pgxpool.New(ctx,
		"postgresql://postgres:testus@172.17.0.1:5432/templates")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	ath, err := auth.NewAuthManager(db)
	if err != nil {
		slog.Error("cannot init auth")
	}

	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
		Skipper: func(c echo.Context) bool {
			if c.Request().URL.Path == "/server/payment" {
				return true
			}
			if email := ath.GetKeyAuth(c); email != "" {
				return true
			}
			return false
		},
		TokenLookup: "query:csrf",
		CookiePath:  "/",
	}))
	e.Renderer = &Templates{template.Must(template.ParseGlob("views/*.html"))}

	// login
	e.GET("/login", ath.LoginHandler)
	e.POST("/login", ath.LoginPostHandler)
	e.GET("/logout", ath.LogoutHandler)

	e.GET("/link1", func(c echo.Context) error {
		block := "link1Page"
		if c.Request().Header.Get("Hx-Request") == "true" {
			block = "link1Container"
		}
		return c.Render(http.StatusOK, block, map[string]interface{}{"Name": "Link1"})
	})
	e.GET("/link2", func(c echo.Context) error {
		block := "link2Page"
		if c.Request().Header.Get("Hx-Request") == "true" {
			block = "link2Container"
		}
		return c.Render(http.StatusOK, block, map[string]interface{}{"Name": "Link2"})
	})
	e.GET("/link3", func(c echo.Context) error {
		block := "link3Page"
		if c.Request().Header.Get("Hx-Request") == "true" {
			block = "link3Container"
		}
		return c.Render(http.StatusOK, block, map[string]interface{}{"Name": "Link3"})
	})
	e.GET("/", func(c echo.Context) error {
		return c.Render(http.StatusOK, "link1Page", map[string]interface{}{"Name": "Home"})
	})
	l := e.Group("/admin")
	l.Use(ath.AuthMiddleware)

	l.GET("/", func(c echo.Context) error {
		return c.Render(http.StatusOK, "admin", map[string]interface{}{
			"User":    c.Get("email"),
			"Group":   c.Get("group"),
			"Code":    c.Get("code"),
			"CSRF":    c.Get(middleware.DefaultCSRFConfig.ContextKey),
			"Version": version,
		})
	})
	e.Logger.Fatal(e.Start(":8000"))
}
