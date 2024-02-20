package main

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"os"

	"net/http"

	"github.com/georgysavva/scany/pgxscan"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)



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

	var users []*User
	if err := pgxscan.Select(ctx, db, &users, `SELECT id, first_name, email FROM "user"`); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to fetch: %v\n", err)
	}

	for _, u := range users {
		fmt.Println(u)
	}

	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Renderer = &Templates{template.Must(template.ParseGlob("views/*.html"))}

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
		return c.Render(http.StatusOK, "index", map[string]interface{}{"Name": "Home"})
	})
	e.Logger.Fatal(e.Start(":8000"))
}
