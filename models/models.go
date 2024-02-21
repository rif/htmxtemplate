package models

type User struct {
	ID               string
	Group            string
	FirstName        string
	LastName         string
	Email            string
	HashedPassword   string
	RegistrationKey  string
	ResetPasswordKey string
}

type Session struct {
	ID   string
	Email string
	Group string
}

type Key struct {
	Email       string
	Value       string
	Description string
}
