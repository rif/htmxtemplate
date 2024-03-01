package utils

import (
	"crypto/rand"
	"encoding/hex"
)

const (
	GroupAdmin = "admin"
	GroupStaffManager = "staff_manager"
	GroupStaff = "staff"
	GroupNobody = "nobody"
)


func UniqueID() string {
	bytes := make([]byte, 16) // generates a 128-bit (16 bytes) random number
	if _, err := rand.Read(bytes); err != nil {
		panic(err) // handle error
	}
	return hex.EncodeToString(bytes)
}
