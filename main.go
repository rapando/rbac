package main

import (
	"log"

	"github.com/casbin/casbin/v2"
)

type Input struct {
	Role     string
	Path     string
	Method   string
	Expected bool
}

func main() {
	log.SetFlags(4)
	// set up casbin auth rules
	authEnforcer, err := casbin.NewEnforcer("./auth_model.conf", "./policy.csv")
	if err != nil {
		log.Fatal(err)
	}

	var inputs = []Input{
		{"anonymous", "/", "GET", false},
		{"anonymous", "/login", "GET", true},
		{"admin", "/login", "GET", true},
		{"admin", "/some/weird/path", "GET", true},
		{"member", "/logout", "GET", true},
		{"member", "/member/weird/path", "GET", true},
		{"member", "/admin", "GET", false},
		{"member", "/some/weird/path", "GET", false},
	}

	for _, input := range inputs {
		res, _ := authEnforcer.Enforce(input.Role, input.Path, input.Method)
		if res == input.Expected {
			log.Println("ok")
		} else {
			log.Println("--- failed")
		}
	}
}
