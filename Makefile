generate:
	go run make.go -v Generate

bin:
	go run make.go -v Bin

race:
	go run make.go -v Race
