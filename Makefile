generate:
	go run make.go -v Generate

bin:
	go run make.go -v Bin

race:
	go run make.go -v Race

sync:
	go run make.go -v SyncCode

clean:
	rm -rf ./c/ ./userspace/
