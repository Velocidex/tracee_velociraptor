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

cleanbuild: clean sync bin

full: clean sync generate bin

debug:
	dlv debug "./userspace/cmd/" -- dump --policy ./test_files/test.policy.yaml security_file_open
