generate:
	go run make.go -v Generate

bin:
	go run make.go -v Bin

race:
	go run make.go -v Race

sync:
	go run make.go -v SyncCode
	#	git checkout origin/master ./userspace/ebpf/ab0x* ./userspace/ebpf/ebpf_bpfel.go

clean:
	rm -rf ./c/ ./userspace/

cleanbuild: clean sync bin

full: clean sync generate bin
