# An EBPF plugin for Velociraptor based on Tracee

This project is a simplified version of Tracee
(https://github.com/aquasecurity/tracee) for use in Velociraptor
(https://github.com/Velocidex/velociraptor).

Only a subset of Tracee functionality is enabled for use in
Velociraptor. Following are the main differences:

1. The EBPF code is identical to Tracee
2. The Go code is mostly the same except that it is adapted to use
   https://github.com/cilium/ebpf instead of
   https://github.com/aquasecurity/tracee/libbtfgo .

   The reason this is preferred is that https://github.com/cilium/ebpf
   does not require any CGO dependencies and therefore can be built
   completely portably (Even cross compiled from Windows).

   We encode the compressed EBFP object files into the Go binaries in
   such a way that they are only expanded into memory during the ebpf
   load stage. This means that binary size is kept small (adding
   approximately 1.5Mb) and running memory needs are not increased
   much when ebpf is not needed (and even then the program is only
   loaded into memory during the load stage).

3. Currently Tracee's extensive rule filtering policy engine is not
   used in this implementation. Instead we automatically insert a
   match all policy for each event ID that is selected.

4. Tracee's extensive process tracker is not used, since Velociraptor
   already has a generic process tracker (that also works on Windows).

5. The event output format is much simplified and is emitted to be
   more useful for Velociraptor.
