module github.com/appsentinels/coraza/v3/examples/http-server

go 1.18

require github.com/appsentinels/coraza/v3 v3.0.0-20220914101451-05d352c89b24

require (
	github.com/corazawaf/libinjection-go v0.1.2 // indirect
	github.com/magefile/mage v1.15.0 // indirect
	github.com/petar-dambovaliev/aho-corasick v0.0.0-20230725210150-fb29fc3c913e // indirect
	github.com/tidwall/gjson v1.14.4 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	golang.org/x/net v0.11.0 // indirect
	golang.org/x/sync v0.3.0 // indirect
	rsc.io/binaryregexp v0.2.0 // indirect
)

replace github.com/appsentinels/coraza/v3 => ../..
