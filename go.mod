module github.com/gravitational/teleport

go 1.14

require (
	cloud.google.com/go v0.41.0
	github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78
	github.com/Azure/go-autorest v14.0.1+incompatible
	github.com/Microsoft/go-winio v0.4.9
	github.com/alecthomas/template v0.0.0-20160405071501-a0175ee3bccc
	github.com/alecthomas/units v0.0.0-20151022065526-2efee857e7cf
	github.com/armon/go-radix v1.0.0
	github.com/aws/aws-sdk-go v1.32.7
	github.com/beevik/etree v0.0.0-20170418002358-cda1c0026246
	github.com/beorn7/perks v0.0.0-20150223135152-b965b613227f
	github.com/boombuler/barcode v0.0.0-20161226211916-fe0f26ff6d26
	github.com/cjbassi/drawille-go v0.1.0
	github.com/codahale/hdrhistogram v0.0.0-20150708134006-954f16e8b9ef
	github.com/coreos/go-semver v0.2.0
	github.com/coreos/go-systemd v0.0.0-20190620071333-e64a0ec8b42a
	github.com/coreos/pkg v0.0.0-20160314094717-1914e367e85e
	github.com/davecgh/go-spew v1.1.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/docker/docker v17.12.0-ce-rc1.0.20180721085148-1ef1cc838816+incompatible
	github.com/docker/spdystream v0.0.0-20170912183627-bc6354cbbc29
	github.com/dustin/go-humanize v1.0.0
	github.com/fsouza/fake-gcs-server v1.11.6
	github.com/ghodss/yaml v0.0.0-20150909031657-73d445a93680
	github.com/gizak/termui v0.0.0-20190224181052-63c2a0d70943
	github.com/gogo/protobuf v1.1.1
	github.com/gokyle/hotp v0.0.0-20160218004637-c180d57d286b
	github.com/golang/groupcache v0.0.0-20190702054246-869f871628b6
	github.com/golang/protobuf v1.3.1
	github.com/google/btree v0.0.0-20180124185431-e89373fe6b4a
	github.com/google/gofuzz v0.0.0-20170612174753-24818f796faf
	github.com/google/gops v0.3.1
	github.com/google/uuid v1.1.1
	github.com/googleapis/gax-go v1.0.3
	github.com/googleapis/gnostic v0.2.0
	github.com/gorilla/mux v1.7.3
	github.com/gravitational/configure v0.0.0-20160909185025-1db4b84fe9db
	github.com/gravitational/form v0.0.0-20151109031454-c4048f792f70
	github.com/gravitational/go-oidc v0.0.3
	github.com/gravitational/gobpf v0.0.1
	github.com/gravitational/kingpin v2.1.11-0.20190130013101-742f2714c145+incompatible
	github.com/gravitational/license v0.0.0-20180912170534-4f189e3bd6e3
	github.com/gravitational/logrus v0.10.1-0.20171120195323-8ab1e1b91d5f
	github.com/gravitational/oxy v0.0.0-20180629203109-e4a7e35311e6
	github.com/gravitational/reporting v0.0.0-20180907002058-ac7b85c75c4c
	github.com/gravitational/roundtrip v1.0.0
	github.com/gravitational/trace v1.1.6
	github.com/gravitational/ttlmap v0.0.0-20171116003245-91fd36b9004c
	github.com/imdario/mergo v0.3.4
	github.com/jmespath/go-jmespath v0.0.0-20180206201540-c2b33e8439af
	github.com/johannesboyne/gofakes3 v0.0.0-20191228161223-9aee1c78a252
	github.com/jonboulle/clockwork v0.1.1-0.20190114141812-62fb9bc030d1
	github.com/json-iterator/go v1.1.9
	github.com/julienschmidt/httprouter v1.1.0
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0
	github.com/kr/pty v1.0.0
	github.com/kylelemons/godebug v0.0.0-20160406211939-eadb3ce320cb
	github.com/mailgun/lemma v0.0.0-20160211003854-e8b0cd607f58
	github.com/mailgun/metrics v0.0.0-20150124003306-2b3c4565aafd
	github.com/mailgun/minheap v0.0.0-20131208021033-7c28d80e2ada
	github.com/mailgun/timetools v0.0.0-20141028012446-7e6055773c51
	github.com/mailgun/ttlmap v0.0.0-20150816203249-16b258d86efc
	github.com/mattn/go-runewidth v0.0.4
	github.com/mattn/go-sqlite3 v1.10.0
	github.com/matttproud/golang_protobuf_extensions v0.0.0-20151011102529-d0c3fe89de86
	github.com/mdp/rsc v0.0.0-20160131164516-90f07065088d
	github.com/mitchellh/go-wordwrap v1.0.0
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd
	github.com/modern-go/reflect2 v0.0.0-20180701023420-4b7aa43c6742
	github.com/nsf/termbox-go v0.0.0-20190121233118-02980233997d
	github.com/pborman/uuid v0.0.0-20170612153648-e790cca94e6c
	github.com/petar/GoLLRB v0.0.0-20130427215148-53be0d36a84c
	github.com/pquerna/otp v0.0.0-20160912161815-54653902c20e
	github.com/prometheus/client_golang v1.1.0
	github.com/prometheus/client_model v0.0.0-20190129233127-fd36f4220a90
	github.com/prometheus/common v0.4.1
	github.com/prometheus/procfs v0.0.4
	github.com/russellhaering/gosaml2 v0.0.0-20170515204909-8908227c114a
	github.com/russellhaering/goxmldsig v0.0.0-20170515183101-605161228693
	github.com/ryszard/goskiplist v0.0.0-20150312221310-2dfbae5fcf46
	github.com/satori/go.uuid v1.1.1-0.20170321230731-5bf94b69c6b6
	github.com/shabbyrobe/gocovmerge v0.0.0-20190829150210-3e036491d500
	github.com/spf13/pflag v1.0.1
	github.com/tstranex/u2f v0.0.0-20160508205855-eb799ce68da4
	github.com/vulcand/predicate v1.1.0
	github.com/xeipuuv/gojsonpointer v0.0.0-20151027082146-e0fe6f683076
	github.com/xeipuuv/gojsonreference v0.0.0-20150808065054-e02fc20de94c
	github.com/xeipuuv/gojsonschema v0.0.0-20151204154511-3988ac14d6f6
	go.etcd.io/etcd v0.5.0-alpha.5.0.20190830150955-898bd1351fcf
	go.opencensus.io v0.22.1
	go.uber.org/atomic v1.4.0
	go.uber.org/multierr v1.1.0
	go.uber.org/zap v1.10.0
	golang.org/x/crypto v0.0.0-20200220183623-bac4c82f6975
	golang.org/x/net v0.0.0-20180826012351-8a410e7b638d
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	golang.org/x/sys v0.0.0-20200107162124-548cf772de50
	golang.org/x/text v0.0.0-20170512150324-19e51611da83
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0
	golang.org/x/tools v0.0.0-20191227053925-7b8e75db28f4
	google.golang.org/api v0.10.0
	google.golang.org/appengine v1.6.3
	google.golang.org/genproto v0.0.0-20190916214212-f660b8655731
	google.golang.org/grpc v1.23.0
	gopkg.in/check.v1 v1.0.0-20141024133853-64131543e789
	gopkg.in/inf.v0 v0.9.1
	gopkg.in/yaml.v2 v2.2.8
	k8s.io/api v0.17.3
	k8s.io/apimachinery v0.17.3
	k8s.io/client-go v0.17.3
	k8s.io/klog v1.0.0
	k8s.io/utils v0.0.0-20200124190032-861946025e34
	sigs.k8s.io/yaml v1.2.0
)

replace (
	github.com/coreos/go-oidc => github.com/gravitational/go-oidc v0.0.3
	github.com/iovisor/gobpf => github.com/gravitational/gobpf v0.0.1
	github.com/sirupsen/logrus => github.com/gravitational/logrus v0.10.1-0.20171120195323-8ab1e1b91d5f
)
