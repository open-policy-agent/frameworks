module github.com/open-policy-agent/frameworks/constraint

go 1.13

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/fatih/color v1.7.0 // indirect
	github.com/gobuffalo/flect v0.1.5 // indirect
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/google/go-cmp v0.3.0
	github.com/markbates/inflect v1.0.4 // indirect
	github.com/mattn/go-colorable v0.1.2 // indirect
	github.com/onsi/ginkgo v1.8.0 // indirect
	github.com/onsi/gomega v1.5.0
	github.com/open-policy-agent/opa v0.15.0
	github.com/pkg/errors v0.8.1
	github.com/spf13/cobra v0.0.5
	github.com/spf13/pflag v1.0.3
	golang.org/x/net v0.0.0-20190812203447-cdfb69ac37fc
	gopkg.in/yaml.v3 v3.0.0-20190905181640-827449938966 // indirect
	k8s.io/apiextensions-apiserver v0.0.0-20191016113550-5357c4baaf65
	k8s.io/apimachinery v0.0.0-20191004115801-a2eda9f80ab8
	k8s.io/client-go v11.0.1-0.20190409021438-1a26190bd76a+incompatible
	k8s.io/code-generator v0.0.0-20190713022532-93d7507fc8ff // indirect
	sigs.k8s.io/controller-runtime v0.2.2
	sigs.k8s.io/controller-tools v0.1.8 // indirect

)

replace (
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.0.0-20191016113439-b64f2075a530
	k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20191004115701-31ade1b30762
	k8s.io/client-go => k8s.io/client-go v0.0.0-20191016110837-54936ba21026
)
