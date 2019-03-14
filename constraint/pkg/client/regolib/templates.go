package regolib

import "text/template"

var Deny = template.Must(template.New("deny").Parse(denySrc))
var Audit = template.Must(template.New("audit").Parse(auditSrc))
