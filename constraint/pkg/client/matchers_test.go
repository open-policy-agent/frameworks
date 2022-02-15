package client

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/errors"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler/handlertest"
)

func TestConstraintMatchers_Add(t *testing.T) {
	tests := []struct {
		name    string
		before  *constraintMatchers
		key     matcherKey
		matcher constraints.Matcher
		want    *constraintMatchers
	}{
		{
			name:    "add to empty",
			before:  &constraintMatchers{},
			key:     matcherKey{Target: "foo", Kind: "bar", Name: "qux"},
			matcher: handlertest.Matcher{},
			want: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux": handlertest.Matcher{},
							},
						},
					},
				},
			},
		},
		{
			name: "overwrite with identical",
			before: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux": handlertest.Matcher{},
							},
						},
					},
				},
			},
			key:     matcherKey{Target: "foo", Kind: "bar", Name: "qux"},
			matcher: handlertest.Matcher{},
			want: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux": handlertest.Matcher{},
							},
						},
					},
				},
			},
		},
		{
			name: "overwrite with new",
			before: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux": handlertest.Matcher{Namespace: "aaa"},
							},
						},
					},
				},
			},
			key:     matcherKey{Target: "foo", Kind: "bar", Name: "qux"},
			matcher: handlertest.Matcher{Namespace: "bbb"},
			want: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux": handlertest.Matcher{Namespace: "bbb"},
							},
						},
					},
				},
			},
		},
		{
			name: "add with different name",
			before: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux": handlertest.Matcher{Namespace: "aaa"},
							},
						},
					},
				},
			},
			key:     matcherKey{Target: "foo", Kind: "bar", Name: "cog"},
			matcher: handlertest.Matcher{Namespace: "bbb"},
			want: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux": handlertest.Matcher{Namespace: "aaa"},
								"cog": handlertest.Matcher{Namespace: "bbb"},
							},
						},
					},
				},
			},
		},
		{
			name: "add with different kind",
			before: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux": handlertest.Matcher{Namespace: "aaa"},
							},
						},
					},
				},
			},
			key:     matcherKey{Target: "foo", Kind: "cog", Name: "qux"},
			matcher: handlertest.Matcher{Namespace: "bbb"},
			want: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux": handlertest.Matcher{Namespace: "aaa"},
							},
							"cog": {
								"qux": handlertest.Matcher{Namespace: "bbb"},
							},
						},
					},
				},
			},
		},
		{
			name: "add with different target",
			before: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux": handlertest.Matcher{Namespace: "aaa"},
							},
						},
					},
				},
			},
			key:     matcherKey{Target: "cog", Kind: "bar", Name: "qux"},
			matcher: handlertest.Matcher{Namespace: "bbb"},
			want: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux": handlertest.Matcher{Namespace: "aaa"},
							},
						},
					},
					"cog": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux": handlertest.Matcher{Namespace: "bbb"},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.before

			got.Add(tt.key, tt.matcher)

			opts := []cmp.Option{cmp.AllowUnexported(constraintMatchers{}), cmpopts.IgnoreFields(constraintMatchers{}, "mtx"), cmp.AllowUnexported(targetMatchers{})}
			if diff := cmp.Diff(tt.want, got, opts...); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestConstraintMatchers_Remove(t *testing.T) {
	tests := []struct {
		name   string
		before *constraintMatchers
		key    matcherKey
		want   *constraintMatchers
	}{
		{
			name:   "remove from empty",
			before: &constraintMatchers{},
			key:    matcherKey{Target: "foo", Kind: "bar", Name: "qux"},
			want:   &constraintMatchers{},
		},
		{
			name: "remove from empty target",
			before: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {},
				},
			},
			key: matcherKey{Target: "foo", Kind: "bar", Name: "qux"},
			want: &constraintMatchers{
				matchers: map[string]targetMatchers{},
			},
		},
		{
			name: "remove from empty kind",
			before: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {},
						},
					},
				},
			},
			key: matcherKey{Target: "foo", Kind: "bar", Name: "qux"},
			want: &constraintMatchers{
				matchers: map[string]targetMatchers{},
			},
		},
		{
			name: "remove last from target",
			before: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux": handlertest.Matcher{},
							},
						},
					},
				},
			},
			key: matcherKey{Target: "foo", Kind: "bar", Name: "qux"},
			want: &constraintMatchers{
				matchers: map[string]targetMatchers{},
			},
		},
		{
			name: "remove last from kind",
			before: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux": handlertest.Matcher{},
							},
							"cog": {
								"qux": handlertest.Matcher{},
							},
						},
					},
				},
			},
			key: matcherKey{Target: "foo", Kind: "bar", Name: "qux"},
			want: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"cog": {
								"qux": handlertest.Matcher{},
							},
						},
					},
				},
			},
		},
		{
			name: "remove",
			before: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux": handlertest.Matcher{},
								"cog": handlertest.Matcher{},
							},
						},
					},
				},
			},
			key: matcherKey{Target: "foo", Kind: "bar", Name: "qux"},
			want: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"cog": handlertest.Matcher{},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.before

			got.Remove(tt.key)

			opts := []cmp.Option{cmp.AllowUnexported(constraintMatchers{}), cmpopts.IgnoreFields(constraintMatchers{}, "mtx"), cmp.AllowUnexported(targetMatchers{})}
			if diff := cmp.Diff(tt.want, got, opts...); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestConstraintMatchers_RemoveKind(t *testing.T) {
	tests := []struct {
		name   string
		before *constraintMatchers
		kind   string
		want   *constraintMatchers
	}{
		{
			name:   "remove from empty",
			before: &constraintMatchers{},
			kind:   "bar",
			want:   &constraintMatchers{},
		},
		{
			name: "remove from empty handler",
			before: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {},
				},
			},
			kind: "bar",
			want: &constraintMatchers{
				matchers: map[string]targetMatchers{},
			},
		},
		{
			name: "remove last from handler",
			before: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux": handlertest.Matcher{},
							},
						},
					},
				},
			},
			kind: "bar",
			want: &constraintMatchers{
				matchers: map[string]targetMatchers{},
			},
		},
		{
			name: "remove from handler",
			before: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux": handlertest.Matcher{},
							},
							"cog": {
								"qux": handlertest.Matcher{},
							},
						},
					},
				},
			},
			kind: "bar",
			want: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"cog": {
								"qux": handlertest.Matcher{},
							},
						},
					},
				},
			},
		},
		{
			name: "remove from multiple handlers",
			before: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux": handlertest.Matcher{},
							},
						},
					},
					"cog": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux": handlertest.Matcher{},
							},
						},
					},
				},
			},
			kind: "bar",
			want: &constraintMatchers{
				matchers: map[string]targetMatchers{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.before

			got.RemoveKind(tt.kind)

			opts := []cmp.Option{cmp.AllowUnexported(constraintMatchers{}), cmpopts.IgnoreFields(constraintMatchers{}, "mtx"), cmp.AllowUnexported(targetMatchers{})}
			if diff := cmp.Diff(tt.want, got, opts...); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestConstraintMatchers_ConstraintsFor(t *testing.T) {
	c := &handlertest.Cache{}
	namespaceA := &handlertest.Object{Namespace: "aaa"}
	err := c.Add(namespaceA.Key(), namespaceA)
	if err != nil {
		t.Fatal(err)
	}
	namespaceB := &handlertest.Object{Namespace: "bbb"}
	err = c.Add(namespaceB.Key(), namespaceB)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		matchers *constraintMatchers
		handler  string
		review   interface{}
		want     []matcherKey
		wantErrs error
	}{
		{
			name:     "no matchers",
			matchers: &constraintMatchers{},
			handler:  "foo",
			review: &handlertest.Review{
				Object: handlertest.Object{Namespace: "aaa"},
			},
			want:     []matcherKey{},
			wantErrs: nil,
		},
		{
			name: "match one",
			matchers: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux": handlertest.Matcher{},
							},
						},
					},
				},
			},
			handler: "foo",
			review: &handlertest.Review{
				Object: handlertest.Object{Namespace: "aaa"},
			},
			want: []matcherKey{
				{Target: "foo", Kind: "bar", Name: "qux"},
			},
			wantErrs: nil,
		},
		{
			name: "match two same kind",
			matchers: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux": handlertest.Matcher{},
								"cog": handlertest.Matcher{},
							},
						},
					},
				},
			},
			handler: "foo",
			review: &handlertest.Review{
				Object: handlertest.Object{},
			},
			want: []matcherKey{
				{Target: "foo", Kind: "bar", Name: "cog"},
				{Target: "foo", Kind: "bar", Name: "qux"},
			},
			wantErrs: nil,
		},
		{
			name: "match two different kinds",
			matchers: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux": handlertest.Matcher{},
							},
							"cog": {
								"qux": handlertest.Matcher{},
							},
						},
					},
				},
			},
			handler: "foo",
			review: &handlertest.Review{
				Object: handlertest.Object{},
			},
			want: []matcherKey{
				{Target: "foo", Kind: "bar", Name: "qux"},
				{Target: "foo", Kind: "cog", Name: "qux"},
			},
			wantErrs: nil,
		},
		{
			name: "match one target",
			matchers: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux1": handlertest.Matcher{},
							},
						},
					},
					"cog": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux2": handlertest.Matcher{},
							},
						},
					},
				},
			},
			handler: "foo",
			review: &handlertest.Review{
				Object: handlertest.Object{},
			},
			want: []matcherKey{
				{Target: "foo", Kind: "bar", Name: "qux1"},
			},
			wantErrs: nil,
		},
		{
			name: "match other target",
			matchers: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux1": handlertest.Matcher{},
							},
						},
					},
					"cog": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux2": handlertest.Matcher{},
							},
						},
					},
				},
			},
			handler: "cog",
			review: &handlertest.Review{
				Object: handlertest.Object{},
			},
			want: []matcherKey{
				{Target: "cog", Kind: "bar", Name: "qux2"},
			},
			wantErrs: nil,
		},
		{
			name: "match one but not the other",
			matchers: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux": handlertest.Matcher{
									Namespace: "aaa",
									Cache:     c,
								},
								"cog": handlertest.Matcher{
									Namespace: "bbb",
									Cache:     c,
								},
							},
						},
					},
				},
			},
			handler: "foo",
			review: &handlertest.Review{
				Object: handlertest.Object{Namespace: "aaa"},
			},
			want: []matcherKey{
				{Target: "foo", Kind: "bar", Name: "qux"},
			},
			wantErrs: nil,
		},
		{
			name: "error matching",
			matchers: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraints.Matcher{
							"bar": {
								"qux": handlertest.Matcher{
									Namespace: "aaa",
									Cache:     c,
								},
							},
						},
					},
				},
			},
			handler: "foo",
			review:  "nope",
			want:    nil,
			wantErrs: &errors.ErrorMap{
				"foo bar qux": handlertest.ErrInvalidType,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.matchers.ConstraintsFor(tt.handler, tt.review)
			if diff := cmp.Diff(tt.wantErrs, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatal(diff)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Error(diff)
			}
		})
	}
}
