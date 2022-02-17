package client

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest/cts"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/errors"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler/handlertest"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestConstraintMatchers_Add(t *testing.T) {
	tests := []struct {
		name       string
		before     *constraintMatchers
		constraint *unstructured.Unstructured
		matchers   map[string]constraints.Matcher
		want       *constraintMatchers
	}{
		{
			name:       "add to empty",
			before:     &constraintMatchers{},
			constraint: cts.MakeConstraint(t, "bar", "qux"),
			matchers: map[string]constraints.Matcher{
				"foo": handlertest.Matcher{},
			},
			want: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"qux": {
									Constraint: cts.MakeConstraint(t, "bar", "qux"),
									Matcher:    handlertest.Matcher{},
								},
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
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"qux": {
									Constraint: cts.MakeConstraint(t, "bar", "qux"),
									Matcher:    handlertest.Matcher{},
								},
							},
						},
					},
				},
			},
			constraint: cts.MakeConstraint(t, "bar", "qux"),
			matchers: map[string]constraints.Matcher{
				"foo": handlertest.Matcher{},
			},
			want: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"qux": {
									Constraint: cts.MakeConstraint(t, "bar", "qux"),
									Matcher:    handlertest.Matcher{},
								},
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
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"qux": {
									Constraint: cts.MakeConstraint(t, "bar", "qux"),
									Matcher: handlertest.Matcher{
										Namespace: "aaa",
									},
								},
							},
						},
					},
				},
			},
			constraint: cts.MakeConstraint(t, "bar", "qux"),
			matchers: map[string]constraints.Matcher{
				"foo": handlertest.Matcher{
					Namespace: "bbb",
				},
			},
			want: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"qux": {
									Constraint: cts.MakeConstraint(t, "bar", "qux"),
									Matcher: handlertest.Matcher{
										Namespace: "bbb",
									},
								},
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
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"qux": {
									Constraint: cts.MakeConstraint(t, "bar", "qux"),
									Matcher:    handlertest.Matcher{Namespace: "aaa"},
								},
							},
						},
					},
				},
			},
			constraint: cts.MakeConstraint(t, "bar", "cog"),
			matchers: map[string]constraints.Matcher{
				"foo": handlertest.Matcher{Namespace: "bbb"},
			},
			want: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"qux": {
									Constraint: cts.MakeConstraint(t, "bar", "qux"),
									Matcher:    handlertest.Matcher{Namespace: "aaa"},
								},
								"cog": {
									Constraint: cts.MakeConstraint(t, "bar", "cog"),
									Matcher:    handlertest.Matcher{Namespace: "bbb"},
								},
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
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"qux": {
									Constraint: cts.MakeConstraint(t, "bar", "qux"),
									Matcher:    handlertest.Matcher{Namespace: "aaa"},
								},
							},
						},
					},
				},
			},
			constraint: cts.MakeConstraint(t, "cog", "qux"),
			matchers: map[string]constraints.Matcher{
				"foo": handlertest.Matcher{Namespace: "bbb"},
			},
			want: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"qux": {
									Constraint: cts.MakeConstraint(t, "bar", "qux"),
									Matcher:    handlertest.Matcher{Namespace: "aaa"},
								},
							},
							"cog": {
								"qux": {
									Constraint: cts.MakeConstraint(t, "cog", "qux"),
									Matcher:    handlertest.Matcher{Namespace: "bbb"},
								},
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
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"qux": {
									Constraint: cts.MakeConstraint(t, "bar", "qux"),
									Matcher:    handlertest.Matcher{Namespace: "aaa"},
								},
							},
						},
					},
				},
			},
			constraint: cts.MakeConstraint(t, "bar", "qux"),
			matchers: map[string]constraints.Matcher{
				"cog": handlertest.Matcher{Namespace: "bbb"},
			},
			want: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraintMatcher{},
					},
					"cog": {
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"qux": {
									Constraint: cts.MakeConstraint(t, "bar", "qux"),
									Matcher:    handlertest.Matcher{Namespace: "bbb"},
								},
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

			got.Upsert(tt.constraint, tt.matchers)

			opts := []cmp.Option{cmp.AllowUnexported(constraintMatchers{}), cmp.AllowUnexported(targetMatchers{})}
			if diff := cmp.Diff(tt.want, got, opts...); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestConstraintMatchers_Remove(t *testing.T) {
	tests := []struct {
		name       string
		before     *constraintMatchers
		target     string
		constraint *unstructured.Unstructured
		want       *constraintMatchers
	}{
		{
			name:       "remove from empty",
			before:     &constraintMatchers{},
			constraint: cts.MakeConstraint(t, "bar", "qux"),
			want:       &constraintMatchers{},
		},
		{
			name: "remove from empty target",
			before: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {},
				},
			},
			target:     "foo",
			constraint: cts.MakeConstraint(t, "bar", "qux"),
			want: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {},
				},
			},
		},
		{
			name: "remove from empty kind",
			before: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraintMatcher{
							"bar": {},
						},
					},
				},
			},
			target:     "foo",
			constraint: cts.MakeConstraint(t, "bar", "qux"),
			want: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraintMatcher{},
					},
				},
			},
		},
		{
			name: "remove last from target",
			before: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"qux": {},
							},
						},
					},
				},
			},
			target:     "foo",
			constraint: cts.MakeConstraint(t, "bar", "qux"),
			want: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraintMatcher{},
					},
				},
			},
		},
		{
			name: "remove last from kind",
			before: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"qux": {},
							},
							"cog": {
								"qux": {},
							},
						},
					},
				},
			},
			target:     "foo",
			constraint: cts.MakeConstraint(t, "bar", "qux"),
			want: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraintMatcher{
							"cog": {
								"qux": {},
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
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"qux": {},
								"cog": {},
							},
						},
					},
				},
			},
			target:     "foo",
			constraint: cts.MakeConstraint(t, "bar", "qux"),
			want: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"cog": {},
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

			got.Remove(tt.target, tt.constraint)

			opts := []cmp.Option{cmp.AllowUnexported(constraintMatchers{}), cmp.AllowUnexported(targetMatchers{})}
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
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"qux": {},
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
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"qux": {},
							},
							"cog": {
								"qux": {},
							},
						},
					},
				},
			},
			kind: "bar",
			want: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraintMatcher{
							"cog": {
								"qux": {},
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
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"qux": {},
							},
						},
					},
					"cog": {
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"qux": {},
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

			opts := []cmp.Option{cmp.AllowUnexported(constraintMatchers{}), cmp.AllowUnexported(targetMatchers{})}
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
		want     []*unstructured.Unstructured
		wantErrs error
	}{
		{
			name:     "no matchers",
			matchers: &constraintMatchers{},
			handler:  "foo",
			review: &handlertest.Review{
				Object: handlertest.Object{Namespace: "aaa"},
			},
			want:     []*unstructured.Unstructured{},
			wantErrs: nil,
		},
		{
			name: "match one",
			matchers: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"qux": {
									Constraint: cts.MakeConstraint(t, "bar", "qux"),
									Matcher:    handlertest.Matcher{},
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
			want: []*unstructured.Unstructured{
				cts.MakeConstraint(t, "bar", "qux"),
			},
			wantErrs: nil,
		},
		{
			name: "match two same kind",
			matchers: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"qux": {
									Constraint: cts.MakeConstraint(t, "bar", "qux"),
									Matcher:    handlertest.Matcher{},
								},
								"cog": {
									Constraint: cts.MakeConstraint(t, "bar", "cog"),
									Matcher:    handlertest.Matcher{},
								},
							},
						},
					},
				},
			},
			handler: "foo",
			review: &handlertest.Review{
				Object: handlertest.Object{},
			},
			want: []*unstructured.Unstructured{
				cts.MakeConstraint(t, "bar", "cog"),
				cts.MakeConstraint(t, "bar", "qux"),
			},
			wantErrs: nil,
		},
		{
			name: "match two different kinds",
			matchers: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"qux": {
									Constraint: cts.MakeConstraint(t, "bar", "qux"),
									Matcher:    handlertest.Matcher{},
								},
							},
							"cog": {
								"qux": {
									Constraint: cts.MakeConstraint(t, "cog", "qux"),
									Matcher:    handlertest.Matcher{},
								},
							},
						},
					},
				},
			},
			handler: "foo",
			review: &handlertest.Review{
				Object: handlertest.Object{},
			},
			want: []*unstructured.Unstructured{
				cts.MakeConstraint(t, "bar", "qux"),
				cts.MakeConstraint(t, "cog", "qux"),
			},
			wantErrs: nil,
		},
		{
			name: "match one target",
			matchers: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"qux1": {
									Constraint: cts.MakeConstraint(t, "bar", "qux1"),
									Matcher:    handlertest.Matcher{},
								},
							},
						},
					},
					"cog": {
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"qux2": {
									Constraint: cts.MakeConstraint(t, "bar", "qux2"),
									Matcher:    handlertest.Matcher{},
								},
							},
						},
					},
				},
			},
			handler: "foo",
			review: &handlertest.Review{
				Object: handlertest.Object{},
			},
			want: []*unstructured.Unstructured{
				cts.MakeConstraint(t, "bar", "qux1"),
			},
			wantErrs: nil,
		},
		{
			name: "match other target",
			matchers: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"qux1": {
									Constraint: cts.MakeConstraint(t, "bar", "qux1"),
									Matcher:    handlertest.Matcher{},
								},
							},
						},
					},
					"cog": {
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"qux1": {
									Constraint: cts.MakeConstraint(t, "bar", "qux2"),
									Matcher:    handlertest.Matcher{},
								},
							},
						},
					},
				},
			},
			handler: "cog",
			review: &handlertest.Review{
				Object: handlertest.Object{},
			},
			want: []*unstructured.Unstructured{
				cts.MakeConstraint(t, "bar", "qux2"),
			},
			wantErrs: nil,
		},
		{
			name: "match one but not the other",
			matchers: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"qux": {
									Constraint: cts.MakeConstraint(t, "bar", "qux"),
									Matcher: handlertest.Matcher{
										Namespace: "aaa",
										Cache:     c,
									},
								},
								"cog": {
									Constraint: cts.MakeConstraint(t, "bar", "cog"),
									Matcher: handlertest.Matcher{
										Namespace: "bbb",
										Cache:     c,
									},
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
			want: []*unstructured.Unstructured{
				cts.MakeConstraint(t, "bar", "qux"),
			},
			wantErrs: nil,
		},
		{
			name: "error matching",
			matchers: &constraintMatchers{
				matchers: map[string]targetMatchers{
					"foo": {
						matchers: map[string]map[string]constraintMatcher{
							"bar": {
								"qux": {
									Constraint: cts.MakeConstraint(t, "bar", "qux"),
									Matcher: handlertest.Matcher{
										Namespace: "aaa",
										Cache:     c,
									},
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
