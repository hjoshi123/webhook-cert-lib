/*
Copyright 2025 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package injectable

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	admissionregistrationv1ac "k8s.io/client-go/applyconfigurations/admissionregistration/v1"

	"github.com/cert-manager/webhook-cert-lib/pkg/runtime"
)

type ValidatingWebhookCaBundleInject struct {
}

var _ Injectable = &ValidatingWebhookCaBundleInject{}

func (i *ValidatingWebhookCaBundleInject) GroupVersionKind() schema.GroupVersionKind {
	return schema.GroupVersionKind{
		Group:   "admissionregistration.k8s.io",
		Version: "v1",
		Kind:    "ValidatingWebhookConfiguration",
	}
}

func (i *ValidatingWebhookCaBundleInject) InjectCA(obj *unstructured.Unstructured, caBundle []byte) (runtime.ApplyConfiguration, error) {
	// TODO: Can we generalize this function for any resource based on a JSON path?

	ac := admissionregistrationv1ac.ValidatingWebhookConfiguration(obj.GetName())

	webhooks, _, err := unstructured.NestedSlice(obj.Object, "webhooks")
	if err != nil {
		return nil, err
	}
	for _, w := range webhooks {
		name, _, err := unstructured.NestedString(w.(map[string]any), "name")
		if err != nil {
			return nil, err
		}
		ac.WithWebhooks(
			admissionregistrationv1ac.ValidatingWebhook().
				WithName(name).
				WithClientConfig(admissionregistrationv1ac.WebhookClientConfig().
					WithCABundle(caBundle...),
				),
		)
	}

	return ac, nil
}
