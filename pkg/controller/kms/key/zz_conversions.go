/*
Copyright 2020 The Crossplane Authors.

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

// Code generated by ack-generate. DO NOT EDIT.

package key

import (
	"github.com/aws/aws-sdk-go/aws/awserr"
	svcsdk "github.com/aws/aws-sdk-go/service/kms"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	svcapitypes "github.com/crossplane/provider-aws/apis/kms/v1alpha1"
)

// NOTE(muvaf): We return pointers in case the function needs to start with an
// empty object, hence need to return a new pointer.

// GenerateDescribeKeyInput returns input for read
// operation.
func GenerateDescribeKeyInput(cr *svcapitypes.Key) *svcsdk.DescribeKeyInput {
	res := &svcsdk.DescribeKeyInput{}

	if cr.Status.AtProvider.KeyID != nil {
		res.SetKeyId(*cr.Status.AtProvider.KeyID)
	}

	return res
}

// GenerateKey returns the current state in the form of *svcapitypes.Key.
func GenerateKey(resp *svcsdk.DescribeKeyOutput) *svcapitypes.Key {
	cr := &svcapitypes.Key{}

	if resp.KeyMetadata.AWSAccountId != nil {
		cr.Status.AtProvider.AWSAccountID = resp.KeyMetadata.AWSAccountId
	}
	if resp.KeyMetadata.Arn != nil {
		cr.Status.AtProvider.ARN = resp.KeyMetadata.Arn
	}
	if resp.KeyMetadata.CloudHsmClusterId != nil {
		cr.Status.AtProvider.CloudHsmClusterID = resp.KeyMetadata.CloudHsmClusterId
	}
	if resp.KeyMetadata.CreationDate != nil {
		cr.Status.AtProvider.CreationDate = &metav1.Time{*resp.KeyMetadata.CreationDate}
	}
	if resp.KeyMetadata.DeletionDate != nil {
		cr.Status.AtProvider.DeletionDate = &metav1.Time{*resp.KeyMetadata.DeletionDate}
	}
	if resp.KeyMetadata.Enabled != nil {
		cr.Status.AtProvider.Enabled = resp.KeyMetadata.Enabled
	}
	if resp.KeyMetadata.EncryptionAlgorithms != nil {
		f9 := []*string{}
		for _, f9iter := range resp.KeyMetadata.EncryptionAlgorithms {
			var f9elem string
			f9elem = *f9iter
			f9 = append(f9, &f9elem)
		}
		cr.Status.AtProvider.EncryptionAlgorithms = f9
	}
	if resp.KeyMetadata.ExpirationModel != nil {
		cr.Status.AtProvider.ExpirationModel = resp.KeyMetadata.ExpirationModel
	}
	if resp.KeyMetadata.KeyId != nil {
		cr.Status.AtProvider.KeyID = resp.KeyMetadata.KeyId
	}
	if resp.KeyMetadata.KeyManager != nil {
		cr.Status.AtProvider.KeyManager = resp.KeyMetadata.KeyManager
	}
	if resp.KeyMetadata.KeyState != nil {
		cr.Status.AtProvider.KeyState = resp.KeyMetadata.KeyState
	}
	if resp.KeyMetadata.SigningAlgorithms != nil {
		f16 := []*string{}
		for _, f16iter := range resp.KeyMetadata.SigningAlgorithms {
			var f16elem string
			f16elem = *f16iter
			f16 = append(f16, &f16elem)
		}
		cr.Status.AtProvider.SigningAlgorithms = f16
	}
	if resp.KeyMetadata.ValidTo != nil {
		cr.Status.AtProvider.ValidTo = &metav1.Time{*resp.KeyMetadata.ValidTo}
	}

	return cr
}

// GenerateCreateKeyInput returns a create input.
func GenerateCreateKeyInput(cr *svcapitypes.Key) *svcsdk.CreateKeyInput {
	res := &svcsdk.CreateKeyInput{}

	if cr.Spec.ForProvider.BypassPolicyLockoutSafetyCheck != nil {
		res.SetBypassPolicyLockoutSafetyCheck(*cr.Spec.ForProvider.BypassPolicyLockoutSafetyCheck)
	}
	if cr.Spec.ForProvider.CustomKeyStoreID != nil {
		res.SetCustomKeyStoreId(*cr.Spec.ForProvider.CustomKeyStoreID)
	}
	if cr.Spec.ForProvider.CustomerMasterKeySpec != nil {
		res.SetCustomerMasterKeySpec(*cr.Spec.ForProvider.CustomerMasterKeySpec)
	}
	if cr.Spec.ForProvider.Description != nil {
		res.SetDescription(*cr.Spec.ForProvider.Description)
	}
	if cr.Spec.ForProvider.KeyUsage != nil {
		res.SetKeyUsage(*cr.Spec.ForProvider.KeyUsage)
	}
	if cr.Spec.ForProvider.Origin != nil {
		res.SetOrigin(*cr.Spec.ForProvider.Origin)
	}
	if cr.Spec.ForProvider.Policy != nil {
		res.SetPolicy(*cr.Spec.ForProvider.Policy)
	}
	if cr.Spec.ForProvider.Tags != nil {
		f7 := []*svcsdk.Tag{}
		for _, f7iter := range cr.Spec.ForProvider.Tags {
			f7elem := &svcsdk.Tag{}
			if f7iter.TagKey != nil {
				f7elem.SetTagKey(*f7iter.TagKey)
			}
			if f7iter.TagValue != nil {
				f7elem.SetTagValue(*f7iter.TagValue)
			}
			f7 = append(f7, f7elem)
		}
		res.SetTags(f7)
	}

	return res
}

// IsNotFound returns whether the given error is of type NotFound or not.
func IsNotFound(err error) bool {
	awsErr, ok := err.(awserr.Error)
	return ok && awsErr.Code() == "UNKNOWN"
}