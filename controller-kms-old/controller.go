/*
Copyright 2019 The Crossplane Authors.

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

package kms

import (
	"context"
	"reflect"

	"github.com/aws/aws-sdk-go-v2/aws"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/pkg/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	runtimev1alpha1 "github.com/crossplane/crossplane-runtime/apis/core/v1alpha1"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/logging"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"

	"github.com/crossplane/provider-aws/apis/kms/v1alpha1"
	awscommon "github.com/crossplane/provider-aws/pkg/clients"
	"github.com/crossplane/provider-aws/pkg/clients/kms"
)

const (
	errUnexpectedObjectCreate  = "unexpected create"
	errUnexpectedObjectObserve = "unexpected observe"
	errUnexpectedObject        = "The managed resource is not a Key resource"
	errKubeUpdateFailed        = "cannot update Key custom resource"

	errDescribe     = "failed to describe Key with id"
	errCreate       = "failed to create the Key resource"
	errUpdate       = "failed to update Key resource"
	errCreateTags   = "failed to create tags for the Key resource"
	errDelete       = "failed to delete the Key resource"
	errSpecUpdate   = "cannot update spec of Key custom resource"
	errStatusUpdate = "cannot update status of Key custom resource"
)

// SetupKey adds a controller that reconciles VPCs.
func SetupKey(mgr ctrl.Manager, l logging.Logger) error {
	name := managed.ControllerName(v1alpha1.KeyGroupKind)
	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		For(&v1alpha1.Key{}).
		Complete(managed.NewReconciler(mgr,
			resource.ManagedKind(v1alpha1.KeyGroupVersionKind),
			managed.WithExternalConnecter(&connector{kube: mgr.GetClient(), newClientFn: kms.NewClient}),
			managed.WithReferenceResolver(managed.NewAPISimpleReferenceResolver(mgr.GetClient())),
			managed.WithConnectionPublishers(),
			managed.WithInitializers(), // remove NameAsExternalName Initializer
			managed.WithLogger(l.WithValues("controller", name)),
			managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
		))
}

type connector struct {
	kube        client.Client
	newClientFn func(config aws.Config) kms.Client
}

func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*v1alpha1.Key)
	if !ok {
		return nil, errors.New(errUnexpectedObject)
	}

	cfg, err := awscommon.GetConfig(ctx, c.kube, mg, cr.Spec.ForProvider.Region)
	if err != nil {
		return nil, err
	}
	return &external{client: c.newClientFn(*cfg), kube: c.kube}, nil
}

type external struct {
	kube   client.Client
	client kms.Client
}

func (e *external) Observe(ctx context.Context, mgd resource.Managed) (managed.ExternalObservation, error) { // nolint:gocyclo
	cr, ok := mgd.(*v1alpha1.Key)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errUnexpectedObjectObserve)
	}

	if meta.GetExternalName(cr) == "" {
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil
	}

	response, err := e.client.DescribeKeyRequest(&awskms.DescribeKeyInput{
		KeyId: aws.String(meta.GetExternalName(cr)),
	}).Send(ctx)
	if err != nil {
		return managed.ExternalObservation{}, errors.Wrapf(resource.Ignore(kms.IsErrorNotFound, err), errDescribe)
	}

	// abort early if Key is scheduled for deletion
	// Key resource is deleted as soon as it is scheduled for deletion in AWS
	if response.DescribeKeyOutput.KeyMetadata.DeletionDate != nil {
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil
	}

	// hardcoded - this is the only supported policyName by AWS
	policyName := "default"

	// Example sending a request using the GetKeyPolicyRequest method.
	policyResp, err := e.client.GetKeyPolicyRequest(&awskms.GetKeyPolicyInput{
		KeyId:      aws.String(meta.GetExternalName(cr)),
		PolicyName: &policyName,
	}).Send(ctx)

	if err != nil && !kms.IsErrorNotFound(err) { // resp is now filled
		return managed.ExternalObservation{}, errors.Wrapf(err, errDescribe)
	}

	tagResp, err := e.client.ListResourceTagsRequest(&awskms.ListResourceTagsInput{
		KeyId: aws.String(meta.GetExternalName(cr)),
	}).Send(ctx)

	if err != nil && !kms.IsErrorNotFound(err) { // resp is now filled
		return managed.ExternalObservation{}, errors.Wrapf(err, errDescribe)
	}

	current := cr.Spec.ForProvider.DeepCopy()
	kms.LateInitialize(&cr.Spec.ForProvider, response.KeyMetadata, policyResp.Policy, tagResp.Tags)
	if !reflect.DeepEqual(current, &cr.Spec.ForProvider) {
		if err := e.kube.Update(ctx, cr); err != nil {
			return managed.ExternalObservation{}, errors.Wrap(err, errKubeUpdateFailed)
		}
	}

	cr.Status.AtProvider = kms.GenerateObservation(response.KeyMetadata)

	return managed.ExternalObservation{
		ResourceExists:   true,
		ResourceUpToDate: kms.IsUpToDate(&cr.Spec.ForProvider, policyResp.Policy, tagResp.Tags),
	}, nil
}

func (e *external) Create(ctx context.Context, mgd resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mgd.(*v1alpha1.Key)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errUnexpectedObjectCreate)
	}

	cr.Status.SetConditions(runtimev1alpha1.Creating())
	if err := e.kube.Status().Update(ctx, cr); err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, errStatusUpdate)
	}

	input := awskms.CreateKeyInput{
		CustomerMasterKeySpec: cr.Spec.ForProvider.Type,
	}

	if cr.Spec.ForProvider.Usage != nil {
		input.KeyUsage = *cr.Spec.ForProvider.Usage
	}

	if cr.Spec.ForProvider.Description != nil {
		input.Description = aws.String(*cr.Spec.ForProvider.Description)
	}

	if cr.Spec.ForProvider.JSONPolicy != nil {
		input.Policy = aws.String(*cr.Spec.ForProvider.JSONPolicy)
	}

	// TODO: support asymetric keys
	// TODO: add description
	result, err := e.client.CreateKeyRequest(&input).Send(ctx)
	if err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, errCreate)
	}

	meta.SetExternalName(cr, aws.StringValue(result.KeyMetadata.KeyId))

	return managed.ExternalCreation{}, errors.Wrap(e.kube.Update(ctx, cr), errSpecUpdate)
}

func (e *external) Update(ctx context.Context, mgd resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mgd.(*v1alpha1.Key)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errUnexpectedObject)
	}

	keyID := meta.GetExternalName(cr)

	_, err := e.client.DescribeKeyRequest(&awskms.DescribeKeyInput{
		KeyId: aws.String(keyID),
	}).Send(ctx)

	if err != nil {
		return managed.ExternalUpdate{}, errors.Wrapf(resource.Ignore(kms.IsErrorNotFound, err), errDescribe)
	}

	if _, err = e.client.PutKeyPolicyRequest(&awskms.PutKeyPolicyInput{
		KeyId:      aws.String(keyID),
		PolicyName: aws.String("default"),
		Policy:     aws.String(*cr.Spec.ForProvider.JSONPolicy),
	}).Send(ctx); err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, errCreateTags)
	}

	_, err = e.client.TagResourceRequest(&awskms.TagResourceInput{
		KeyId: aws.String(keyID),
		Tags:  kms.GenerateKMSTags(cr.Spec.ForProvider.Tags),
	}).Send(ctx)

	return managed.ExternalUpdate{}, errors.Wrap(err, errUpdate)
}

func (e *external) Delete(ctx context.Context, mgd resource.Managed) error {
	cr, ok := mgd.(*v1alpha1.Key)
	if !ok {
		return errors.New(errUnexpectedObject)
	}

	cr.Status.SetConditions(runtimev1alpha1.Deleting())

	req := awskms.ScheduleKeyDeletionInput{
		KeyId: aws.String(meta.GetExternalName(cr)),
	}

	if cr.Spec.ForProvider.PendingWindowInDays != nil {
		req.PendingWindowInDays = aws.Int64(*cr.Spec.ForProvider.PendingWindowInDays)
	}

	_, err := e.client.ScheduleKeyDeletionRequest(&req).Send(ctx)

	return errors.Wrap(resource.Ignore(kms.IsErrorNotFound, err), errDelete)
}
