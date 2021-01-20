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

package alias

import (
	"context"

	svcapi "github.com/aws/aws-sdk-go/service/kms"
	svcsdk "github.com/aws/aws-sdk-go/service/kms"
	svcsdkapi "github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	cpresource "github.com/crossplane/crossplane-runtime/pkg/resource"

	svcapitypes "github.com/crossplane/provider-aws/apis/kms/v1alpha1"
	awsclient "github.com/crossplane/provider-aws/pkg/clients"
)

const (
	errUnexpectedObject = "managed resource is not an Alias resource"

	errCreateSession = "cannot create a new session"
	errCreate        = "cannot create Alias in AWS"
	errUpdate        = "cannot update Alias in AWS"
	errDescribe      = "failed to describe Alias"
	errDelete        = "failed to delete Alias"
)

type connector struct {
	kube client.Client
	opts []option
}

func (c *connector) Connect(ctx context.Context, mg cpresource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*svcapitypes.Alias)
	if !ok {
		return nil, errors.New(errUnexpectedObject)
	}
	sess, err := awsclient.GetConfigV1(ctx, c.kube, mg, cr.Spec.ForProvider.Region)
	if err != nil {
		return nil, errors.Wrap(err, errCreateSession)
	}
	return newExternal(c.kube, svcapi.New(sess), c.opts), nil
}

func (e *external) Observe(ctx context.Context, mg cpresource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*svcapitypes.Alias)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errUnexpectedObject)
	}
	if meta.GetExternalName(cr) == "" {
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil
	}
	input := GenerateListAliasesInput(cr)
	if err := e.preObserve(ctx, cr, input); err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "pre-observe failed")
	}
	resp, err := e.client.ListAliasesWithContext(ctx, input)
	if err != nil {
		return managed.ExternalObservation{ResourceExists: false}, errors.Wrap(cpresource.Ignore(IsNotFound, err), errDescribe)
	}
	resp = e.filterList(cr, resp)
	if len(resp.Items) == 0 {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}
	currentSpec := cr.Spec.ForProvider.DeepCopy()
	if err := e.lateInitialize(&cr.Spec.ForProvider, resp); err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "late-init failed")
	}
	GenerateAlias(resp).Status.AtProvider.DeepCopyInto(&cr.Status.AtProvider)
	return e.postObserve(ctx, cr, resp, managed.ExternalObservation{
		ResourceExists:          true,
		ResourceUpToDate:        e.isUpToDate(cr, resp),
		ResourceLateInitialized: !cmp.Equal(&cr.Spec.ForProvider, currentSpec),
	}, nil)
}

func (e *external) Create(ctx context.Context, mg cpresource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*svcapitypes.Alias)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errUnexpectedObject)
	}
	cr.Status.SetConditions(xpv1.Creating())
	input := GenerateCreateAliasInput(cr)
	if err := e.preCreate(ctx, cr, input); err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, "pre-create failed")
	}
	resp, err := e.client.CreateAliasWithContext(ctx, input)
	if err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, errCreate)
	}

	return e.postCreate(ctx, cr, resp, managed.ExternalCreation{}, err)
}

func (e *external) Update(ctx context.Context, mg cpresource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*svcapitypes.Alias)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errUnexpectedObject)
	}
	input := GenerateUpdateAliasInput(cr)
	if err := e.preUpdate(ctx, cr, input); err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, "pre-update failed")
	}
	resp, err := e.client.UpdateAliasWithContext(ctx, input)
	if err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, errUpdate)
	}
	return e.postUpdate(ctx, cr, resp, managed.ExternalUpdate{}, err)
}

func (e *external) Delete(ctx context.Context, mg cpresource.Managed) error {
	cr, ok := mg.(*svcapitypes.Alias)
	if !ok {
		return errors.New(errUnexpectedObject)
	}
	cr.Status.SetConditions(xpv1.Deleting())
	input := GenerateDeleteAliasInput(cr)
	if err := e.preDelete(ctx, cr, input); err != nil {
		return errors.Wrap(err, "pre-delete failed")
	}
	_, err := e.client.DeleteAliasWithContext(ctx, input)
	return errors.Wrap(cpresource.Ignore(IsNotFound, err), errDelete)
}

type option func(*external)

func newExternal(kube client.Client, client svcsdkapi.KMSAPI, opts []option) *external {
	e := &external{
		kube:           kube,
		client:         client,
		preObserve:     nopPreObserve,
		postObserve:    nopPostObserve,
		preCreate:      nopPreCreate,
		postCreate:     nopPostCreate,
		preDelete:      nopPreDelete,
		preUpdate:      nopPreUpdate,
		postUpdate:     nopPostUpdate,
		lateInitialize: nopLateInitialize,
		isUpToDate:     alwaysUpToDate,
	}
	for _, f := range opts {
		f(e)
	}
	return e
}

type external struct {
	kube           client.Client
	client         svcsdkapi.KMSAPI
	preObserve     func(context.Context, *svcapitypes.Alias, *svcsdk.ListAliasesInput) error
	postObserve    func(context.Context, *svcapitypes.Alias, *svcsdk.ListAliasesOutput, managed.ExternalObservation, error) (managed.ExternalObservation, error)
	filterList     func(*svcapitypes.Alias, *svcsdk.ListAliasesOutput) *svcsdk.ListAliasesOutput
	lateInitialize func(*svcapitypes.AliasParameters, *svcsdk.ListAliasesOutput) error
	isUpToDate     func(*svcapitypes.Alias, *svcsdk.ListAliasesOutput) bool

	preCreate  func(context.Context, *svcapitypes.Alias, *svcsdk.CreateAliasInput) error
	postCreate func(context.Context, *svcapitypes.Alias, *svcsdk.CreateAliasOutput, managed.ExternalCreation, error) (managed.ExternalCreation, error)
	preDelete  func(context.Context, *svcapitypes.Alias, *svcsdk.DeleteAliasInput) error
	preUpdate  func(context.Context, *svcapitypes.Alias, *svcsdk.UpdateAliasInput) error
	postUpdate func(context.Context, *svcapitypes.Alias, *svcsdk.UpdateAliasOutput, managed.ExternalUpdate, error) (managed.ExternalUpdate, error)
}

func nopPreObserve(context.Context, *svcapitypes.Alias, *svcsdk.ListAliasesInput) error {
	return nil
}
func nopPostObserve(context.Context, *svcapitypes.Alias, *svcsdk.ListAliasesOutput, managed.ExternalObservation, error) (managed.ExternalObservation, error) {
	return managed.ExternalObservation{}, nil
}
func nopFilterList(_ *svcapitypes.Alias, list *svcsdk.ListAliasesOutput) *svcsdk.ListAliasesOutput {
	return list
}

func nopLateInitialize(*svcapitypes.AliasParameters, *svcsdk.ListAliasesOutput) error {
	return nil
}
func alwaysUpToDate(*svcapitypes.Alias, *svcsdk.ListAliasesOutput) bool {
	return true
}

func nopPreCreate(context.Context, *svcapitypes.Alias, *svcsdk.CreateAliasInput) error {
	return nil
}
func nopPostCreate(context.Context, *svcapitypes.Alias, *svcsdk.CreateAliasOutput, managed.ExternalCreation, error) (managed.ExternalCreation, error) {
	return managed.ExternalCreation{}, nil
}
func nopPreDelete(context.Context, *svcapitypes.Alias, *svcsdk.DeleteAliasInput) error {
	return nil
}
func nopPreUpdate(context.Context, *svcapitypes.Alias, *svcsdk.UpdateAliasInput) error {
	return nil
}
func nopPostUpdate(context.Context, *svcapitypes.Alias, *svcsdk.UpdateAliasOutput, managed.ExternalUpdate, error) (managed.ExternalUpdate, error) {
	return managed.ExternalUpdate{}, nil
}
