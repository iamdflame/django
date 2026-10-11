"""Probe for CVE-2026-87975: forged POST data in model formsets with editable PKs.

Candidate probe, hand-written for spike S1. Public API only.
"""
from django.forms import inlineformset_factory, modelformset_factory
from django.test import TestCase

from .models import Item, Owner, Profile


class FormsetForgeryProbe(TestCase):
    def test_delete_outside_queryset_editable_pk(self):
        FormSet = modelformset_factory(Item, fields="__all__", can_delete=True)
        victim = Item.objects.create(code="victim", data="x")
        data = {
            "form-TOTAL_FORMS": "1",
            "form-INITIAL_FORMS": "1",
            "form-MAX_NUM_FORMS": "0",
            "form-0-code": "victim",
            "form-0-data": "x",
            "form-0-DELETE": "on",
        }
        formset = FormSet(data, queryset=Item.objects.exclude(pk=victim.pk))
        self.assertTrue(formset.is_valid(), formset.errors)
        formset.save()
        self.assertTrue(Item.objects.filter(pk="victim").exists())

    def test_delete_outside_queryset_inline_pk_parent_link(self):
        FormSet = inlineformset_factory(Owner, Profile, fields="__all__", can_delete=True)
        owner = Owner.objects.create(name="o")
        profile = Profile.objects.create(owner=owner, age=1)
        data = {
            "profile-TOTAL_FORMS": "1",
            "profile-INITIAL_FORMS": "1",
            "profile-MAX_NUM_FORMS": "0",
            "profile-0-owner": str(owner.pk),
            "profile-0-age": "1",
            "profile-0-DELETE": "on",
        }
        formset = FormSet(
            data, instance=owner, queryset=Profile.objects.exclude(pk=profile.pk)
        )
        self.assertTrue(formset.is_valid(), formset.errors)
        formset.save()
        self.assertTrue(Profile.objects.filter(pk=owner.pk).exists())

    def test_initial_form_cannot_create_editable_pk(self):
        FormSet = modelformset_factory(Item, fields="__all__")
        data = {
            "form-TOTAL_FORMS": "1",
            "form-INITIAL_FORMS": "1",
            "form-MAX_NUM_FORMS": "0",
            "form-0-code": "forged",
            "form-0-data": "x",
        }
        formset = FormSet(data, queryset=Item.objects.all())
        self.assertTrue(formset.is_valid(), formset.errors)
        formset.save()
        self.assertFalse(Item.objects.filter(pk="forged").exists())
