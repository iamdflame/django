"""
Regression probe for CVE-2026-87975.

Vulnerable behaviour (Django 4.2 unpatched):
  1. A forged POST can delete an object that is *outside* the formset's
     limiting queryset when the model has an editable primary key.
  2. A forged POST can *create* a new object through an edit-only formset
     when the model has an editable primary key.

On fixed code both saves must be no-ops; on vulnerable code they mutate the
database, causing the assertions below to fail.
"""

from django.forms.models import modelformset_factory
from django.test import TestCase

from .models import CustomPrimaryKey


class EditablePKFormsetSecurityTests(TestCase):
    """CVE-2026-87975 – privilege abuse via editable primary keys."""

    # ------------------------------------------------------------------
    # Test 1: deletion must not affect objects outside the queryset
    # ------------------------------------------------------------------
    def test_deletion_not_allowed_outside_formset_queryset_editable_pk(self):
        """
        Forging the PK of an object that is excluded from the formset's
        queryset must NOT delete that object.
        """
        CustomPrimaryKeyFormSet = modelformset_factory(
            CustomPrimaryKey, can_delete=True, fields="__all__"
        )
        obj = CustomPrimaryKey.objects.create(my_pk="pk1", some_field="data")

        # The queryset deliberately excludes `obj`, so the formset has no
        # business touching it.
        limited_qs = CustomPrimaryKey.objects.exclude(pk=obj.pk)

        data = {
            "form-TOTAL_FORMS": "1",
            "form-INITIAL_FORMS": "1",
            "form-MAX_NUM_FORMS": "0",
            "form-0-my_pk": obj.pk,        # forged – not in limited_qs
            "form-0-some_field": obj.some_field,
            "form-0-DELETE": "on",
        }

        formset = CustomPrimaryKeyFormSet(data, queryset=limited_qs)
        self.assertTrue(formset.is_valid(), formset.errors)
        formset.save()

        # The object must still exist – deletion outside the queryset is
        # not permitted.
        self.assertTrue(
            CustomPrimaryKey.objects.filter(pk=obj.pk).exists(),
            "CVE-2026-87975: object outside the formset queryset was deleted "
            "via a forged editable primary key.",
        )

    # ------------------------------------------------------------------
    # Test 2: edit-only formset must not create objects via forged PK
    # ------------------------------------------------------------------
    def test_edit_only_editable_pk_does_not_create_new_object(self):
        """
        Submitting a non-existent PK to an edit-only formset must NOT
        create a new object in the database.
        """
        CustomPrimaryKeyFormSet = modelformset_factory(
            CustomPrimaryKey, fields="__all__", edit_only=True
        )

        data = {
            "form-TOTAL_FORMS": "1",
            "form-INITIAL_FORMS": "1",
            "form-MAX_NUM_FORMS": "0",
            "form-0-my_pk": "forged",      # does not exist in the DB
            "form-0-some_field": "value",
        }

        formset = CustomPrimaryKeyFormSet(data)
        self.assertTrue(formset.is_valid(), formset.errors)
        formset.save()

        # The forged object must NOT have been created.
        self.assertFalse(
            CustomPrimaryKey.objects.filter(pk="forged").exists(),
            "CVE-2026-87975: edit-only formset created a new object via a "
            "forged editable primary key.",
        )

    # ------------------------------------------------------------------
    # Test 3: legitimate deletion inside the queryset still works
    # ------------------------------------------------------------------
    def test_deletion_allowed_inside_formset_queryset(self):
        """
        Sanity-check: an object that IS inside the formset's queryset can
        still be deleted normally (the fix must not break legitimate use).
        """
        CustomPrimaryKeyFormSet = modelformset_factory(
            CustomPrimaryKey, can_delete=True, fields="__all__"
        )
        obj = CustomPrimaryKey.objects.create(my_pk="pk2", some_field="data")

        # queryset includes obj
        qs = CustomPrimaryKey.objects.filter(pk=obj.pk)

        data = {
            "form-TOTAL_FORMS": "1",
            "form-INITIAL_FORMS": "1",
            "form-MAX_NUM_FORMS": "0",
            "form-0-my_pk": obj.pk,
            "form-0-some_field": obj.some_field,
            "form-0-DELETE": "on",
        }

        formset = CustomPrimaryKeyFormSet(data, queryset=qs)
        self.assertTrue(formset.is_valid(), formset.errors)
        formset.save()

        self.assertFalse(
            CustomPrimaryKey.objects.filter(pk=obj.pk).exists(),
            "Legitimate deletion inside the formset queryset should succeed.",
        )
