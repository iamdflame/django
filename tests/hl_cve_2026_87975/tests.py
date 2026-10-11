from django.forms.models import modelformset_factory
from django.test import TestCase

from .models import CustomPrimaryKey


class EditablePKFormsetDeletionTest(TestCase):
    """
    CVE-2026-87975: forged POST data must NOT delete objects outside the
    formset's limiting queryset when the model has an editable primary key.
    On vulnerable Django 4.2 the object IS deleted → AssertionError.
    On fixed code the object survives → test passes.
    """

    def test_deletion_not_allowed_outside_formset_queryset_editable_pk(self):
        obj = CustomPrimaryKey.objects.create(my_pk="target", some_field="data")

        # The queryset deliberately excludes `obj`, so the formset should
        # never be allowed to touch it.
        limited_qs = CustomPrimaryKey.objects.exclude(pk=obj.pk)

        CustomPrimaryKeyFormSet = modelformset_factory(
            CustomPrimaryKey, can_delete=True, fields="__all__"
        )

        # Forge POST data that references the excluded object and marks it
        # for deletion.
        data = {
            "form-TOTAL_FORMS": "1",
            "form-INITIAL_FORMS": "1",
            "form-MAX_NUM_FORMS": "0",
            "form-0-my_pk": obj.pk,          # NOT in limited_qs
            "form-0-some_field": obj.some_field,
            "form-0-DELETE": "on",
        }

        formset = CustomPrimaryKeyFormSet(data, queryset=limited_qs)
        self.assertTrue(formset.is_valid())
        formset.save()

        # The object must still exist – deletion outside the queryset is
        # forbidden.  Vulnerable code deletes it, causing this to fail.
        self.assertTrue(
            CustomPrimaryKey.objects.filter(pk=obj.pk).exists(),
            "Object was deleted even though it was outside the formset queryset "
            "(CVE-2026-87975 privilege-abuse via editable PK).",
        )

    def test_edit_only_editable_pk_no_new_object_created(self):
        """
        An edit-only formset must not create a new object when forged POST
        data supplies a primary key that does not exist in the database.
        On vulnerable Django 4.2 the object IS created → AssertionError.
        On fixed code nothing is created → test passes.
        """
        CustomPrimaryKeyFormSet = modelformset_factory(
            CustomPrimaryKey, fields="__all__", edit_only=True
        )

        # Claim there is one initial form whose PK is "forged" – a value that
        # does not exist in the database.
        data = {
            "form-TOTAL_FORMS": "1",
            "form-INITIAL_FORMS": "1",
            "form-MAX_NUM_FORMS": "0",
            "form-0-my_pk": "forged",
            "form-0-some_field": "value",
        }

        formset = CustomPrimaryKeyFormSet(data)
        self.assertTrue(formset.is_valid())
        formset.save()

        # The forged object must NOT have been persisted.
        self.assertFalse(
            CustomPrimaryKey.objects.filter(pk="forged").exists(),
            "A new object was created by an edit-only formset via a forged "
            "editable primary key (CVE-2026-87975).",
        )
