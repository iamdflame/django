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
        # forbidden.  On vulnerable code this assertion fails because the
        # object has been deleted.
        self.assertTrue(
            CustomPrimaryKey.objects.filter(pk=obj.pk).exists(),
            "Object outside the formset queryset was incorrectly deleted "
            "(CVE-2026-87975).",
        )

    def test_edit_only_editable_pk_does_not_create_new_object(self):
        """
        edit_only=True formsets must not create new objects even when the
        submitted PK does not exist in the database.
        On vulnerable Django 4.2 a new row IS inserted → AssertionError.
        On fixed code no row is created → test passes.
        """
        CustomPrimaryKeyFormSet = modelformset_factory(
            CustomPrimaryKey, fields="__all__", edit_only=True
        )

        # Submit a form that looks like an existing record (INITIAL_FORMS=1)
        # but references a PK that is not in the database.
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

        # The forged object must NOT have been created.
        # On vulnerable code this assertion fails because the object exists.
        self.assertFalse(
            CustomPrimaryKey.objects.filter(pk="forged").exists(),
            "edit_only formset created a new object via forged PK "
            "(CVE-2026-87975).",
        )
