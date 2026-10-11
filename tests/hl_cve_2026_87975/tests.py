from django.forms.models import modelformset_factory
from django.test import TestCase

from .models import CustomPrimaryKey


class EditablePKFormsetSecurityTests(TestCase):
    """
    Regression tests for CVE-2026-87975.

    On vulnerable Django 4.2 code:
      - A forged POST can delete objects outside the formset's limiting queryset.
      - A forged POST can create new objects via an edit-only formset.

    On fixed code both operations are silently ignored and the assertions pass.
    """

    def test_deletion_not_allowed_outside_formset_queryset_editable_pk(self):
        """
        Forging the PK of an object that is excluded from the formset's
        queryset must NOT cause that object to be deleted.
        """
        obj = CustomPrimaryKey.objects.create(my_pk="target", some_field="data")

        # The queryset deliberately excludes `obj` – it is outside the formset's scope.
        limited_qs = CustomPrimaryKey.objects.exclude(pk=obj.pk)

        CustomPrimaryKeyFormSet = modelformset_factory(
            CustomPrimaryKey,
            can_delete=True,
            fields="__all__",
        )

        data = {
            "form-TOTAL_FORMS": "1",
            "form-INITIAL_FORMS": "1",
            "form-MAX_NUM_FORMS": "0",
            # Attacker forges the PK of an object NOT in limited_qs.
            "form-0-my_pk": obj.pk,
            "form-0-some_field": obj.some_field,
            "form-0-DELETE": "on",
        }

        formset = CustomPrimaryKeyFormSet(data, queryset=limited_qs)
        self.assertTrue(formset.is_valid())
        formset.save()

        # The object must still exist – deletion outside the queryset is forbidden.
        self.assertTrue(
            CustomPrimaryKey.objects.filter(pk=obj.pk).exists(),
            "CVE-2026-87975: object outside the formset queryset was deleted via "
            "a forged editable primary key.",
        )

    def test_edit_only_formset_cannot_create_via_forged_editable_pk(self):
        """
        An edit-only formset must not create a new object when the submitted
        PK does not correspond to any existing object in the queryset.
        """
        # Start with an empty table so there is nothing to edit.
        CustomPrimaryKey.objects.all().delete()

        CustomPrimaryKeyFormSet = modelformset_factory(
            CustomPrimaryKey,
            fields="__all__",
            edit_only=True,
        )

        data = {
            "form-TOTAL_FORMS": "1",
            "form-INITIAL_FORMS": "1",
            "form-MAX_NUM_FORMS": "0",
            # Attacker supplies a PK that does not exist in the DB.
            "form-0-my_pk": "forged",
            "form-0-some_field": "injected",
        }

        formset = CustomPrimaryKeyFormSet(data)
        self.assertTrue(formset.is_valid())
        formset.save()

        # The forged object must NOT have been created.
        self.assertFalse(
            CustomPrimaryKey.objects.filter(pk="forged").exists(),
            "CVE-2026-87975: edit-only formset created a new object via a forged "
            "editable primary key.",
        )
