from django.forms.models import modelformset_factory
from django.test import TestCase

from .models import CustomPrimaryKey


class EditablePKFormsetSecurityTests(TestCase):
    """
    CVE-2026-87975: Model formsets with editable PKs must not allow forged
    POST data to delete objects outside the queryset or create objects via
    edit-only formsets.
    """

    def _make_formset_data(self, pk_value, some_field, delete=False, initial_forms=1):
        data = {
            "form-TOTAL_FORMS": "1",
            "form-INITIAL_FORMS": str(initial_forms),
            "form-MAX_NUM_FORMS": "0",
            "form-0-my_pk": pk_value,
            "form-0-some_field": some_field,
        }
        if delete:
            data["form-0-DELETE"] = "on"
        return data

    def test_deletion_not_allowed_outside_formset_queryset_editable_pk(self):
        """
        Forging a PK that exists in the DB but is excluded from the formset's
        queryset must NOT cause that object to be deleted.
        On vulnerable Django 4.2: the object IS deleted → AssertionError.
        On fixed code: the object survives.
        """
        obj = CustomPrimaryKey.objects.create(my_pk="target", some_field="data")
        # The queryset explicitly excludes the object we're trying to delete.
        limited_qs = CustomPrimaryKey.objects.exclude(pk=obj.pk)

        FormSet = modelformset_factory(
            CustomPrimaryKey, can_delete=True, fields="__all__"
        )
        data = self._make_formset_data(
            pk_value=obj.pk,
            some_field=obj.some_field,
            delete=True,
        )
        formset = FormSet(data, queryset=limited_qs)
        self.assertTrue(formset.is_valid())
        formset.save()

        # The object must still exist – deletion outside the queryset is forbidden.
        self.assertTrue(
            CustomPrimaryKey.objects.filter(pk=obj.pk).exists(),
            "CVE-2026-87975: object outside the formset queryset was deleted via "
            "forged POST data.",
        )

    def test_edit_only_formset_cannot_create_via_forged_pk(self):
        """
        An edit-only formset (edit_only=True) must not create a new object
        when POST data supplies a PK that does not exist in the queryset.
        On vulnerable Django 4.2: the object IS created → AssertionError.
        On fixed code: no new object is created.
        """
        # Start with an empty table so "forged" cannot accidentally match.
        CustomPrimaryKey.objects.all().delete()

        FormSet = modelformset_factory(
            CustomPrimaryKey, fields="__all__", edit_only=True
        )
        # Claim there is 1 initial form whose PK is "forged" – it doesn't exist.
        data = self._make_formset_data(
            pk_value="forged",
            some_field="value",
            initial_forms=1,
        )
        formset = FormSet(data)
        self.assertTrue(formset.is_valid())
        formset.save()

        # No object with pk="forged" should have been created.
        self.assertFalse(
            CustomPrimaryKey.objects.filter(pk="forged").exists(),
            "CVE-2026-87975: edit-only formset created a new object via forged PK.",
        )

    def test_edit_only_extra_form_does_not_create_via_forged_pk(self):
        """
        When INITIAL_FORMS=1 but the PK resolves to nothing in the queryset,
        save_existing_objects skips it (obj.pk is None path). No new row must
        appear.
        """
        # Ensure the pk "ghost" does not exist.
        CustomPrimaryKey.objects.filter(pk="ghost").delete()

        FormSet = modelformset_factory(
            CustomPrimaryKey, fields="__all__", edit_only=True
        )
        data = {
            "form-TOTAL_FORMS": "1",
            "form-INITIAL_FORMS": "1",
            "form-MAX_NUM_FORMS": "0",
            "form-0-my_pk": "ghost",
            "form-0-some_field": "injected",
        }
        formset = FormSet(data)
        self.assertTrue(formset.is_valid())
        formset.save()

        self.assertFalse(
            CustomPrimaryKey.objects.filter(pk="ghost").exists(),
            "CVE-2026-87975: edit-only formset created 'ghost' object via forged PK.",
        )
