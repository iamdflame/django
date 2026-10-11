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
            "Object was deleted even though it was outside the formset queryset "
            "(CVE-2026-87975: privilege abuse via forged editable PK).",
        )

    def test_edit_only_editable_pk_cannot_create_new_object(self):
        """
        Submitting a forged PK that does NOT exist in the DB to an edit-only
        formset must NOT create a new object.
        On vulnerable Django 4.2: a new object IS created → AssertionError.
        On fixed code: no new object is created.
        """
        # Ensure the forged PK does not exist.
        CustomPrimaryKey.objects.filter(pk="forged").delete()

        FormSet = modelformset_factory(
            CustomPrimaryKey, fields="__all__"
            # edit_only is the fixed behaviour; on 4.2 we test the raw path
            # where INITIAL_FORMS=1 but the pk resolves to nothing in the qs.
        )
        data = self._make_formset_data(
            pk_value="forged",
            some_field="value",
            delete=False,
            initial_forms=1,
        )
        # Use an empty queryset so "forged" is not in it.
        formset = FormSet(data, queryset=CustomPrimaryKey.objects.none())
        self.assertTrue(formset.is_valid())
        formset.save()

        # The forged object must NOT have been created.
        self.assertFalse(
            CustomPrimaryKey.objects.filter(pk="forged").exists(),
            "A new object was created via a forged editable PK in an edit-only "
            "formset context (CVE-2026-87975).",
        )

    def test_deletion_only_affects_objects_in_queryset(self):
        """
        When two objects exist but only one is in the formset queryset,
        submitting DELETE for the out-of-scope object must leave it intact.
        """
        in_scope = CustomPrimaryKey.objects.create(my_pk="in", some_field="yes")
        out_of_scope = CustomPrimaryKey.objects.create(my_pk="out", some_field="no")

        # Queryset contains only `in_scope`; we forge a delete for `out_of_scope`.
        limited_qs = CustomPrimaryKey.objects.filter(pk=in_scope.pk)

        FormSet = modelformset_factory(
            CustomPrimaryKey, can_delete=True, fields="__all__"
        )
        data = self._make_formset_data(
            pk_value=out_of_scope.pk,
            some_field=out_of_scope.some_field,
            delete=True,
        )
        formset = FormSet(data, queryset=limited_qs)
        self.assertTrue(formset.is_valid())
        formset.save()

        self.assertTrue(
            CustomPrimaryKey.objects.filter(pk=out_of_scope.pk).exists(),
            "Out-of-scope object was deleted via forged editable PK "
            "(CVE-2026-87975).",
        )
        # in_scope object should still exist too (we didn't delete it).
        self.assertTrue(
            CustomPrimaryKey.objects.filter(pk=in_scope.pk).exists(),
        )
