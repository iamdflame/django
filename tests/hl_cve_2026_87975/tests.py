"""
Regression probe for CVE-2026-87975.

Vulnerable behaviour (Django 4.2 unpatched):
  1. A forged POST can delete an object that is *outside* the formset's
     limiting queryset when the model has an editable primary key.
  2. A forged POST can *create* a new object through an edit-only formset
     when the model has an editable primary key.

On fixed code both saves must be no-ops, so the assertions below pass.
On vulnerable code the saves mutate the database, causing AssertionErrors.
"""

from django.forms.models import modelformset_factory
from django.test import TestCase

from .models import CustomPrimaryKey


class EditablePKFormsetSecurityTests(TestCase):
    """Tests that forged POST data cannot abuse model formsets with editable PKs."""

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _make_formset_cls(self, **kwargs):
        return modelformset_factory(CustomPrimaryKey, fields="__all__", **kwargs)

    # ------------------------------------------------------------------
    # 1. Deletion outside the limiting queryset must be blocked
    # ------------------------------------------------------------------

    def test_deletion_outside_queryset_is_blocked(self):
        """
        Forging the PK of an object that is excluded from the formset's
        queryset must NOT delete that object.
        """
        obj = CustomPrimaryKey.objects.create(my_pk="target", some_field="data")

        # The queryset deliberately excludes `obj` – it is "outside" the set.
        limited_qs = CustomPrimaryKey.objects.exclude(pk=obj.pk)

        FormSet = self._make_formset_cls(can_delete=True)

        # Attacker forges a POST that references the excluded object and
        # marks it for deletion.
        data = {
            "form-TOTAL_FORMS": "1",
            "form-INITIAL_FORMS": "1",
            "form-MAX_NUM_FORMS": "0",
            "form-0-my_pk": obj.pk,          # not in limited_qs
            "form-0-some_field": obj.some_field,
            "form-0-DELETE": "on",
        }

        formset = FormSet(data, queryset=limited_qs)
        self.assertTrue(formset.is_valid(), formset.errors)
        formset.save()

        # The object must still exist – deletion outside the queryset is
        # not permitted on fixed code.
        still_exists = CustomPrimaryKey.objects.filter(pk=obj.pk).exists()
        assert still_exists, (
            "CVE-2026-87975: forged DELETE removed an object that was outside "
            "the formset's limiting queryset."
        )

    # ------------------------------------------------------------------
    # 2. Edit-only formset must not create objects via forged PKs
    # ------------------------------------------------------------------

    def test_edit_only_cannot_create_via_forged_pk(self):
        """
        An edit-only formset must not create a new object when the POST
        data contains a PK that does not exist in the database.
        """
        # Ensure the "forged" key does not exist before the test.
        CustomPrimaryKey.objects.filter(pk="forged").delete()

        FormSet = self._make_formset_cls(edit_only=True)

        # Attacker submits an INITIAL_FORMS=1 form with a non-existent PK,
        # hoping the formset will create the object.
        data = {
            "form-TOTAL_FORMS": "1",
            "form-INITIAL_FORMS": "1",
            "form-MAX_NUM_FORMS": "0",
            "form-0-my_pk": "forged",
            "form-0-some_field": "injected",
        }

        formset = FormSet(data)
        self.assertTrue(formset.is_valid(), formset.errors)
        formset.save()

        created = CustomPrimaryKey.objects.filter(pk="forged").exists()
        assert not created, (
            "CVE-2026-87975: edit-only formset created a new object via a "
            "forged primary key in POST data."
        )

    # ------------------------------------------------------------------
    # 3. Legitimate deletion inside the queryset still works
    # ------------------------------------------------------------------

    def test_deletion_inside_queryset_is_allowed(self):
        """
        Sanity-check: a deletion that targets an object *inside* the
        formset's queryset must still succeed on fixed code.
        """
        obj = CustomPrimaryKey.objects.create(my_pk="legit", some_field="ok")

        # The queryset includes `obj`.
        qs = CustomPrimaryKey.objects.filter(pk=obj.pk)

        FormSet = self._make_formset_cls(can_delete=True)

        data = {
            "form-TOTAL_FORMS": "1",
            "form-INITIAL_FORMS": "1",
            "form-MAX_NUM_FORMS": "0",
            "form-0-my_pk": obj.pk,
            "form-0-some_field": obj.some_field,
            "form-0-DELETE": "on",
        }

        formset = FormSet(data, queryset=qs)
        self.assertTrue(formset.is_valid(), formset.errors)
        formset.save()

        still_exists = CustomPrimaryKey.objects.filter(pk=obj.pk).exists()
        assert not still_exists, (
            "Legitimate deletion inside the queryset should have removed the object."
        )
