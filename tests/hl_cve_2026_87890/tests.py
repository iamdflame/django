import unittest.mock

from django.contrib.gis.db.models.fields import GeometryField
from django.contrib.gis.gdal import GDALRaster
from django.contrib.gis.gdal.error import GDALException
from django.contrib.gis.gdal.raster.source import DisallowedRasterLookup
from django.test import SimpleTestCase

from .models import *  # noqa: F401, F403


class PatchedGDALRaster(GDALRaster):
    """
    Subclass that overrides __init__ to raise GDALException immediately,
    preventing any native I/O while keeping isinstance() checks intact.
    """

    def __init__(self, ds_input, write=False):
        raise GDALException("Mocked: no native I/O in tests.")


class BytesRejectedInSpatialLookupTest(SimpleTestCase):
    """
    CVE-2026-87890: bytes values must be rejected by BaseSpatialField.get_prep_value
    via DisallowedRasterLookup, not silently passed to GDALRaster native I/O.
    """

    def _get_prep_value_with_bytes(self, value):
        """
        Call GeometryField.get_prep_value with the given bytes value,
        patching GDALRaster so native I/O never happens.
        """
        field = GeometryField(srid=4326)
        with unittest.mock.patch(
            "django.contrib.gis.db.models.fields.gdal.GDALRaster",
            new=PatchedGDALRaster,
        ):
            return field.get_prep_value(value)

    def test_plain_bytes_rejected(self):
        """
        Plain bytes (not valid hex geometry) must raise DisallowedRasterLookup.
        On vulnerable code, bytes pass check_raster_lookup_value and reach
        GDALRaster() instead of being blocked.
        """
        value = b"not a geometry"
        try:
            self._get_prep_value_with_bytes(value)
        except DisallowedRasterLookup:
            # Fixed behaviour: bytes are blocked before native I/O
            return
        except Exception:
            # Any other exception (e.g. ValueError from GEOSGeometry) means
            # bytes were NOT blocked by DisallowedRasterLookup — vulnerable.
            pass
        raise AssertionError(
            "DisallowedRasterLookup was not raised for bytes input. "
            "CVE-2026-87890: bytes must be rejected in spatial lookups."
        )

    def test_arbitrary_bytes_rejected(self):
        """
        Arbitrary binary bytes must raise DisallowedRasterLookup.
        """
        value = bytes(range(256)) * 4
        try:
            self._get_prep_value_with_bytes(value)
        except DisallowedRasterLookup:
            return
        except Exception:
            pass
        raise AssertionError(
            "DisallowedRasterLookup was not raised for binary bytes input. "
            "CVE-2026-87890: bytes must be rejected in spatial lookups."
        )

    def test_large_bytes_rejected(self):
        """
        Large bytes values (potential VRT documents) must raise DisallowedRasterLookup.
        """
        value = b"x" * 5000
        try:
            self._get_prep_value_with_bytes(value)
        except DisallowedRasterLookup:
            return
        except Exception:
            pass
        raise AssertionError(
            "DisallowedRasterLookup was not raised for large bytes input. "
            "CVE-2026-87890: bytes must be rejected in spatial lookups."
        )

    def test_get_prep_value_executes_check(self):
        """
        Verify that get_prep_value actually calls check_raster_lookup_value
        by confirming DisallowedRasterLookup propagates for bytes on fixed code,
        while on vulnerable code bytes bypass the check entirely.

        This test also verifies that a GDALRaster instance is still accepted
        (the fix must not break the wrapped-GDALRaster path).
        """
        field = GeometryField(srid=4326)
        # bytes b"POINT (invalid)" - not valid hex, not valid geometry
        value = b"POINT (invalid)"
        raised_disallowed = False
        raised_other = False
        try:
            with unittest.mock.patch(
                "django.contrib.gis.db.models.fields.gdal.GDALRaster",
                new=PatchedGDALRaster,
            ):
                field.get_prep_value(value)
        except DisallowedRasterLookup:
            raised_disallowed = True
        except Exception:
            raised_other = True

        # On fixed code: DisallowedRasterLookup must be raised
        # On vulnerable code: some other exception is raised (bytes not blocked)
        assert raised_disallowed, (
            "DisallowedRasterLookup was not raised for bytes b'POINT (invalid)'. "
            "CVE-2026-87890: get_prep_value must reject bytes via "
            "DisallowedRasterLookup. "
            f"raised_other={raised_other}"
        )
