import json

from django.contrib.gis.db.models.fields import GeometryField
from django.core.exceptions import SuspiciousOperation
from django.test import SimpleTestCase


JSON_RASTER = json.dumps(
    {
        "driver": "MEM",
        "width": 2,
        "height": 2,
        "srid": 4326,
        "bands": [{"data": [1, 2, 3, 4]}],
    }
)


class CVE202615307SpatialLookupTest(SimpleTestCase):
    """
    CVE-2026-15307: spatial lookups must reject dict and non-geometry string
    inputs instead of forwarding them to GDALRaster (which can write files or
    issue network requests).

    On vulnerable code get_prep_value silently accepts these inputs and passes
    them to GDALRaster.__init__, so no exception is raised → AssertionError.
    On fixed code a SuspiciousOperation (or subclass) is raised → test passes.
    """

    def _field(self):
        # Unbound GeometryField – no database needed.
        f = GeometryField(srid=4326)
        f.set_attributes_from_name("geom")
        return f

    def test_dict_input_raises_suspicious_operation(self):
        """
        A dict that looks like a GDALRaster definition must be rejected by
        get_prep_value with SuspiciousOperation, not silently forwarded to
        GDALRaster (which would create/write a raster).
        """
        raster_dict = {
            "driver": "MEM",
            "width": 2,
            "height": 2,
            "srid": 4326,
            "bands": [{"data": [1, 2, 3, 4]}],
        }
        field = self._field()
        raised = False
        try:
            field.get_prep_value(raster_dict)
        except SuspiciousOperation:
            raised = True
        except Exception:
            # Any other exception (e.g. GDALException from actually opening a
            # raster on vulnerable code) means the dict reached GDALRaster –
            # that is the vulnerability.
            raised = False
        assert raised, (
            "VULNERABLE: get_prep_value accepted a dict without raising "
            "SuspiciousOperation (CVE-2026-15307). The dict was forwarded to "
            "GDALRaster, enabling server-side file writes."
        )

    def test_json_raster_string_raises_suspicious_operation(self):
        """
        A JSON string that encodes a raster dict must be rejected with
        SuspiciousOperation, not forwarded to GDALRaster.
        """
        field = self._field()
        raised = False
        try:
            field.get_prep_value(JSON_RASTER)
        except SuspiciousOperation:
            raised = True
        except Exception:
            raised = False
        assert raised, (
            "VULNERABLE: get_prep_value accepted a JSON raster string without "
            "raising SuspiciousOperation (CVE-2026-15307). The string was "
            "forwarded to GDALRaster, enabling server-side file writes."
        )

    def test_vsicurl_string_raises_suspicious_operation(self):
        """
        A /vsicurl/ path must be rejected with SuspiciousOperation, not
        forwarded to GDALRaster (which would issue a network request).
        """
        field = self._field()
        raised = False
        try:
            field.get_prep_value("/vsicurl/http://attacker.example.com/evil.tif")
        except SuspiciousOperation:
            raised = True
        except Exception:
            raised = False
        assert raised, (
            "VULNERABLE: get_prep_value accepted a /vsicurl/ string without "
            "raising SuspiciousOperation (CVE-2026-15307). The string was "
            "forwarded to GDALRaster, enabling SSRF."
        )

    def test_vsis3_string_raises_suspicious_operation(self):
        """
        A /vsis3/ path must be rejected with SuspiciousOperation, not
        forwarded to GDALRaster (which would issue a network/S3 request).
        """
        field = self._field()
        raised = False
        try:
            field.get_prep_value("/vsis3/my-bucket/evil.tif")
        except SuspiciousOperation:
            raised = True
        except Exception:
            raised = False
        assert raised, (
            "VULNERABLE: get_prep_value accepted a /vsis3/ string without "
            "raising SuspiciousOperation (CVE-2026-15307). The string was "
            "forwarded to GDALRaster, enabling SSRF."
        )
