import sys
from django.test import SimpleTestCase
from django.contrib.gis.gdal import GDALRaster


class GDALRasterVSIBufferTest(SimpleTestCase):
    """
    Regression test for CVE-2026-53877: Heap buffer over-read in GDALRaster.vsi_buffer
    
    When GDALRaster is instantiated with bytes, the vsi_buffer property should
    return a buffer with length equal to len(input_bytes), not sys.getsizeof(input_bytes).
    """

    def test_vsi_buffer_length_matches_input(self):
        """
        Test that vsi_buffer length equals the input bytes length.
        
        On vulnerable code (Django 4.2), sys.getsizeof(bytes_obj) is used,
        which includes Python object overhead (~49 bytes on most platforms),
        causing the buffer to be over-read.
        
        On fixed code (Django 5.2+), len(bytes_obj) is used, so the lengths match.
        """
        # Create a small test raster in GeoTIFF format (minimal valid raster)
        # This is a 1x1 pixel, 1-band GeoTIFF file (minimal valid file)
        test_raster_bytes = (
            b'II*\x00\x08\x00\x00\x00'  # TIFF header (little-endian)
            b'\x0e\x00'  # 14 IFD entries
            b'\xfe\x00\x04\x00\x01\x00\x00\x00\x00\x00\x00\x00'  # NewSubfileType
            b'\x00\x01\x03\x00\x01\x00\x00\x00\x01\x00\x00\x00'  # ImageWidth = 1
            b'\x01\x01\x03\x00\x01\x00\x00\x00\x01\x00\x00\x00'  # ImageLength = 1
            b'\x02\x01\x03\x00\x01\x00\x00\x00\x08\x00\x00\x00'  # BitsPerSample = 8
            b'\x03\x01\x03\x00\x01\x00\x00\x00\x01\x00\x00\x00'  # Compression = 1 (none)
            b'\x06\x01\x03\x00\x01\x00\x00\x00\x01\x00\x00\x00'  # PhotometricInterpretation
            b'\x11\x01\x04\x00\x01\x00\x00\x00\x08\x00\x00\x00'  # StripOffsets
            b'\x15\x01\x03\x00\x01\x00\x00\x00\x01\x00\x00\x00'  # SamplesPerPixel = 1
            b'\x16\x01\x03\x00\x01\x00\x00\x00\x01\x00\x00\x00'  # RowsPerStrip = 1
            b'\x17\x01\x04\x00\x01\x00\x00\x00\x01\x00\x00\x00'  # StripByteCounts = 1
            b'\x1a\x01\x05\x00\x01\x00\x00\x00\x9a\x00\x00\x00'  # XResolution
            b'\x1b\x01\x05\x00\x01\x00\x00\x00\xa2\x00\x00\x00'  # YResolution
            b'\x1c\x01\x03\x00\x01\x00\x00\x00\x02\x00\x00\x00'  # ResolutionUnit
            b'\x00\x00\x00\x00'  # Next IFD offset (0 = none)
            b'\x00'  # Pixel data (1 byte)
            b'\x48\x00\x01\x00\x48\x00\x01\x00'  # XResolution value
            b'\x48\x00\x01\x00\x48\x00\x01\x00'  # YResolution value
        )
        
        # Instantiate GDALRaster with bytes
        raster = GDALRaster(test_raster_bytes)
        
        # Get the vsi_buffer
        vsi_buffer = raster.vsi_buffer
        
        # The critical assertion: vsi_buffer length must equal input bytes length
        # On vulnerable code, len(vsi_buffer) > len(test_raster_bytes) due to
        # sys.getsizeof() including Python object overhead
        self.assertIsNotNone(vsi_buffer, "vsi_buffer should not be None for VSI-based raster")
        self.assertEqual(
            len(vsi_buffer),
            len(test_raster_bytes),
            f"vsi_buffer length {len(vsi_buffer)} should equal input bytes length {len(test_raster_bytes)}. "
            f"Difference of {len(vsi_buffer) - len(test_raster_bytes)} bytes indicates over-read."
        )
