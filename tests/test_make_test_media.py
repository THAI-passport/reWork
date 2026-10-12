import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
try:
    from PIL import Image
    import make_test_media
except ImportError:                                   # Pillow is optional for reWork itself
    Image = None


@unittest.skipIf(Image is None, "Pillow not installed")
class TestMedia(unittest.TestCase):
    def test_generates_expected_files(self):
        d = tempfile.mkdtemp()
        self.assertEqual(make_test_media.main(["--out", d, "--no-video"]), 0)
        self.assertEqual(sorted(os.listdir(d)), ["blue.png", "gradient_label.png", "noise.png", "party.gif", "photo.jpg", "red.png"])
        self.assertEqual(Image.open(os.path.join(d, "red.png")).getpixel((5, 5)), (255, 0, 0))
        self.assertEqual(Image.open(os.path.join(d, "party.gif")).n_frames, 20)

    def test_noise_is_deterministic(self):
        self.assertEqual(make_test_media.noise().tobytes(), make_test_media.noise().tobytes())


if __name__ == "__main__":
    unittest.main()
