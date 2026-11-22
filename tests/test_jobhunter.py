import unittest

from cybersecurity_job_hunter import location_allowed, normalize_salary


class LocationEligibilityTests(unittest.TestCase):
    def test_each_requested_city_is_allowed(self):
        for city in ("Hyderabad", "Gurugram", "Gurgaon", "Delhi", "New Delhi", "Noida"):
            with self.subTest(city=city):
                self.assertTrue(location_allowed(city + ", India"))

    def test_multi_location_with_one_requested_city_is_allowed(self):
        self.assertTrue(location_allowed("Hyderabad / Bengaluru / Noida, India"))

    def test_pan_india_location_is_allowed(self):
        self.assertTrue(location_allowed("Pan-India"))

    def test_all_india_in_description_is_allowed(self):
        self.assertTrue(location_allowed("India", "This position is open across India"))

    def test_generic_india_alone_is_not_allowed(self):
        self.assertFalse(location_allowed("India"))

    def test_remote_india_is_allowed(self):
        self.assertTrue(location_allowed("Remote India"))

    def test_remote_restricted_to_bengaluru_is_not_allowed(self):
        self.assertFalse(location_allowed("Remote (Bengaluru)"))

    def test_zero_salary_is_not_disclosed(self):
        self.assertEqual(normalize_salary("0"), "Not disclosed")


if __name__ == "__main__":
    unittest.main()
